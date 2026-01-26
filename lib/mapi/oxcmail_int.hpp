#pragma once
#include <cstdint>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

struct MIME;
struct attachment_content;
struct message_content;

enum class oxcmail_type {
	normal, xsigned, encrypted, dsn, mdn, calendar, tnef,
};

namespace oxcmail {

using namemap = std::unordered_map<int, PROPERTY_NAME>;

/**
 * @noattach: a set of MIME parts that were chosen for the body,
 *            or which are considered discarded alternatives
 */
struct MIME_ENUM_PARAM {
	MIME_ENUM_PARAM(namemap &r) : phash(r) {}
	NOMOVE(MIME_ENUM_PARAM);

	bool b_result = false;
	int attach_id = 0;
	const char *charset = nullptr;
	GET_PROPIDS get_propids{};
	EXT_BUFFER_ALLOC alloc{};
	message_content *pmsg = nullptr;
	namemap phash;
	uint16_t last_propid = 0;
	uint64_t nttime_stamp = 0;
	const MIME *pplain = nullptr, *penriched = nullptr;
	const MIME *pcalendar = nullptr, *preport = nullptr;
	std::vector<const MIME *> htmls, hjoin;
	std::unordered_map<const MIME *, std::string> new_ctids;
};

/**
 * @b_inline:     Indicator for producing a multipart/related later on
 * @b_attachment: Indicator for producing a multipart/mixed later on
 * @pattachments: Buffer for holding ad-hoc generated attachments (that are not
 *                (backed by an actual MAPI attachment; mostly used for an RTF body)
 * @pplain:       Pointer to the plaintext body (if any) of the
 *                struct message_content that is to be exported
 * @phtml:        Pointer to the HTML body (if any)
 * @rtf:          Uncompressed RTF markup.
 * @rtf_bin:      RTF markup's container for other APIs.
 *
 * mime_skeleton will hold a bunch of pointers to a struct message_content.
 * You are responsible for lifetime management.
 */
struct mime_skeleton {
	mime_skeleton() = default;
	~mime_skeleton() { clear(); }
	NOMOVE(mime_skeleton);
	void clear();

	enum oxcmail_type mail_type{};
	enum oxcmail_body body_type{};
	BOOL b_inline = false, b_attachment = false;
	std::string rtf;
	BINARY rtf_bin{};
	const char *pplain = nullptr;
	const BINARY *phtml = nullptr;
	const char *charset = nullptr, *pmessage_class = nullptr;
	attachment_list *pattachments = nullptr;
};
using MIME_SKELETON = mime_skeleton;

static constexpr unsigned int MAXIMUM_SEARCHING_DEPTH = 10;

extern void select_parts(const MIME *, MIME_ENUM_PARAM &, unsigned int level);
extern ec_error_t bodyset_html(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_plain(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_enriched(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_multi(MIME_ENUM_PARAM &, TPROPVAL_ARRAY &);
extern bool attachment_is_inline(const attachment_content &);
extern bool parse_keywords(const char *cset, const char *fieldvalue, gromox::propid_t, TPROPVAL_ARRAY &);
extern bool parse_response_suppress(const char *raw, TPROPVAL_ARRAY &);

}

extern bool oxcmail_get_content_param(const MIME *, const char *tag, std::string &);
extern bool oxcmail_export_attachment(const attachment_content &, const char *log_id, bool b_inline, const oxcmail::mime_skeleton &, EXT_BUFFER_ALLOC, GET_PROPIDS, GET_PROPNAME, MIME *);
extern bool oxcmail_export(const message_content &, const char *log_id, bool b_tnef, enum oxcmail_body, MAIL *, EXT_BUFFER_ALLOC, GET_PROPIDS, GET_PROPNAME);

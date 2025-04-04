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
struct message_content;

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
	const char *charset = nullptr, *str_zone = nullptr;
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

static constexpr unsigned int MAXIMUM_SEARCHING_DEPTH = 10;

extern void select_parts(const MIME *, MIME_ENUM_PARAM &, unsigned int level);
extern ec_error_t bodyset_html(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_plain(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_enriched(TPROPVAL_ARRAY &, std::string &&, const char *);
extern ec_error_t bodyset_multi(MIME_ENUM_PARAM &, TPROPVAL_ARRAY &, const char *);

}

extern bool oxcmail_get_content_param(const MIME *, const char *tag, std::string &);

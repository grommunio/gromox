#pragma once
#include <memory>
#include <string>
#include <vector>
#include <vmime/generationContext.hpp>
#include <vmime/message.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/usercvt.hpp>

enum {
	VCARD_MAX_BUFFER_LEN = 1048576U,
};

struct ical;
struct message_content;
using MESSAGE_CONTENT = message_content;
struct vcard;

namespace gromox {

struct GX_EXPORT addr_tags {
	uint32_t pr_name, pr_addrtype, pr_emaddr, pr_smtpaddr, pr_entryid;
};

extern GX_EXPORT vmime::generationContext vmail_default_genctx();
extern GX_EXPORT std::string vmail_to_string(const vmime::message &);
extern GX_EXPORT bool vmail_to_mail(const vmime::message &, MAIL &);

extern GX_EXPORT unsigned int g_oxvcard_pedantic;

}

enum class oxcmail_body {
	plain_only = 1,
	html_only = 2,
	plain_and_html = 3,
};

struct GX_EXPORT oxcmail_converter {
	void use_format_override(const message_content &);
	bool mapi_to_inet(const message_content &, MAIL &);
	std::unique_ptr<message_content, gromox::mc_delete> inet_to_mapi(const MAIL &);

	const char *log_id = "";
	EXT_BUFFER_ALLOC alloc = nullptr;
	GET_PROPIDS get_propids = nullptr;
	GET_PROPNAME get_propname = nullptr;
	oxcmail_body body_type = oxcmail_body::plain_and_html;
	bool add_rcvd_timestamp = false;
};

struct GX_EXPORT oxcical_converter {
	ec_error_t ical_to_mapi_multi(const ical &, std::vector<std::unique_ptr<message_content, gromox::mc_delete>> &);
	std::unique_ptr<message_content, gromox::mc_delete> ical_to_mapi_single(const ical &);
	bool mapi_to_ical(const message_content &, ical &);

	const char *log_id = "", *org_name = "";
	EXT_BUFFER_ALLOC alloc = nullptr;
	GET_PROPIDS get_propids = nullptr;
	USERNAME_TO_ENTRYID username_to_entryid = nullptr;
	gromox::cvt_id2user id2user = nullptr;
};

struct GX_EXPORT oxvcard_converter {
	std::unique_ptr<message_content, gromox::mc_delete> vcard_to_mapi(const vcard &);
	bool mapi_to_vcard(const message_content &, vcard &out);

	const char *log_id = "";
	GET_PROPIDS get_propids = nullptr;
};

extern GX_EXPORT BOOL oxcmail_init_library(const char *org_name, GET_USER_IDS, GET_DOMAIN_IDS, GET_USERNAME);
extern GX_EXPORT bool oxcical_export_freebusy(const char *, const char *, time_t, time_t, const std::vector<freebusy_event> &, ical &);
extern GX_EXPORT BOOL oxcmail_username_to_entryid(const char *user, const char *disp, BINARY *, enum display_type *);
extern GX_EXPORT BOOL oxcmail_get_smtp_address(const TPROPVAL_ARRAY &, const gromox::addr_tags *, const char *org, gromox::cvt_id2user, std::string &out);

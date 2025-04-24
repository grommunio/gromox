#pragma once
#include <memory>
#include <vector>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#include <gromox/usercvt.hpp>

enum {
	VCARD_MAX_BUFFER_LEN = 1048576U,
};

enum class oxcmail_body {
	plain_only = 1,
	html_only = 2,
	plain_and_html = 3,
};

struct ical;
struct message_content;
using MESSAGE_CONTENT = message_content;
struct vcard;

namespace gromox {

struct GX_EXPORT addr_tags {
	uint32_t pr_name, pr_addrtype, pr_emaddr, pr_smtpaddr, pr_entryid;
};

extern GX_EXPORT bool g_oxcical_allday_ymd, oxcical_exchsched_compat;
extern GX_EXPORT unsigned int g_oxvcard_pedantic;

}

extern GX_EXPORT BOOL oxcmail_init_library(const char *org_name, GET_USER_IDS, GET_DOMAIN_IDS, GET_USERNAME);
extern GX_EXPORT ec_error_t oxcical_import_multi(const char *zone, const ical &, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID, std::vector<std::unique_ptr<MESSAGE_CONTENT, gromox::mc_delete>> &);
extern GX_EXPORT std::unique_ptr<MESSAGE_CONTENT, gromox::mc_delete> oxcical_import_single(const char *zone, const ical &, EXT_BUFFER_ALLOC, GET_PROPIDS, USERNAME_TO_ENTRYID);
extern GX_EXPORT bool oxcical_export(const MESSAGE_CONTENT *, const char *log_id, ical &, const char *org, EXT_BUFFER_ALLOC, GET_PROPIDS, gromox::cvt_id2user) __attribute__((nonnull(2)));
extern GX_EXPORT bool oxcical_export_freebusy(const char *, const char *, time_t, time_t, const std::vector<freebusy_event> &, ical &);
extern GX_EXPORT message_content *oxcmail_import(const char *charset, const char *timezone, const MAIL *, EXT_BUFFER_ALLOC, GET_PROPIDS);
extern GX_EXPORT BOOL oxcmail_export(const MESSAGE_CONTENT *, const char *log_id, BOOL tnef, enum oxcmail_body, MAIL *, EXT_BUFFER_ALLOC, GET_PROPIDS, GET_PROPNAME) __attribute__((nonnull(2)));
extern GX_EXPORT BOOL oxcmail_username_to_entryid(const char *user, const char *disp, BINARY *, enum display_type *);
extern GX_EXPORT enum oxcmail_body get_override_format(const MESSAGE_CONTENT &);
extern GX_EXPORT BOOL oxcmail_get_smtp_address(const TPROPVAL_ARRAY &, const gromox::addr_tags *, const char *org, gromox::cvt_id2user, std::string &out);

extern GX_EXPORT MESSAGE_CONTENT *oxvcard_import(const vcard *, GET_PROPIDS);
extern GX_EXPORT BOOL oxvcard_export(const MESSAGE_CONTENT *, const char *log_id, vcard &, GET_PROPIDS) __attribute__((nonnull(2)));

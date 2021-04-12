#pragma once
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>
#define OXCMAIL_BODY_PLAIN_ONLY				1
#define OXCMAIL_BODY_HTML_ONLY				2
#define OXCMAIL_BODY_PLAIN_AND_HTML			3

BOOL oxcmail_init_library(const char *org_name,
	GET_USER_IDS get_user_ids, GET_USERNAME get_username,
	LTAG_TO_LCID ltag_to_lcid, LCID_TO_LTAG lcid_to_ltag,
	CHARSET_TO_CPID charset_to_cpid, CPID_TO_CHARSET
	cpid_to_charset, MIME_TO_EXTENSION mime_to_extension,
	EXTENSION_TO_MIME extension_to_mime);
MESSAGE_CONTENT* oxcmail_import(const char *charset,
	const char *str_zone, MAIL *pmail,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids);
BOOL oxcmail_export(const MESSAGE_CONTENT *pmsg,
	BOOL b_tnef, int body_type, MIME_POOL *ppool,
	MAIL *pmail, EXT_BUFFER_ALLOC alloc,
	GET_PROPIDS get_propids, GET_PROPNAME get_propname);

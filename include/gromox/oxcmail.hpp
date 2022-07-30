#pragma once
#include <memory>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail.hpp>

enum class oxcmail_body {
	plain_only = 1,
	html_only = 2,
	plain_and_html = 3,
};

struct MESSAGE_CONTENT;
struct MIME_POOL;

extern BOOL oxcmail_init_library(const char *org_name, GET_USER_IDS, GET_USERNAME, LTAG_TO_LCID, MIME_TO_EXTENSION, EXTENSION_TO_MIME);
MESSAGE_CONTENT* oxcmail_import(const char *charset,
	const char *str_zone, MAIL *pmail,
	EXT_BUFFER_ALLOC alloc, GET_PROPIDS get_propids);
extern GX_EXPORT BOOL oxcmail_export(const MESSAGE_CONTENT *, BOOL tnef, enum oxcmail_body, std::shared_ptr<MIME_POOL>, MAIL *, EXT_BUFFER_ALLOC, GET_PROPIDS, GET_PROPNAME);
extern GX_EXPORT BOOL oxcmail_username_to_entryid(const char *user, const char *disp, BINARY *, enum display_type *);
extern GX_EXPORT enum oxcmail_body get_override_format(const MESSAGE_CONTENT &);

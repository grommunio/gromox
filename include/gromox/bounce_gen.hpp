#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>

struct ATTACHMENT_LIST;
struct MAIL;
struct tarray_set;

namespace gromox {

struct bounce_template {
	std::string content_type, from, subject;
	std::unique_ptr<char[], stdlib_delete> content;
	size_t ctlen = 0, body_start = 0;
};

extern GX_EXPORT gromox::errno_t bounce_gen_init(const char *sep, const char *cfgdir, const char *datadir, const char *bounce_class);
extern GX_EXPORT const bounce_template *bounce_gen_lookup(const char *cset, const char *tname);
extern GX_EXPORT const std::string &bounce_gen_sep();
extern GX_EXPORT const char *bounce_gen_postmaster();

extern GX_EXPORT std::string bounce_gen_rcpts(const tarray_set &);
extern GX_EXPORT std::string bounce_gen_attachs(const ATTACHMENT_LIST &);
extern GX_EXPORT std::string bounce_gen_attachs(const MAIL &, const char *cset);
extern GX_EXPORT std::string bounce_gen_thrindex(const MAIL &);
extern GX_EXPORT std::string bounce_gen_charset(const MAIL &);
extern GX_EXPORT std::string bounce_gen_subject(const MAIL &, const char *cset);

}

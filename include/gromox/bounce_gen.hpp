#pragma once
#include <memory>
#include <string>
#include <gromox/defs.h>

struct attachment_list;
struct MAIL;
struct tarray_set;

namespace gromox {

struct GX_EXPORT bounce_template {
	std::string from, subject;
	std::unique_ptr<char[], stdlib_delete> content;
	size_t ctlen = 0, body_start = 0;
};

extern GX_EXPORT gromox::errno_t bounce_gen_init(const char *cfgdir, const char *datadir, const char *bounce_class);
extern GX_EXPORT const bounce_template *bounce_gen_lookup(const char *cset, const char *tname);
extern GX_EXPORT const char *bounce_gen_postmaster();

extern GX_EXPORT std::string bounce_gen_rcpts(const tarray_set &);
extern GX_EXPORT std::string bounce_gen_thrindex(const MAIL &);
extern GX_EXPORT std::string bounce_gen_charset(const MAIL &);
extern GX_EXPORT std::string bounce_gen_subject(const MAIL &, const char *cset);

}

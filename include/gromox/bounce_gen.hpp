#pragma once
#include <string>
#include <gromox/defs.h>
struct ATTACHMENT_LIST;
struct MAIL;
struct tarray_set;
namespace gromox {
extern GX_EXPORT std::string bounce_gen_rcpts(const tarray_set &, const char *sep);
extern GX_EXPORT std::string bounce_gen_attachs(const ATTACHMENT_LIST &, const char *sep);
extern GX_EXPORT std::string bounce_gen_attachs(const MAIL &, const char *cset, const char *sep);
extern GX_EXPORT std::string bounce_gen_thrindex(const MAIL &);
extern GX_EXPORT std::string bounce_gen_charset(const MAIL &);
extern GX_EXPORT std::string bounce_gen_subject(const MAIL &, const char *cset);
}

#pragma once
#include <string>
#include <gromox/defs.h>
struct ATTACHMENT_LIST;
struct tarray_set;
namespace gromox {
extern GX_EXPORT std::string bounce_gen_rcpts(const tarray_set &, const char *sep);
extern GX_EXPORT std::string bounce_gen_attachs(const ATTACHMENT_LIST &, const char *sep);
}

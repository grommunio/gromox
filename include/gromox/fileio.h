#pragma once
#ifdef __cplusplus
#	include <string>
#endif
#include <gromox/defs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char **read_file_by_line(const char *file);

#ifdef __cplusplus
namespace gromox {

extern std::string iconvtext(const char *, size_t, const char *from, const char *to);

}

} /* extern "C" */
#endif

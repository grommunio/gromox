#pragma once
#include <cstdarg>
#include <cstddef>
#include <string>
#include <sys/types.h>
#include <gromox/defs.h>

#define gx_snprintf(buf, size, fmt, ...) gx_snprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
#define gx_vsnprintf(buf, size, fmt, ...) gx_vsnprintf1((buf), (size), __FILE__, __LINE__, (fmt), ## __VA_ARGS__)
extern GX_EXPORT int gx_snprintf1(char *, size_t, const char *, unsigned int, const char *, ...) __attribute__((format(printf, 5, 6)));
extern GX_EXPORT int gx_vsnprintf1(char *, size_t, const char *, unsigned int, const char *, va_list);
extern char **read_file_by_line(const char *file);

namespace gromox {

extern std::string iconvtext(const char *, size_t, const char *from, const char *to);
extern GX_EXPORT pid_t popenfd(const char *const *, int *, int *, int *, const char *const *);
extern GX_EXPORT ssize_t feed_w3m(const void *in, size_t insize, std::string &out);

}

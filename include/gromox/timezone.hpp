#pragma once
#include <ctime>
#include <memory>
#include <string>
#include <gromox/defs.h>

struct BINARY;
namespace tz {
struct state;
using timezone_t = state *;
extern GX_EXPORT timezone_t tzalloc(const char *);
extern GX_EXPORT void tzfree(timezone_t);
extern GX_EXPORT void tzset();
extern GX_EXPORT struct tm *localtime_rz(timezone_t, const time_t *, tm *);
extern GX_EXPORT time_t mktime_z(timezone_t, tm *);
}

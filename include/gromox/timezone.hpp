#pragma once
#include <ctime>

struct state;
extern const struct state *tz_alloc(const char *name);
void tz_free(const struct state* const sp);
struct tm* tz_localtime_r(const struct state* const sp,
	const time_t* const timep, struct tm* tmp);
time_t tz_mktime(const struct state* const sp, struct tm* const tmp);

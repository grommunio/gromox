#ifndef _H_TIMEZONE_
#define _H_TIMEZONE_

#ifdef __cplusplus
#	include <ctime>
#else
#	include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

const struct state* tz_alloc(register const char *name);
void tz_free(const struct state* const sp);

struct tm* tz_localtime(const struct state* const sp,
	const time_t* const timep);
struct tm* tz_localtime_r(const struct state* const sp,
	const time_t* const timep, struct tm* tmp);

time_t tz_mktime(const struct state* const sp, struct tm* const tmp);

#ifdef __cplusplus
}
#endif

#endif /* _H_TIMEZONE_ */

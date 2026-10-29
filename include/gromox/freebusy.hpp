#pragma once
#include <ctime>
#include <vector>
#include <gromox/defs.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

using namespace gromox;

extern GX_EXPORT unsigned int freebusy_perms(const char *actor, const char *target);
extern GX_EXPORT bool sees_private_items(const char *dir, const char *org, const char *actor);
extern GX_EXPORT bool delegate_eid_is(const BINARY &eid, const char *org, const char *actor);
extern GX_EXPORT ec_error_t get_freebusy(const char *, const char *, const char *org, time_t, time_t, std::vector<freebusy_event> &);

namespace gromox {

struct fb_instance {
	time_t start_time = 0, end_time = 0, orig_start = 0;
	const EXCEPTIONINFO *ei = nullptr;
	const EXTENDEDEXCEPTION *xe = nullptr;
};

extern GX_EXPORT bool fb_recur_times(const ical_component *tz, time_t start_whole, const APPOINTMENT_RECUR_PAT &, time_t start, time_t end, std::vector<fb_instance> &);

}

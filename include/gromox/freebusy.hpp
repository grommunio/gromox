#pragma once
#include <ctime>
#include <vector>
#include <gromox/defs.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

using namespace gromox;

extern GX_EXPORT unsigned int freebusy_perms(const char *actor, const char *target);
extern GX_EXPORT bool get_freebusy(const char *, const char *, time_t, time_t, std::vector<freebusy_event> &);

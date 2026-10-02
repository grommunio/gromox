#pragma once
#include <ctime>
#include <optional>
#include <vector>
#include <gromox/defs.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

using namespace gromox;

extern GX_EXPORT unsigned int freebusy_perms(const char *actor, const char *target);
/**
 * Build a VTIMEZONE component from a MAPI PidLidTimeZoneStruct blob, so that
 * local times stored in a recurrence blob can be resolved to UTC across
 * daylight-saving transitions (ical_itime_to_utc).
 */
extern GX_EXPORT std::optional<ical_component> tzstruct_to_vtimezone(int year, const char *tzid, const TZSTRUCT &);
extern GX_EXPORT ec_error_t get_freebusy(const char *, const char *, time_t, time_t, std::vector<freebusy_event> &);

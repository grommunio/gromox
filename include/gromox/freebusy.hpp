#pragma once
#include <ctime>
#include <vector>
#include <fmt/core.h>
#include <fmt/format.h>
#include <gromox/defs.h>
#include <gromox/ical.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>

using namespace gromox;

template<> struct fmt::formatter<ICAL_TIME>
{
	constexpr auto parse(format_parse_context &ctx) { return ctx.begin(); }
	format_context::iterator format(const ICAL_TIME &t, format_context &ctx) const
	{
		return t.type == ICT_FLOAT_DAY ?
		       fmt::format_to(ctx.out(), "{:04}{:02}{:02}",
		       t.year, t.month, t.day) :
		       fmt::format_to(ctx.out(), "{:04}{:02}{:02}T{:02}{:02}{:02}{}",
		       t.year, t.month, t.day, t.hour, t.minute, t.second,
		       t.type == ICT_UTC ? "Z" : "");
	}
};

struct event
{
	time_t start_time = 0, end_time = 0;
	EXCEPTIONINFO *ei = nullptr;
	EXTENDEDEXCEPTION *xe = nullptr;
};

struct freebusy_tags
{
	freebusy_tags(const char *);

	uint32_t apptstartwhole = 0, apptendwhole = 0, busystatus = 0, recurring = 0,
		apptrecur = 0, apptsubtype = 0, private_flag = 0, apptstateflags = 0,
		clipend = 0, location = 0, reminderset = 0, globalobjectid = 0,
		timezonestruct = 0;
};

extern GX_EXPORT bool get_freebusy(const char *, const char *, time_t, time_t, std::vector<freebusy_event> &);

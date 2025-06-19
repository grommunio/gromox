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

template<> struct fmt::formatter<ical_time> {
	constexpr auto parse(format_parse_context &ctx) { return ctx.begin(); }
	format_context::iterator format(const ical_time &t, format_context &ctx) const
	{
		return t.type == ICT_FLOAT_DAY ?
		       fmt::format_to(ctx.out(), "{:04}{:02}{:02}",
		       t.year, t.month, t.day) :
		       fmt::format_to(ctx.out(), "{:04}{:02}{:02}T{:02}{:02}{:02}{}",
		       t.year, t.month, t.day, t.hour, t.minute, t.second,
		       t.type == ICT_UTC ? "Z" : "");
	}
};

extern GX_EXPORT bool get_freebusy(const char *, const char *, time_t, time_t, std::vector<freebusy_event> &);

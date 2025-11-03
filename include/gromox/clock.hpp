#pragma once
#include <chrono>
#include <libHX/scope.hpp>
namespace gromox {
using time_point = std::chrono::steady_clock::time_point;
using time_duration = time_point::duration;
inline time_point tp_now() { return time_point::clock::now(); }
}
#define CLK_START(tmr) \
	auto CLK_ ## tmr = gromox::time_point::clock::now()
#define CLK_TICK(tmr, s) \
	fprintf(stderr, "%s %llu ns\n", (s), \
	static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>( \
	gromox::time_point::clock::now() - CLK_ ## tmr).count()))
#define CLK_DTOR(tmr, s) \
	auto CLK_ ## tmr ## _dtor = HX::make_scope_exit([&]() { CLK_TICK(tmr, (s)); })

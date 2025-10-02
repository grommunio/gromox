#pragma once
#include <chrono>
#include <libHX/scope.hpp>
namespace gromox {
using time_point = std::chrono::steady_clock::time_point;
using time_duration = time_point::duration;
inline time_point tp_now() { return time_point::clock::now(); }
}
#define CLK_DS(tmr) \
	auto CLK_ ## tmr = gromox::time_point::clock::now()
#define CLK_DT(tmr, s) \
	CLK_DT2(tmr, (s), __LINE__)
#define CLK_DT2(tmr, s, line) \
	CLK_DT3(tmr, (s), line)
#define CLK_DT3(tmr, s, line) \
	auto CLK_ ## line ## _dtor = HX::make_scope_exit([&]() { \
		fprintf(stderr, "%s %llu ns\n", (s), \
		static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>( \
		gromox::time_point::clock::now() - CLK_ ## tmr).count())); \
	});

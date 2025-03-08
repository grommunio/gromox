#pragma once
#include <chrono>
#include <libHX/scope.hpp>
namespace gromox {
using time_point = std::chrono::steady_clock::time_point;
using time_duration = time_point::duration;
inline time_point tp_now() { return time_point::clock::now(); }
}
#define CLK_D0 \
	auto D0 = gromox::time_point::clock::now()
#define CLK_DT(s) \
	auto D0_dtor = HX::make_scope_exit([&]() { \
		fprintf(stderr, "%s %llu ns\n", (s), \
		static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>( \
		gromox::time_point::clock::now() - D0).count())); \
	});

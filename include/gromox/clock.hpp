#pragma once
#include <chrono>
namespace gromox {
using time_duration = std::chrono::steady_clock::duration;
using time_point = std::chrono::time_point<std::chrono::system_clock>;
inline time_point tp_now() { return time_point::clock::now(); }
}

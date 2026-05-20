#pragma once
#include <atomic>
namespace gromox {
/*
 * riscv does not have subword atomic. GCC generates a lot of code for
 * atomic<bool>, so just use uint for our implementation of a boolean flag.
 */
#if !defined(__riscv)
using atomic_bool = std::atomic<bool>;
#else
using atomic_bool = std::atomic<unsigned int>;
#endif
}

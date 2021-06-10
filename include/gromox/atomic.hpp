#pragma once
#include <atomic>
namespace gromox {
#if !defined(__riscv) || defined(PROMISE_TO_LINK_LIBATOMIC)
using atomic_bool = std::atomic<bool>;
#else
using atomic_bool = std::atomic<unsigned int>;
#endif
}

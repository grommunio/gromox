#pragma once
#include <pthread.h>
#ifdef __OpenBSD__
#	include <pthread_np.h>
#endif
#include <string>
#include <gromox/defs.h>

#if defined(__OpenBSD__)
static inline int _pthread_setname_np(pthread_t thread, const char *name)
{
	pthread_set_name_np(thread, name);
	return 0;
}
#define pthread_setname_np _pthread_setname_np
#endif

namespace gromox {

#ifdef __OpenBSD__
static constexpr char RUNNING_IDENTITY[] = "_gromox";
#else
static constexpr char RUNNING_IDENTITY[] = "gromox";
#endif

extern GX_EXPORT errno_t filedes_limit_bump(size_t);
extern GX_EXPORT unsigned long gx_gettid();
extern GX_EXPORT void gx_reexec_record(int);
extern GX_EXPORT int pthread_create4(pthread_t *, std::nullptr_t, void *(*)(void *), void * = nullptr) noexcept;
extern GX_EXPORT int setup_sigalrm();
extern GX_EXPORT std::string simple_backtrace();
extern GX_EXPORT errno_t switch_user_exec(const char *user, char *const *argv);

}

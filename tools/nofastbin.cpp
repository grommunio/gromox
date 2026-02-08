#include <cstdio>
#ifdef __GLIBC__
#include <malloc.h>
#include <gromox/mapidefs.h>
extern void __attribute__((constructor)) nofastbin_init();
void nofastbin_init()
{
	size_t a = sizeof(size_t) == 8 ? 24 : 20;
	auto s = getenv("MALLOC_MXFAST");
	if (s != nullptr)
		a = strtoull(s, nullptr, 0);
	mallopt(M_MXFAST, a);
}
#endif

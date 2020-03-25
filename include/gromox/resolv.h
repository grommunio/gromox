#pragma once
#include <gromox/defs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int gx_getmxbyname(const char *domain, char ***mxout);

#ifdef __cplusplus
}
#endif

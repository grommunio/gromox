#pragma once
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int guid_compare(const GUID *u1, const GUID *u2);

void guid_to_string(const GUID *guid, char *buff, int buflen);

BOOL guid_from_string(GUID *guid, const char *guid_string);

GUID guid_random_new(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

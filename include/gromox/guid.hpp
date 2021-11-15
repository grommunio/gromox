#pragma once
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>

int guid_compare(const GUID *u1, const GUID *u2);
extern GX_EXPORT void guid_to_string(const GUID *guid, char *buff, size_t buflen);
BOOL guid_from_string(GUID *guid, const char *guid_string);
extern GUID guid_random_new();
static inline bool operator==(const GUID &a, const GUID &b)
{
	return guid_compare(&a, &b) == 0;
}

#ifndef _H_GUID_
#define _H_GUID_
#include "common_types.h"

int guid_compare(const GUID *u1, const GUID *u2);

void guid_to_string(const GUID *guid, char *buff, int buflen);

BOOL guid_from_string(GUID *guid, const char *guid_string);

GUID guid_random_new(void);

#endif /* _H_GUID_ */

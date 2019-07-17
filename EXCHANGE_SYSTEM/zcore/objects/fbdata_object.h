#ifndef _H_FBDATA_OBJECT
#include "common_util.h"

typedef struct _FBDATA_OBJECT {
	char *username;
	char *maildir;
} FBDATA_OBJECT;

FBDATA_OBJECT* fbdata_object_create(const char *username);

void fbdata_object_free(FBDATA_OBJECT *pfbdata);

void fbdata_object_get_range(FBDATA_OBJECT *pfbdata,
	uint64_t *pnttime_start, uint64_t *pnttime_end);

FBBLOCK_ARRAY* fbdata_object_get_blocks(FBDATA_OBJECT *pfbdata,
	uint64_t nttime_start, uint64_t nttime_end);

#endif /* _H_FBDATA_OBJECT */

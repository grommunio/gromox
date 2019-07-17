#include "fbdata_object.h"
#include <string.h>

FBDATA_OBJECT* fbdata_object_create(const char *username)
{
	char maildir[256];
	FBDATA_OBJECT *pfbdata;
	
	if (FALSE == system_services_get_maildir(username, maildir)) {
		return NULL;
	}
	pfbdata = malloc(sizeof(FBDATA_OBJECT));
	if (NULL == pfbdata) {
		return NULL;
	}
	pfbdata->username = strdup(username);
	if (NULL == pfbdata->username) {
		free(pfbdata);
		return NULL;
	}
	pfbdata->maildir = strdup(maildir);
	if (NULL == pfbdata->maildir) {
		free(pfbdata->username);
		free(pfbdata);
		return NULL;
	}
	return pfbdata;
}

void fbdata_object_free(FBDATA_OBJECT *pfbdata)
{
	free(pfbdata->username);
	free(pfbdata->maildir);
	free(pfbdata);
}

void fbdata_object_get_range(FBDATA_OBJECT *pfbdata,
	uint64_t *pnttime_start, uint64_t *pnttime_end)
{
	
	
	
}

FBBLOCK_ARRAY* fbdata_object_get_blocks(FBDATA_OBJECT *pfbdata,
	uint64_t nttime_start, uint64_t nttime_end)
{
	
}
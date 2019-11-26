#ifndef _H_MSGCHG_GROUPING_
#define _H_MSGCHG_GROUPING_
#include "element_data.h"
#include "logon_object.h"
#include "mapi_types.h"
#include <stdint.h>

void msgchg_grouping_init(const char *path);

int msgchg_grouping_run();

uint32_t msgchg_grouping_get_last_group_id();

PROPERTY_GROUPINFO* msgchg_grouping_get_groupinfo(
	LOGON_OBJECT *plogon, uint32_t group_id);

int msgchg_grouping_stop();

void msgchg_grouping_free();

#endif /* _H_MSGCHG_GROUPING_ */

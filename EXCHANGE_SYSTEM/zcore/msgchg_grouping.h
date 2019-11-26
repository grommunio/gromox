#ifndef _H_MSGCHG_GROUPING_
#define _H_MSGCHG_GROUPING_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "element_data.h"
#include "store_object.h"
#include "mapi_types.h"

void msgchg_grouping_init(const char *path);
extern int msgchg_grouping_run(void);
extern uint32_t msgchg_grouping_get_last_group_id(void);
PROPERTY_GROUPINFO* msgchg_grouping_get_groupinfo(
	STORE_OBJECT *pstore, uint32_t group_id);
extern int msgchg_grouping_stop(void);
extern void msgchg_grouping_free(void);

#endif /* _H_MSGCHG_GROUPING_ */

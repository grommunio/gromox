#ifndef _H_ITEM_SORTER_
#define _H_ITEM_SORTER_
#include "common_types.h"
#include <time.h>

void item_sorter_init(time_t now_time, const char *data_path,
	const char *url_link, const char *resource_path);
extern int item_sorter_run(void);
extern int item_sorter_stop(void);
extern void item_sorter_free(void);

#endif


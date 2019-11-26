#ifndef _H_ITEM_SORTER_
#define _H_ITEM_SORTER_
#include "common_types.h"
#include <time.h>

void item_sorter_init(time_t now_time, const char *data_path,
	const char *url_link, const char *resource_path);

int item_sorter_run();

int item_sorter_stop();

void item_sorter_free();


#endif


#ifndef _H_RETRYING_TABLE_
#define _H_RETRYING_TABLE_
#include "common_types.h"
#include "mem_file.h"

enum {
	RETRYING_TABLE_MIN_INTERVAL,
	RETRYING_TABLE_MAX_INTERVAL,
	RETRYING_TABLE_TABLE_SIZE
};

void retrying_table_init(int size, int min_intvl, int valid_intvl);

int retrying_table_run();

BOOL retrying_table_check(char *temp_string);

int retrying_table_stop();

void retrying_table_free();

int retrying_table_get_valid();

void retrying_table_set_param(int param, int value);

int retrying_table_get_param(int param);


#endif /* end of _H_RETRYING_TABLE_ */

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
extern int retrying_table_run(void);
BOOL retrying_table_check(char *temp_string);
extern int retrying_table_stop(void);
extern void retrying_table_free(void);
extern int retrying_table_get_valid(void);
void retrying_table_set_param(int param, int value);

int retrying_table_get_param(int param);


#endif /* end of _H_RETRYING_TABLE_ */

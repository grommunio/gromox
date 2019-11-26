#ifndef _H_RETRYING_TABLE_
#define _H_RETRYING_TABLE_
#include "common_types.h"
#include "mem_file.h"


void retrying_table_init(const char *config_path, int size, int min_intvl,
	int valid_intvl);
extern int retrying_table_run(void);
BOOL retrying_table_check(const char *ip, const char *from, MEM_FILE *pfile);
extern int retrying_table_stop(void);
extern void retrying_table_free(void);
void retrying_table_console_talk(int argc, char **argv,
	char *result, int length);

#endif /* end of _H_RETRYING_TABLE_ */

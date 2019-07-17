#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);

int data_source_run();

int data_source_stop();

void data_source_free();

BOOL data_source_get_datadir(char *path_buff);

void* data_source_lock_flush();

void data_source_unlock(void *pmysql);


#endif

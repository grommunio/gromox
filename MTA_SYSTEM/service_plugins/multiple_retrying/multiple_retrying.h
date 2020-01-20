#pragma once
#include "common_types.h"

void multiple_retrying_init(const char *config_path, const char *list_path,
	int table_size, int min_interval, int valid_interval, int port,
	int time_out, int ping_interval, int channel_num);
extern int multiple_retrying_run(void);
extern int multiple_retrying_stop(void);
extern void multiple_retrying_free(void);
BOOL multiple_retrying_readline_timeout(int sockd, char *buff, int length,
	int time_out);

BOOL multiple_retrying_writeline_timeout(int sockd, const char *buff,
	int time_out);

void multiple_retrying_console_talk(int argc, char **argv,
	char *result, int length);

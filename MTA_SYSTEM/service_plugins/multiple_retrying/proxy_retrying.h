#ifndef _H_PROXY_RETRYING_
#define _H_PROXY_RETRYING_
#include "common_types.h"
#include "mem_file.h"

enum {
	PROXY_RETRYING_PING_INTERVAL,
	PROXY_RETRYING_TIME_OUT,
	PROXY_RETRYING_UNIT_NUM,
	PROXY_RETRYING_CHANNEL_NUM
};

void proxy_retrying_init(const char *list_path, int port, int time_out,
	int ping_interval, int channel_num);
int proxy_retrying_run();
BOOL proxy_retrying_check(const char *ip, const char *from, MEM_FILE *pfile);
int proxy_retrying_stop();
void proxy_retrying_free();
int proxy_retrying_get_param(int param);

void proxy_retrying_set_param(int param, int value);

#endif

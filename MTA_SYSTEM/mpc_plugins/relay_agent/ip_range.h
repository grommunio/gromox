#ifndef _H_IP_RANGE_
#define _H_IP_RANGE_
#include "common_types.h"

enum {
	DOWNLOAD_INTERVAL,
	SITE_TYPE
};

void ip_range_init(const char *list_path, const char *url_path, int interval, 
	const char *country, BOOL b_main);

int ip_range_run();

BOOL ip_range_check(const char *ip);

int ip_range_stop();

void ip_range_free();

void ip_range_set_param(int param, int val);

int ip_range_get_param(int param);

const char *ip_range_country();

const char *ip_range_url();

#endif

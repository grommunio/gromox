#ifndef _H_IP_RANGE_
#define _H_IP_RANGE_
#include "common_types.h"

enum {
	DOWNLOAD_INTERVAL,
	SITE_TYPE
};

void ip_range_init(const char *list_path, const char *url_path, int interval, 
	const char *country, BOOL b_main);
extern int ip_range_run(void);
BOOL ip_range_check(const char *ip);
extern int ip_range_stop(void);
extern void ip_range_free(void);
void ip_range_set_param(int param, int val);

int ip_range_get_param(int param);
extern const char *ip_range_country(void);
extern const char *ip_range_url(void);

#endif

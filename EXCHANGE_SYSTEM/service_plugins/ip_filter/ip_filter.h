#ifndef _H_IP_FILTER
#define _H_IP_FILTER

#include "common_types.h"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define CALCULATE_INTERVAL(a, b) \
	(((a).tv_usec >= (b).tv_usec) ? ((a).tv_sec - (b).tv_sec) : \
	((a).tv_sec - (b).tv_sec - 1))

void ip_filter_init(const char *module_name, const char *config_path,
	int audit_num, int audit_interval, int audit_times, int temp_list_size,
	const char *list_path, int growing_num); 
extern void ip_filter_free(void);
extern int ip_filter_run(void);
extern int ip_filter_stop(void);
BOOL ip_filter_judge(char *ip);

BOOL ip_filter_query(char *ip);

BOOL ip_filter_add_ip_into_temp_list(char *ip, int interval);

void ip_filter_console_talk(int argc, char **argv, char *result, int length);

void ip_filter_echo(const char *format, ...);

#endif

#ifndef _H_STR_FILTER
#define _H_STR_FILTER

#include "common_types.h"

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define CALCULATE_INTERVAL(a, b) \
	(((a).tv_usec >= (b).tv_usec) ? ((a).tv_sec - (b).tv_sec) : \
	((a).tv_sec - (b).tv_sec - 1))

void str_filter_init(const char *module_name, const char *config_path,
	BOOL case_sensitive, int audit_num, int audit_interval, int audit_times,
	int temp_list_size, const char *list_path, int growing_num); 

void str_filter_free();

int str_filter_run();

int str_filter_stop();

BOOL str_filter_judge(char* str);

BOOL str_filter_query(char* str);

BOOL str_filter_add_string_into_temp_list(char* str, int interval);

void str_filter_console_talk(int argc, char **argv, char *result, int length);

void str_filter_echo(const char *format, ...);

#endif

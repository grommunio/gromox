#pragma once
#include <sys/stat.h>
#include <gromox/common_types.hpp>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

#define CALCULATE_INTERVAL(a, b) \
	(((a).tv_usec >= (b).tv_usec) ? ((a).tv_sec - (b).tv_sec) : \
	((a).tv_sec - (b).tv_sec - 1))

extern void str_filter_init(const char *module_name, BOOL case_sensitive, int audit_num, int audit_interval, int audit_times, int temp_list_size, const char *list_path, int growing_num);
extern void str_filter_free();
extern int str_filter_run();
extern void str_filter_stop();
extern BOOL str_filter_judge(const char *str);
extern BOOL str_filter_query(const char *str);
extern BOOL str_filter_add_string_into_temp_list(const char *str, int interval);
extern void str_filter_echo(const char *format, ...) __attribute__((format(printf, 1, 2)));

#pragma once
#include <ctime>
#include <sys/stat.h>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>

extern void audit_filter_init(BOOL case_sensitive, int audit_num, int audit_interval, int audit_times);
extern void audit_filter_stop();
extern BOOL audit_filter_query(const char *str);
extern BOOL audit_filter_judge(const char *str);

extern void str_filter_init(const char *module_name, BOOL case_sensitive, int audit_num, int audit_interval, int audit_times, int temp_list_size);
extern void str_filter_free();
extern int str_filter_run();
extern void str_filter_stop();
extern BOOL str_filter_judge(const char *str);
extern BOOL str_filter_query(const char *str);
extern BOOL str_filter_add_string_into_temp_list(const char *str, int interval);
extern void str_filter_echo(const char *format, ...) __attribute__((format(printf, 1, 2)));

extern void temp_list_init(BOOL case_sensitive, size_t max);
extern int temp_list_run();
extern void temp_list_free();
extern BOOL temp_list_add_string(const char *str, int interval);
extern BOOL temp_list_query(const char *str);

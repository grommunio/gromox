#pragma once
#include <ctime>
#include <gromox/common_types.hpp>

void audit_filter_init(BOOL case_sensitive, int audit_num, int audit_interval, 
    int audit_times);
extern void audit_filter_stop();
BOOL audit_filter_query(const char *str);
BOOL audit_filter_judge(const char *str);
BOOL audit_filter_echo(const char *str, time_t *pfirst_access,
	time_t *plast_access, int *ptimes);
BOOL audit_filter_dump(const char *path);
BOOL audit_filter_remove_string(const char *str);

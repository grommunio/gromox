#ifndef _H_AUDIT_FILTER_
#define _H_AUDIT_FILTER_

#include "common_types.h"
#include <time.h>

/* the index of audit param is from 0 to 99 */
enum {
    AUDIT_INTERVAL = 0,
    AUDIT_TIMES,
	AUDIT_CAPABILITY
};

void audit_filter_init(int audit_num, long audit_interval, int audit_times);

int audit_filter_run();

int audit_filter_stop();

int audit_filter_set_param(int tpye, int value);

int audit_filter_get_param(int type);

void audit_filter_free();

BOOL audit_filter_query(const char *ip);

BOOL audit_filer_judge(const char *ip);

BOOL audit_filter_echo(const char *ip, time_t *pfirst_access,
	time_t *plast_access, int *ptimes);

BOOL audit_filter_dump(const char *path);

BOOL audit_filter_remove_ip(const char *ip);

#endif /* _H_AUDIT_FILTER_ */

#pragma once
#include <ctime>
#include <gromox/common_types.hpp>
#include <gromox/hook_common.h>

enum {
	DELIVERY_NO_USER,
	DELIVERY_MAILBOX_FULL,
	DELIVERY_OPERATION_ERROR,
	DELIVERY_OPERATION_FAILURE,
	DELIVERY_OPERATION_OK,
	DELIVERY_OPERATION_DELIVERED
};

struct MAIL;
#define BOUND_NOTLOCAL					7

extern void auto_response_reply(const char *user_home, const char *from, const char *rcpt);

extern void bounce_audit_init(int audit_num, int audit_interval);
extern BOOL bounce_audit_check(const char *audit_string);

extern bool exml_bouncer_make(const char *from, const char *rcpt, MAIL *orig, time_t orig_time, const char *bounce_type, MAIL *cur);

extern int (*exmdb_local_check_domain)(const char *domainname);
extern bool (*exmdb_local_get_lang)(const char *username, char *lang, size_t);
extern bool (*exmdb_local_get_timezone)(const char *username, char *timezone, size_t);
extern BOOL (*exmdb_local_check_same_org2)(const char *domainname1, const char *domainname2);

extern void cache_queue_init(const char *path, int scan_interval, int retrying_times);
extern int cache_queue_run();
extern void cache_queue_stop();
extern void cache_queue_free();
extern int cache_queue_put(MESSAGE_CONTEXT *, const char *rcpt, time_t orig_time);

extern void exmdb_local_init(const char *org_name, const char *default_charset);
extern int exmdb_local_run();
extern gromox::hook_result exmdb_local_hook(MESSAGE_CONTEXT *);
int exmdb_local_deliverquota(MESSAGE_CONTEXT *pcontext, const char *address);
extern void exmdb_local_log_info(MESSAGE_CONTEXT *pcontext, const char *rcpt_to, int level, const char *format, ...);

extern void net_failure_init(int times, int interval, int alarm_interval);
extern int net_failure_run();
extern void net_failure_free();
extern void net_failure_statistic(int OK_num, int temp_fail, int permanent_fail, int nouser_num);

#pragma once
#include <ctime>
#include <gromox/common_types.hpp>
#include <gromox/hook_common.h>

enum class delivery_status {
	ok, no_user, mailbox_full, error, failure, bounce_sent,
};

struct MAIL;

extern void auto_response_reply(const char *user_home, const char *from, const char *rcpt);

extern void bounce_audit_init(int audit_num, int audit_interval);
extern BOOL bounce_audit_check(const char *audit_string);

extern bool exml_bouncer_make(const char *from, const char *rcpt, MAIL *orig, time_t orig_time, const char *bounce_type, MAIL *cur);

extern int (*exmdb_local_check_domain)(const char *domainname);
extern bool (*exmdb_local_get_lang)(const char *username, char *lang, size_t);
extern BOOL (*exmdb_local_check_same_org2)(const char *domainname1, const char *domainname2);

extern void cache_queue_init(const char *path, int scan_interval, int retrying_times);
extern int cache_queue_run();
extern void cache_queue_stop();
extern void cache_queue_free();
extern int cache_queue_put(MESSAGE_CONTEXT *, const char *rcpt, time_t orig_time);

extern void exmdb_local_init(const char *org_name, const char *default_charset);
extern int exmdb_local_run();
extern gromox::hook_result exmdb_local_hook(MESSAGE_CONTEXT *);
extern delivery_status exmdb_local_deliverquota(MESSAGE_CONTEXT *pcontext, const char *address);
extern void exmdb_local_log_info(const CONTROL_INFO &, const char *rcpt, int level, const char *format, ...);

extern unsigned int autoreply_silence_window;

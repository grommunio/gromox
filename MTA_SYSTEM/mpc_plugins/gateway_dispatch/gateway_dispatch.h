#ifndef _H_GATEWAY_DISPATCH_
#define _H_GATEWAY_DISPATCH_

#include "hook_common.h"

enum {
    BOUNCE_POLICY_NONE = 0,
	BOUNCE_POLICY_VERIFY,
	BOUNCE_POLICY_ALWAYS
};

enum {
	GATEWAY_DISPATCH_BOUNCE_POLICY
};

#define BOUND_NOTLOCAL					7

#define SPAM_STATISTIC_OK               0
#define SPAM_STATISTIC_NOUSER           2

typedef void (*SPAM_STATISTIC)(int);

extern SPAM_STATISTIC gateway_dispatch_spam_statistic;

void gateway_dispatch_init(const char *list_path, int backend_interval, 
	int files_num, int times, int interval, int alarm_interval,
	int bounce_policy, const char *mask_string, const char *resource_path,
	const char* separator, const char *cache_path, int cache_interval,
	int retrying_times, int block_interval, const char *config_path);
extern int gateway_dispatch_run(void);
extern int gateway_dispatch_stop(void);
extern void gateway_dispatch_free(void);
BOOL gateway_dispatch_hook(MESSAGE_CONTEXT *pcontext);

BOOL gateway_dispatch_verify_ipdomain(const char *domain, const char *ip);

int gateway_dispatch_get_param(int param);

void gateway_dispatch_console_talk(int argc, char **argv, char *result,
	int length);


#endif /* _H_GATEWAY_DISPATCH_ */

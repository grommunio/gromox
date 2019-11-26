#ifndef _H_DNS_ADAPTOR_
#define _H_DNS_ADAPTOR_
#include "common_types.h"
#include "vstack.h"
#include <time.h>

enum {
	DNS_ADAPTOR_TIMEOUT = 0,
	DNS_ADAPTOR_VALID_INTERVAL
};

void dns_adaptor_init(const char *path, int capacity, time_t valid_interval);
extern void dns_adaptor_free(void);
extern int dns_adaptor_run(void);
extern int dns_adaptor_stop(void);
BOOL dns_adaptor_query_MX(char* mx_name, VSTACK* pstack);

BOOL dns_adaptor_query_A(char* domain, VSTACK* pstack);

void dns_adaptor_console_talk(int argc, char **argv, char *result, int length);

#endif /* _H_DNS_ADAPTOR_ */


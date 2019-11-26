#ifndef _H_SESSION_CLIENT_
#define _H_SESSION_CLIENT_
#include "common_types.h"

void session_client_init(const char *ip, int port);
extern int session_client_run(void);
extern int session_client_stop(void);
BOOL session_client_check(const char *domainname, const char *session);
extern void session_client_free(void);

#endif

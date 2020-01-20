#pragma once
#include "common_types.h"

void session_client_init(const char *ip, int port);
extern int session_client_run(void);
extern int session_client_stop(void);
BOOL session_client_update(const char *domainname,
	const char *cookie, char *session);

BOOL session_client_check(const char *domainname, const char *session);

BOOL session_client_remove(const char *domainname, const char *session);
extern void session_client_free(void);

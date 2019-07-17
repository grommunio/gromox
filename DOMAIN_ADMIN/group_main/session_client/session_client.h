#ifndef _H_SESSION_CLIENT_
#define _H_SESSION_CLIENT_
#include "common_types.h"

void session_client_init(const char *ip, int port);

int session_client_run();

int session_client_stop();

BOOL session_client_update(const char *domainname,
	const char *cookie, char *session);

BOOL session_client_check(const char *domainname, const char *session);

BOOL session_client_remove(const char *domainname, const char *session);

void session_client_free();


#endif

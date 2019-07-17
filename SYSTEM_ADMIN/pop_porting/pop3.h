#ifndef _H_POP3_
#define _H_POP3_
#include "common_types.h"

typedef struct _POP3_SESSION {
	char server_ip[16];
	int port;
	char username[256];
	char password[256];
	int sockd;
} POP3_SESSION;

void pop3_init(POP3_SESSION *psession, const char *ip, int port,
	const char *username, const char *password);

BOOL pop3_login(POP3_SESSION *psession);

BOOL pop3_list(POP3_SESSION *psession, int *pnum);

BOOL pop3_retr(POP3_SESSION *psession, int n, char *pbuff, int size);

void pop3_free(POP3_SESSION *psession);


#endif

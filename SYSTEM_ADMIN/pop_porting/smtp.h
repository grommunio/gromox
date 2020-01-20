#pragma once
#include "common_types.h"

typedef struct _SMTP_SESSION {
	char ip[16];
	int port;
} SMTP_SESSION;

void smtp_init(SMTP_SESSION *psession, const char *ip, int port);

BOOL smtp_send(SMTP_SESSION *psession, const char *from, const char *rcpt,
	const char *message);

void smtp_free(SMTP_SESSION *psession);

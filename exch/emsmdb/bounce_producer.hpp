#pragma once
#include <gromox/mail.hpp>

struct MAIL;
struct MESSAGE_CONTENT;

enum{
	BOUNCE_NOTIFY_READ,
	BOUNCE_NOTIFY_NON_READ,
	BOUNCE_TOTAL_NUM
};

extern int bounce_producer_run(const char *, const char *, const char *);
extern BOOL bounce_producer_make(const char *username, MESSAGE_CONTENT *pbrief, unsigned int bounce_type, MAIL *);

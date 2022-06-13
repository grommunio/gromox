#pragma once
#include <gromox/mapi_types.hpp>

struct MAIL;
struct MESSAGE_CONTENT;

enum{
	BOUNCE_NOTIFY_READ,
	BOUNCE_NOTIFY_NON_READ,
	BOUNCE_TOTAL_NUM
};

extern void bounce_producer_init(const char *separator);
extern int bounce_producer_run(const char *data_path);
extern BOOL bounce_producer_make(const char *username, MESSAGE_CONTENT *brief, int bounce_type, MAIL *);

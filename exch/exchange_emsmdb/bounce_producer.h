#pragma once
#include <gromox/mail.hpp>
#include <gromox/element_data.hpp>

enum{
	BOUNCE_NOTIFY_READ,
	BOUNCE_NOTIFY_NON_READ,
	BOUNCE_TOTAL_NUM
};

extern void bounce_producer_init(const char *separator);
extern int bounce_producer_run(const char *data_path);
extern void bounce_producer_stop();
extern void bounce_producer_free();
extern BOOL bounce_producer_refresh(const char *data_path);
BOOL bounce_producer_make(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, MAIL *pmail);

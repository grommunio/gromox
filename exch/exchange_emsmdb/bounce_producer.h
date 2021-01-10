#pragma once
#include "mail.h"
#include <gromox/element_data.hpp>

enum{
	BOUNCE_NOTIFY_READ,
	BOUNCE_NOTIFY_NON_READ,
	BOUNCE_TOTAL_NUM
};

#ifdef __cplusplus
extern "C" {
#endif

void bounce_producer_init(const char *path, const char *separator);
extern int bounce_producer_run(void);
extern void bounce_producer_stop(void);
extern void bounce_producer_free(void);
extern BOOL bounce_producer_refresh(void);
BOOL bounce_producer_make(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, MAIL *pmail);

#ifdef __cplusplus
} /* extern "C" */
#endif

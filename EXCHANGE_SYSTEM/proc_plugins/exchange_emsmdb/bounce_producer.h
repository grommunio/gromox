#ifndef _H_BOUNCE_PRODUCER_
#define _H_BOUNCE_PRODUCER_
#include "mail.h"
#include "element_data.h"

enum{
	BOUNCE_NOTIFY_READ,
	BOUNCE_NOTIFY_NON_READ,
	BOUNCE_TOTAL_NUM
};

void bounce_producer_init(const char *path, const char *separator);

int bounce_producer_run();
extern void bounce_producer_stop(void);
void bounce_producer_free();

BOOL bounce_producer_refresh();

BOOL bounce_producer_make(const char *username,
	MESSAGE_CONTENT *pbrief, int bounce_type, MAIL *pmail);

#endif /* _H_BOUNCE_PRODUCER_ */

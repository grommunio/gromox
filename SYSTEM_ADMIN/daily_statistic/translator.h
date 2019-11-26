#ifndef _H_TRANSLATOR_
#define _H_TRANSLATOR__
#include "data_extractor.h"

void translator_init(const char *path);

int translator_run();
extern void translator_stop(void);
void translator_free();

void translator_do(STATISTIC_ITEM *psmtp_item, int smtp_num,
	STATISTIC_ITEM *pdelivery_item, int delivery_num, const char *language);

#endif

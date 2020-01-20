#pragma once
#include "data_extractor.h"

void translator_init(const char *path);
extern int translator_run(void);
extern void translator_stop(void);
extern void translator_free(void);
void translator_do(STATISTIC_ITEM *psmtp_item, int smtp_num,
	STATISTIC_ITEM *pdelivery_item, int delivery_num, const char *language);

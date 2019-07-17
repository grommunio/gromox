#ifndef _H_DATA_EXTRACTOR_
#define _H_DATA_EXTRACTOR_
#include <time.h>

#define SPAM_TAG_LEN        128

typedef struct _STATISTIC_ITEM {
	char    tag[SPAM_TAG_LEN];
	int     number;
} STATISTIC_ITEM;

void data_extractor_init(const char *path);

int data_extractor_run();

void data_extractor_retrieve(const char *console_ip,
	STATISTIC_ITEM *psmtp_item, int *smtp_num, time_t *smtp_time,
	STATISTIC_ITEM *pdelivery_item, int *delivery_num, time_t *delivery_time);

int data_extractor_stop();

void data_extractor_free();

#endif

#ifndef _H_DATA_EXTRACTOR_
#define _H_DATA_EXTRACTOR_

typedef struct _STATUS_ITEM {
	int		cpu;
	double	network;
	int     connection;
} STATUS_ITEM;

void data_extractor_init(const char *path);

int data_extractor_run();

int data_extractor_retrieve(const char *console_ip, STATUS_ITEM *items);

int data_extractor_stop();

void data_extractor_free();

#endif

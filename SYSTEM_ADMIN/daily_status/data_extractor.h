#pragma once

typedef struct _STATUS_ITEM {
	int		cpu;
	double	network;
	int     connection;
} STATUS_ITEM;

void data_extractor_init(const char *path);
extern int data_extractor_run(void);
int data_extractor_retrieve(const char *console_ip, STATUS_ITEM *items);
extern int data_extractor_stop(void);
extern void data_extractor_free(void);

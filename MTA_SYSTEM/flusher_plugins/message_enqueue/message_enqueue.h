#pragma once
#include <gromox/flusher_common.h>

enum{
	MESSAGE_TAPE = 1,
	MESSAGE_MESS
};

enum{
	SMTP_IN = 1,
	SMTP_OUT,
	SMTP_RELAY
};

typedef void (*SPAM_STATISTIC)(int);

extern SPAM_STATISTIC spam_statistic;

void message_enqueue_init(const char *path, int tapse_units);
extern int message_enqueue_run(void);
extern int message_enqueue_stop(void);
extern void message_enqueue_free(void);
void message_enqueue_cancel(FLUSH_ENTITY *pentity);
extern int message_enqueue_retrieve_flush_ID(void);
void message_enqueue_console_talk(int argc, char **argv, char *result,
	int length);

#ifndef _H_MESSAGE_ENQUEUE_
#define _H_MESSAGE_ENQUEUE_

#include "flusher_common.h"

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

int message_enqueue_run();

int message_enqueue_stop();

void message_enqueue_free();

void message_enqueue_cancel(FLUSH_ENTITY *pentity);

int message_enqueue_retrieve_flush_ID();

void message_enqueue_console_talk(int argc, char **argv, char *result,
	int length);

#endif


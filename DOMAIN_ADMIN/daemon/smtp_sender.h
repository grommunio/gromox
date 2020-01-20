#pragma once
#include "common_types.h"

extern void smtp_sender_init(void);
extern int smtp_sender_run(void);
void smtp_sender_send(const char *sender, const char *address, 
	const char *pbuff, int size);
extern int smtp_sender_stop(void);
extern void smtp_sender_free(void);

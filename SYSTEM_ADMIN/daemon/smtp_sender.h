#pragma once
#include "common_types.h"
void smtp_sender_send(const char *sender, const char *address, 
	const char *pbuff, int size);

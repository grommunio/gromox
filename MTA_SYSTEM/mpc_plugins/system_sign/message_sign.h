#ifndef _H_MESSAGE_SIGN_
#define _H_MESSAGE_SIGN_
#include "mail.h"

void message_sign_init(const char *path);

int message_sign_run();

void message_sign_mark(MAIL *pmail);

int message_sign_stop();

void message_sign_free();

BOOL message_sign_refresh();

#endif

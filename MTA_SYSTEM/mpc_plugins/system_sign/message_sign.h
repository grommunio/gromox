#ifndef _H_MESSAGE_SIGN_
#define _H_MESSAGE_SIGN_
#include "mail.h"

void message_sign_init(const char *path);
extern int message_sign_run(void);
void message_sign_mark(MAIL *pmail);
extern int message_sign_stop(void);
extern void message_sign_free(void);
extern BOOL message_sign_refresh(void);

#endif

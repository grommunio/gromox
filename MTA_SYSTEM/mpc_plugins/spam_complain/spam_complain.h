#ifndef _H_SPAM_COMPLAIN_
#define _H_SPAM_COMPLAIN__
#include "hook_common.h"

void spam_complain_init();

int spam_complain_run();

int spam_complain_stop();

void spam_complain_free();

BOOL spam_complain_process(MESSAGE_CONTEXT *pcontext);

#endif /* _H_SPAM_COMPLAIN_ */

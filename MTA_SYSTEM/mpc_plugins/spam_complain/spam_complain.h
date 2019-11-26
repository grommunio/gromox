#ifndef _H_SPAM_COMPLAIN_
#define _H_SPAM_COMPLAIN__
#include "hook_common.h"

extern void spam_complain_init(void);
extern int spam_complain_run(void);
extern int spam_complain_stop(void);
extern void spam_complain_free(void);
BOOL spam_complain_process(MESSAGE_CONTEXT *pcontext);

#endif /* _H_SPAM_COMPLAIN_ */

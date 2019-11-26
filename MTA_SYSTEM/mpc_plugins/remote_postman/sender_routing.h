#ifndef _H_SENDER_ROUTING_
#define _H_SENDER_ROUTING_
#include "common_types.h"
#include "vstack.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


void sender_routing_init(const char *list_path);
extern int sender_routing_run(void);
BOOL sender_routing_check(const char *sender, VSTACK *pstack);
extern BOOL sender_routing_refresh(void);
extern void sender_routing_stop(void);
extern void sender_routing_free(void);

#endif /* end of _H_SENDER_ROUTING_ */

#ifndef _H_SENDER_ROUTING_
#define _H_SENDER_ROUTING_
#include "common_types.h"
#include "vstack.h"
#include <fcntl.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH


void sender_routing_init(const char *list_path);

int sender_routing_run();

BOOL sender_routing_check(const char *sender, VSTACK *pstack);

BOOL sender_routing_refresh();

int sender_routing_stop();

void sender_routing_free();


#endif /* end of _H_SENDER_ROUTING_ */

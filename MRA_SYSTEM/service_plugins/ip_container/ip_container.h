#ifndef _H_IP_CONTAINER_
#define _H_IP_CONTAINER_
#include "common_types.h"

void ip_container_init(int table_size, int max_num);

void ip_container_free();

int ip_container_run();

int ip_container_stop();

BOOL ip_container_add(const char* ip);

BOOL ip_container_remove(const char* ip);

void ip_container_console_talk(int argc, char **argv, char *result, int length);

#endif /* _H_IP_CONTAINER_ */

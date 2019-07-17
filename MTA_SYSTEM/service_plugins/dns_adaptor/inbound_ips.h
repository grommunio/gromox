#ifndef _H_INBOUND_IPS_
#define _H_INBOUND_IPS_
#include "common_types.h"

void inbound_ips_init(const char *path);

int inbound_ips_run();

BOOL inbound_ips_check_local(const char *domain);

BOOL inbound_ips_refresh();

int inbound_ips_stop();

void inbound_ips_free();

#endif

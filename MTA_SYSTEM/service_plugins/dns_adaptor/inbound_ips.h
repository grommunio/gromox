#pragma once
#include "common_types.h"

void inbound_ips_init(const char *path);
extern int inbound_ips_run(void);
BOOL inbound_ips_check_local(const char *domain);
extern BOOL inbound_ips_refresh(void);
extern int inbound_ips_stop(void);
extern void inbound_ips_free(void);

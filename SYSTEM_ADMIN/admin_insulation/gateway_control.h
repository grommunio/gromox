#pragma once
#include "common_types.h"

void gateway_control_init(const char *path);
extern int gateway_control_run(void);
BOOL gateway_control_activate(const char *path);
extern int gateway_control_stop(void);
extern void gateway_control_free(void);

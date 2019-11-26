#ifndef _H_GATEWAY_CONZTROL_
#define _H_GATEWAY_CONZTROL_
#include "common_types.h"

void gateway_control_init(const char *path);

int gateway_control_run();

BOOL gateway_control_activate(const char *path);

int gateway_control_stop();

void gateway_control_free();

#endif

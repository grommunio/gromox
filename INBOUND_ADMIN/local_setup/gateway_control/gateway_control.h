#ifndef _H_GATEWAY_CONTROL_
#define _H_GATEWAY_CONTROL_
#include "common_types.h"

void gateway_control_init(const char *path);

int gateway_control_run();

void gateway_control_enable_domains(BOOL b_enable);

void gateway_control_reload_ips();

void gateway_control_reload_domains();

int gateway_control_stop();

void gateway_control_free();

#endif

#pragma once
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define NOTIFY_DELIVERY		0x00000002

void gateway_control_init(const char *path);
extern int gateway_control_run();
void gateway_control_notify(const char *command, int control_mask);

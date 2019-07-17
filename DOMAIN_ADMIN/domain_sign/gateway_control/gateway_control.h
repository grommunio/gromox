#ifndef _H_GATEWAY_CONTROL_
#define _H_GATEWAY_CONTROL_

#define NOTIFY_SMTP			0x00000001
#define NOTIFY_DELIVERY		0x00000002

void gateway_control_init(const char *path);

int gateway_control_run();

void gateway_control_notify(const char *command, int control_mask);

int gateway_control_stop();

void gateway_control_free();

#endif

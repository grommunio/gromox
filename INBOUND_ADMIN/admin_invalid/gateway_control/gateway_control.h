#ifndef _H_GATEWAY_CONTROL_
#define _H_GATEWAY_CONTROL_

void gateway_control_init(const char *path);

int gateway_control_run();

void gateway_control_dump();

void gateway_control_clear();

void gateway_control_remove(const char *address);

int gateway_control_stop();

void gateway_control_free();

#endif

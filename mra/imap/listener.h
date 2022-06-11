#pragma once
#include <cstdint>
extern void listener_init(uint16_t port, uint16_t port_ssl);
extern int listener_run();
extern int listener_trigger_accept();
extern void listener_stop_accept();
extern void listener_stop();
extern char *capability_list(char *, size_t, bool tls);

extern uint16_t g_listener_ssl_port;

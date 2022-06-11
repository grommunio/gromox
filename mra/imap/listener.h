#pragma once
#include <cstdint>
struct IMAP_CONTEXT;

extern void listener_init(uint16_t port, uint16_t port_ssl);
extern int listener_run();
extern int listener_trigger_accept();
extern void listener_stop_accept();
extern void listener_stop();
extern char *capability_list(char *, size_t, IMAP_CONTEXT *);

extern uint16_t g_listener_ssl_port;

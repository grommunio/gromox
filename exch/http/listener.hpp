#pragma once
#include <cstdint>
extern int listener_init(const char *addr, uint16_t port, uint16_t port_ssl);
extern int listener_trigger_accept();
extern void listener_stop();

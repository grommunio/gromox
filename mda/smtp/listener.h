#pragma once
#include <cstdint>
extern void listener_init(uint16_t port, uint16_t ssl_port);
extern int listener_run();
extern int listener_trigger_accept();
extern void listener_stop_accept();
extern void listener_free();
extern void listener_stop();

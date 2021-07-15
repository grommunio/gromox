#pragma once
#include <cstdint>
extern void listener_init(const char *host, uint16_t port);
extern int listener_run(const char *configdir);
extern int listener_trigger_accept();
extern int listener_stop();
extern void listener_free();

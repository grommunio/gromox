#pragma once
#include <cstdint>
extern void listener_init(const char *host, uint16_t port);
extern int listener_run(const char *config_dir, const char *hosts_allow);
extern int listener_trigger_accept();
extern void listener_stop();

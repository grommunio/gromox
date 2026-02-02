#pragma once
#include <cstdint>
extern int exmdb_listener_init(const char *config_path, const char *hosts_allow, const char *host, uint16_t port);
extern int exmdb_listener_trigger_accept();
extern void exmdb_listener_stop();

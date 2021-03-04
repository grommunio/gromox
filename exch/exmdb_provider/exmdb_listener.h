#pragma once
extern void exmdb_listener_init(const char *ip, int port);
extern int exmdb_listener_run(const char *config_path);
extern int exmdb_listener_trigger_accept();
extern int exmdb_listener_stop();

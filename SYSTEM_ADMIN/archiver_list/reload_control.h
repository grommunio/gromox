#pragma once

void reload_control_init(const char *path);
extern int reload_control_run(void);
extern void reload_control_notify(void);
extern int reload_control_stop(void);
extern void reload_control_free(void);

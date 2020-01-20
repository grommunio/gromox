#pragma once

void reload_control_init(const char *path);
extern int reload_control_run(void);
extern void reload_control_notify_charset(void);
void reload_control_notify_keyword(const char *list);
extern int reload_control_stop(void);
extern void reload_control_free(void);

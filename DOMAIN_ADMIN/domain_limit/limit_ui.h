#pragma once

void limit_ui_init(const char *mount_path, const char *url_link,
	const char *resource_path);
extern int limit_ui_run(void);
extern int limit_ui_stop(void);
extern void limit_ui_free(void);

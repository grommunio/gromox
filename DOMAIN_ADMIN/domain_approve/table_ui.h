#pragma once

void table_ui_init(const char *mount_path, const char *url_link,
	const char *resource_path);
extern int table_ui_run(void);
extern int table_ui_stop(void);
extern void table_ui_free(void);

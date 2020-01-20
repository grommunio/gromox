#pragma once

void group_ui_init(const char *list_path, const char *mount_path,
	const char *url_link, const char *resource_path);
extern int group_ui_run(void);
extern int group_ui_stop(void);
extern void group_ui_free(void);

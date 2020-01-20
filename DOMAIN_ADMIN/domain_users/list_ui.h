#pragma once

void list_ui_init(const char *list_path, int max_file,
	const char *url_link, const char *resource_path,
	const char *thumbnail_path);
extern int list_ui_run(void);
extern int list_ui_stop(void);
extern void list_ui_free(void);

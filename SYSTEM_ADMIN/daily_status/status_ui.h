#pragma once

void status_ui_init(const char *list_path, const char *url_link,
	const char *resource_path);
extern int status_ui_run(void);
extern int status_ui_stop(void);
extern void status_ui_free(void);

#pragma once

void statistic_ui_init(const char *list_path, const char *url_link,
	const char *resource_path);
extern int statistic_ui_run(void);
extern int statistic_ui_stop(void);
extern void statistic_ui_free(void);

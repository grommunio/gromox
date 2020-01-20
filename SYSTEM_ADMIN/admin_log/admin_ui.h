#pragma once

void admin_ui_init(int valid_days, const char *url_link,
	const char *resource_path);
extern int admin_ui_run(void);
extern int admin_ui_stop(void);
extern void admin_ui_free(void);

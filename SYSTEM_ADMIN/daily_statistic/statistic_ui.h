#ifndef _H_STATISTIC_UI_
#define _H_STATISTIC_UI_

void statistic_ui_init(const char *list_path, const char *url_link,
	const char *resource_path);

int statistic_ui_run();

int statistic_ui_stop();

void statistic_ui_free();

#endif


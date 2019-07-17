#ifndef _H_STATUS_UI_
#define _H_STATUS_UI_

void status_ui_init(const char *list_path, const char *url_link,
	const char *resource_path);

int status_ui_run();

int status_ui_stop();

void status_ui_free();

#endif


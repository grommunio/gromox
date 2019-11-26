#ifndef _H_LIMIT_UI_
#define _H_LIMIT_UI_

void limit_ui_init(const char *mount_path, const char *url_link,
	const char *resource_path);

int limit_ui_run();

int limit_ui_stop();

void limit_ui_free();

#endif


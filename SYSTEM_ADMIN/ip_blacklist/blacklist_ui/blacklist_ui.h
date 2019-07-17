#ifndef _H_BLACKLIST_UI_
#define _H_BLACKLIST_UI_

void blacklist_ui_init(const char *list_path, const char *white_path,
	const char *mount_path, const char *url_link, const char *resource_path);

int blacklist_ui_run();

int blacklist_ui_stop();

void blacklist_ui_free();

#endif


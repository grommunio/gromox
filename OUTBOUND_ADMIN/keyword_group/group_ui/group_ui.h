#ifndef _H_GROUP_UI_
#define _H_GROUP_UI_

void group_ui_init(const char *list_path, const char *mount_path,
	const char *url_link, const char *resource_path);

int group_ui_run();

int group_ui_stop();

void group_ui_free();

#endif


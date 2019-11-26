#ifndef _H_LIST_UI_
#define _H_LIST_UI_

void list_ui_init(const char *list_path, int max_file,
	const char *url_link, const char *resource_path,
	const char *thumbnail_path);

int list_ui_run();

int list_ui_stop();

void list_ui_free();


#endif


#ifndef _H_LIST_UI_
#define _H_LIST_UI_

void list_ui_init(const char *list_path, const char *mount_path,
	const char *url_link, const char *resource_path);
extern int list_ui_run(void);
extern int list_ui_stop(void);
extern void list_ui_free(void);

#endif


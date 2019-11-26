#ifndef _H_PASSWORD_UI_
#define _H_PASSWORD_UI_

void password_ui_init(const char *list_path, const char *url_link,
	const char *resource_path);
extern int password_ui_run(void);
extern int password_ui_stop(void);
extern void password_ui_free(void);

#endif


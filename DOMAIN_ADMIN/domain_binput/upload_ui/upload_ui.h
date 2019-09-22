#ifndef _H_UPLOAD_UI_
#define _H_UPLOAD_UI_

void upload_ui_init(const char *list_path, int max_file, const char *url_link,
	const char *host, int port, const char *user, const char *password,
	const char *db_name, const char *resource_path, const char *thumbnail_path);

int upload_ui_run();

int upload_ui_stop();

void upload_ui_free();

#endif


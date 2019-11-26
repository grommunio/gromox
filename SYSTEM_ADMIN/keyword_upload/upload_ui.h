#ifndef _H_UPLOAD_UI_
#define _H_UPLOAD_UI_

void upload_ui_init(const char *charset_path, const char *subject_path,
	const char *from_path, const char *to_path, const char *cc_path,
	const char *content_path, const char *attachment_path,
	const char *mount_path, const char *url_link, const char *resource_path);

int upload_ui_run();

int upload_ui_stop();

void upload_ui_free();

#endif


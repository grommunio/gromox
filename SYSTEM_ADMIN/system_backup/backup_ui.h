#ifndef _H_BACKUP_UI_
#define _H_BACKUP_UI_

void backup_ui_init(const char *backup_path, const char *config_path,
	const char *data_path, const char *mount_path, const char *token_path,
	const char *url_link, const char *resource_path);

int backup_ui_run();

int backup_ui_stop();

void backup_ui_free();

#endif


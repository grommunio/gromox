#pragma once

void auto_backup_init(const char *config_path, const char *data_path,
	const char *backup_path, const char *admin_mailbox, const char *default_domain);
extern int auto_backup_run(void);

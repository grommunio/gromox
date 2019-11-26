#ifndef _H_AUTO_BACKUP_
#define _H_AUTO_BACKUP_

void auto_backup_init(const char *config_path, const char *data_path,
	const char *backup_path, const char *admin_mailbox, const char *default_domain);

int auto_backup_run();

int auto_backup_stop();

void auto_backup_free();

#endif

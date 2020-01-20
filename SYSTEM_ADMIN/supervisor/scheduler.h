#pragma once

void scheduler_init(const char *list_path, const char *failure_path,
	const char *default_domain, const char *admin_mailbox, int max_interval);
extern int scheduler_run(void);
extern void scheduler_stop(void);
extern void scheduler_free(void);

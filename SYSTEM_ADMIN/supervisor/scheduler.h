#ifndef _H_SCHEDULER_
#define _H_SCHEDULER_

void scheduler_init(const char *list_path, const char *failure_path,
	const char *default_domain, const char *admin_mailbox, int max_interval);

int scheduler_run();
extern void scheduler_stop(void);
void scheduler_free();

#endif

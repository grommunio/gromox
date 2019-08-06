#ifndef _H_ENGINE_
#define _H_ENGINE_
#include "common_types.h"

void engine_init(const char *list_path, int log_days,
	int valid_days, const char *default_domain,
	const char *admin_mailbox, const char *db_name,
	const char *backup_path, BOOL parellel_scanning,
	BOOL freetime_scanning);

int engine_run();

int engine_stop();

void engine_free();


#endif

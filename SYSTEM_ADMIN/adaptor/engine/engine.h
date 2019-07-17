#ifndef _H_ENGINE_
#define _H_ENGINE_
#include "common_types.h"

void engine_init(const char *mount_path, const char *domainlist_path,
	const char *aliasaddress_path, const char *aliasdomain_path,
	const char *backup_path, const char *unchkusr_path,
	const char *collector_path, const char *subsystem_path);

int engine_run();

int engine_stop();

void engine_free();

#endif

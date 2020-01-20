#pragma once
#include "common_types.h"

void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);
extern int data_source_run(void);
extern int data_source_stop(void);
extern void data_source_free(void);
BOOL data_source_system_info(int *preal_domains, int *pbackup, int *pmonitor,
	int *punchkusr, int *psubsys, int *psms, int *pextpasswd, int *palias_domains,
	int *poutofdate, int *pdeleted, int *psuspend, int *pgroups,
	int *palloc_addresses, int *preal_addresses, int *palias_address,
	int *pmlists, long *ptotal_space);

#ifndef _H_MIDB_CLIENT_
#define _H_MIDB_CLIENT_

#include "common_types.h"

void midb_client_init(const char *list_path);

int midb_client_run();

int midb_client_stop();

void midb_client_free();

BOOL midb_client_insert(const char *maildir, const char *folder,
	const char *mid_string, const char *flag_strings, long rcv_time);


#endif

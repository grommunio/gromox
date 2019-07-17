#ifndef _H_MIDB_CLIENT_
#define _H_MIDB_CLIENT_

#include "common_types.h"

void midb_client_init(const char *list_path);

int midb_client_run();

int midb_client_stop();

void midb_client_free();

BOOL midb_client_move(const char *maildir, const char *src_folder,
	const char *messge_id, const char *dst_folder);


#endif

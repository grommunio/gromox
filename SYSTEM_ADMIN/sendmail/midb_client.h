#ifndef _H_MIDB_CLIENT_
#define _H_MIDB_CLIENT_

#include "common_types.h"

void midb_client_init(const char *list_path);
extern int midb_client_run(void);
extern int midb_client_stop(void);
extern void midb_client_free(void);
BOOL midb_client_move(const char *maildir, const char *src_folder,
	const char *messge_id, const char *dst_folder);


#endif

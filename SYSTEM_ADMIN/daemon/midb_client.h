#ifndef _H_MIDB_CLIENT_
#define _H_MIDB_CLIENT_

#include "common_types.h"

void midb_client_init(const char *list_path);
extern int midb_client_run(void);
extern int midb_client_stop(void);
extern void midb_client_free(void);
BOOL midb_client_insert(const char *maildir,
	const char *folder, const char *mid_string);


#endif

#ifndef _H_UID_DB_
#define _H_UID_DB_
#include "pop3.h"
#include "list_file.h"

typedef struct _UID_DB {
	char mailbox_path[256];
	char username[256];
	LIST_FILE *pfile;
} UID_DB;

void uid_db_init(UID_DB *pdb, const char *path, const char *username);

BOOL uid_db_open(UID_DB *pdb);

BOOL uid_db_close(UID_DB *pdb);

void uid_db_free(UID_DB *pdb);

BOOL uid_db_update(UID_DB *pdb, POP3_SESSION *psession);

BOOL uid_db_check(UID_DB *pdb, POP3_SESSION *psession);

#endif

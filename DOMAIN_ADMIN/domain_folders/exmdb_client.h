#ifndef _H_EXMDB_CLIENT_
#define _H_EXMDB_CLIENT_
#include "mapi_types.h"

void exmdb_client_init(const char *list_path);
extern int exmdb_client_run(void);
extern int exmdb_client_stop(void);
extern void exmdb_client_free(void);
BOOL exmdb_client_create_folder(const char *dir, int domain_id,
	const char *folder_name, const char *container, const char *comment);
	
BOOL exmdb_client_delete_folder(const char *dir, uint32_t cpid,
	uint64_t folder_id, BOOL b_hard, BOOL *pb_result);
	
BOOL exmdb_client_get_folder_list(const char *dir, TARRAY_SET *pset);

BOOL exmdb_client_get_permission_list(const char *dir,
	uint64_t folder_id, TARRAY_SET *pset);

BOOL exmdb_client_add_folder_owner(const char *dir,
	uint64_t folder_id, const char *username);

BOOL exmdb_client_remove_folder_owner(const char *dir,
	uint64_t folder_id, uint64_t member_id);

#endif

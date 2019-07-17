#ifndef _H_EXMDB_CLIENT_
#define _H_EXMDB_CLIENT_
#include "mapi_types.h"
#include "element_data.h"


void exmdb_client_init(int conn_num,
	int threads_num, const char *list_path);

int exmdb_client_run();

int exmdb_client_stop();

void exmdb_client_free();

BOOL exmdb_client_ping_store(const char *dir);

BOOL exmdb_client_subscribe_notification(const char *dir,
	uint16_t notificaton_type, BOOL b_whole, uint64_t folder_id,
	uint64_t message_id, uint32_t *psub_id);

BOOL exmdb_client_unsubscribe_notification(
	const char *dir, uint32_t sub_id);

void exmdb_client_register_proc(void *pproc);

#endif /* _H_EXMDB_CLIENT_ */

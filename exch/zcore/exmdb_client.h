#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>

enum {
	ALIVE_PROXY_CONNECTIONS,
	LOST_PROXY_CONNECTIONS
};

struct EXMDB_REQUEST;
struct EXMDB_RESPONSE;

int exmdb_client_get_param(int param);
extern void exmdb_client_init(int conn_num, int threads_num);
extern int exmdb_client_run(const char *configdir);
extern int exmdb_client_stop();
BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid);
BOOL exmdb_client_get_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_get_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_delete_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t folder_id,
	uint64_t message_id, BOOL b_hard, BOOL *pb_done);

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	uint32_t proptag, void **ppval);

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult);

BOOL exmdb_client_remove_instance_property(const char *dir,
	uint32_t instance_id, uint32_t proptag, uint32_t *presult);

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner);

BOOL exmdb_client_remove_message_property(const char *dir,
	uint32_t cpid, uint64_t message_id, uint32_t proptag);

void exmdb_client_register_proc(void *pproc);
extern BOOL exmdb_client_do_rpc(const char *dir, const EXMDB_REQUEST *, EXMDB_RESPONSE *);

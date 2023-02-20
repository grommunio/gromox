#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/mapi_types.hpp>

namespace exmdb_client = exmdb_client_remote;

extern int exmdb_client_run_front(const char *);
BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid);
extern BOOL exmdb_client_get_folder_property(const char *dir, cpid_t, uint64_t folder_id, uint32_t proptag, void **val);
extern BOOL exmdb_client_get_message_property(const char *dir, const char *username, cpid_t, uint64_t message_id, uint32_t proptag, void **val);
extern BOOL exmdb_client_delete_message(const char *dir, int account_id, cpid_t, uint64_t folder_id, uint64_t message_id, BOOL hard, BOOL *done);
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
extern BOOL exmdb_client_remove_message_property(const char *dir, cpid_t, uint64_t message_id, uint32_t proptag);
void exmdb_client_register_proc(void *pproc);

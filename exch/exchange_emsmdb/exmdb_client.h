#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/element_data.hpp>

extern void exmdb_client_init();
extern int exmdb_client_run();
extern int exmdb_client_stop();
extern void exmdb_client_free();
extern BOOL exmdb_client_get_named_propid(const char *dir, BOOL create, const PROPERTY_NAME *, uint16_t *ppropid);
extern BOOL exmdb_client_get_named_propname(const char *dir, uint16_t propid, PROPERTY_NAME *);
extern BOOL exmdb_client_get_store_property(const char *dir, uint32_t cpid, uint32_t proptag, void **ppval);
extern BOOL exmdb_client_get_folder_property(const char *dir, uint32_t cpid, uint64_t folder_id, uint32_t proptag, void **ppval);
extern BOOL exmdb_client_delete_message(const char *dir, int account_id, uint32_t cpid, uint64_t folder_id, uint64_t msg_id, BOOL b_hard, BOOL *pb_done);
extern BOOL exmdb_client_check_message_owner(const char *dir, uint64_t msg_id, const char *username, BOOL *pb_owner);
extern BOOL exmdb_client_get_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, void **ppval);
extern BOOL exmdb_client_set_instance_property(const char *dir, uint32_t instance_id, const TAGGED_PROPVAL *, uint32_t *presult);
extern BOOL exmdb_client_remove_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, uint32_t *presult);
extern BOOL exmdb_client_get_message_property(const char *dir, const char *username, uint32_t cpid, uint64_t msg_id, uint32_t proptag, void **ppval);
extern BOOL exmdb_client_set_message_property(const char *dir, const char *username, uint32_t cpid, uint64_t msg_id, TAGGED_PROPVAL *, uint32_t *presult);
extern BOOL exmdb_client_remove_message_property(const char *dir, uint32_t cpid, uint64_t msg_id, uint32_t proptag);
#define EXMIDL(n, p) extern BOOL (*exmdb_client_ ## n) p;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

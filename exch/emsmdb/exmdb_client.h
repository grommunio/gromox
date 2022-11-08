#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>

namespace exmdb_client_ems {

extern void init();
extern int run();
extern void stop();
extern void free();
extern BOOL get_named_propid(const char *dir, BOOL create, const PROPERTY_NAME *, uint16_t *ppropid);
extern BOOL get_named_propname(const char *dir, uint16_t propid, PROPERTY_NAME *);
extern BOOL get_store_property(const char *dir, uint32_t cpid, uint32_t proptag, void **ppval);
extern BOOL get_folder_property(const char *dir, uint32_t cpid, uint64_t folder_id, uint32_t proptag, void **ppval);
extern BOOL delete_message(const char *dir, int account_id, uint32_t cpid, uint64_t folder_id, uint64_t msg_id, BOOL b_hard, BOOL *pb_done);
extern BOOL check_message_owner(const char *dir, uint64_t msg_id, const char *username, BOOL *pb_owner);
extern BOOL get_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, void **ppval);
extern BOOL set_instance_property(const char *dir, uint32_t instance_id, const TAGGED_PROPVAL *, uint32_t *presult);
extern BOOL remove_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, uint32_t *presult);
extern BOOL get_message_property(const char *dir, const char *username, uint32_t cpid, uint64_t msg_id, uint32_t proptag, void **ppval);
extern BOOL set_message_property(const char *dir, const char *username, uint32_t cpid, uint64_t msg_id, TAGGED_PROPVAL *, uint32_t *presult);
extern BOOL remove_message_property(const char *dir, uint32_t cpid, uint64_t msg_id, uint32_t proptag);
#define EXMIDL(n, p) extern BOOL (*n) p;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

}

namespace exmdb_client = exmdb_client_ems;

#pragma once
#include <cstdint>
#include <optional>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>

class GX_EXPORT exmdb_client_shm final {
	public:
	static void init();
	static int run();
	static void stop();
	static void free();
	static BOOL get_named_propid(const char *dir, BOOL create, const PROPERTY_NAME *, uint16_t *ppropid);
	static BOOL get_named_propname(const char *dir, uint16_t propid, PROPERTY_NAME *);
	static BOOL get_store_property(const char *dir, cpid_t, uint32_t proptag, void **ppval);
	static BOOL get_folder_property(const char *dir, cpid_t, uint64_t folder_id, uint32_t proptag, void **ppval);
	static BOOL delete_message(const char *dir, int account_id, cpid_t, uint64_t folder_id, uint64_t msg_id, BOOL b_hard, BOOL *pb_done);
	static BOOL is_message_owner(const char *dir, uint64_t msg_id, const char *username, BOOL *pb_owner);
	static BOOL get_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, void **ppval);
	static BOOL set_instance_property(const char *dir, uint32_t instance_id, const TAGGED_PROPVAL *, uint32_t *presult);
	static BOOL remove_instance_property(const char *dir, uint32_t instance_id, uint32_t proptag, uint32_t *presult);
	static BOOL get_message_property(const char *dir, const char *username, cpid_t, uint64_t msg_id, uint32_t proptag, void **ppval);
	static BOOL set_message_property(const char *dir, const char *username, cpid_t, uint64_t msg_id, TAGGED_PROPVAL *, uint32_t *presult);
	static BOOL remove_message_property(const char *dir, cpid_t, uint64_t msg_id, uint32_t proptag);
#define EXMIDL(n, p) static EXMIDL_RETTYPE (*n) p;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
};

extern std::optional<exmdb_client_shm> exmdb_client;

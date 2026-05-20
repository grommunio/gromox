#pragma once
#include <cstdint>
#include <optional>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/idset.hpp>
#include <gromox/mapi_types.hpp>

class GX_EXPORT exmdb_client_shm final {
	public:
	void init();
	int run();
	void stop();
	void free();
	BOOL get_named_propid(const char *dir, BOOL create, const PROPERTY_NAME *, uint16_t *ppropid);
	BOOL get_named_propname(const char *dir, gromox::propid_t, PROPERTY_NAME *);
	BOOL get_store_property(const char *dir, cpid_t, gromox::proptag_t, void **ppval);
	BOOL get_folder_property(const char *dir, cpid_t, uint64_t folder_id, gromox::proptag_t, void **ppval);
	BOOL delete_message(const char *dir, int account_id, cpid_t, uint64_t folder_id, uint64_t msg_id, BOOL b_hard, BOOL *pb_done);
	BOOL is_message_owner(const char *dir, uint64_t msg_id, const char *username, BOOL *pb_owner);
	BOOL get_instance_property(const char *dir, uint32_t instance_id, gromox::proptag_t, void **ppval);
	BOOL set_instance_property(const char *dir, uint32_t instance_id, const TAGGED_PROPVAL *, uint32_t *presult);
	BOOL remove_instance_property(const char *dir, uint32_t instance_id, gromox::proptag_t, uint32_t *presult);
	BOOL get_message_property(const char *dir, const char *username, cpid_t, uint64_t msg_id, gromox::proptag_t, void **ppval);
	BOOL set_message_property(const char *dir, const char *username, cpid_t, uint64_t msg_id, TAGGED_PROPVAL *, uint32_t *presult);
	BOOL remove_message_property(const char *dir, cpid_t, uint64_t msg_id, gromox::proptag_t);

	/*
	 * Due to https://gcc.gnu.org/bugzilla/show_bug.cgi?id=122630, you will
	 * see some explicit constructor invocations, e.g.
	 * `proptag_cspan{expr}` when exmdb_client_shm's function pointers are
	 * invoked.
	 */
#define EXMIDL(n, p) EXMIDL_RETTYPE (*n) p;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT
};

extern std::optional<exmdb_client_shm> exmdb_client;

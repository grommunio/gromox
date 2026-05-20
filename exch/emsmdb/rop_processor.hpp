#pragma once
#include <cstdint>
#include <ctime>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "logon_object.hpp"

enum class ems_objtype : uint8_t {
	none = 0, logon, folder, message, attach, table, stream, fastdownctx,
	fastupctx, icsdownctx, icsupctx, subscription,
};

struct object_node;

/**
 * LOGON_ITEM - container for tracking the handles within a ropLogon session
 *
 * Within the scope of a ropLogon, the user can e.g. open folders and messages
 * and get handles, whose handle number is scoped to the logon. The store
 * object, i.e. the container with a bunch of readable properties, gets a
 * separate handle in its own right, and it is subordinate to the logon. (This
 * handle is returned in the ropLogon response. It is often index 0 because it
 * is the first handle to be given out, but this is not guaranteed, as
 * alloc_handle_number could yield *any* number for that matter.)
 */
class LOGON_ITEM {
	public:
	~LOGON_ITEM();
	int32_t add_object_handle(int32_t parent_handle, object_node &&);
	void release_object_handle(uint32_t obj_handle);
	logon_object *get_logon_object();
	void *get_object(uint32_t obj_handle, ems_objtype *);

	std::unordered_map<uint32_t, std::shared_ptr<object_node>> phash;
	std::shared_ptr<object_node> root;
	std::string username;
};

extern thread_local const char *g_last_rop_dir;

/**
 * Each emsmdb_session (made with ecDoConnectEx) can have up to 256 "logon" slots that can be used
 * with ropLogon. More on that in LOGON_ITEM.
 *
 * A client like emsmdb32.dll would typically create one ecDoConnectEx session
 * per logical store (e.g. one's own store, someone else's, a public folder,
 * etc.) and usually two logons (but sometimes more) on that.
 */
class LOGMAP {
	public:
	int32_t insert_logon_item(uint8_t logon_id, std::unique_ptr<logon_object> &&);
	int32_t add_object_handle(uint8_t logon_id, int32_t parent_handle, object_node &&);
	void release_object_handle(uint8_t logon_id, uint32_t obj_handle);
	logon_object *get_logon_object(uint8_t logon_id);
	void *get_object(uint8_t logon_id, uint32_t obj_handle, ems_objtype *);
	template<typename T> inline T *get_obj(uint8_t id, uint32_t oh, ems_objtype *ty)
	{
		return static_cast<T *>(get_object(id, oh, ty));
	}
	inline logon_object *get_obj(uint8_t id, uint32_t oh, ems_objtype *ty)
	{
		auto ob = static_cast<logon_object *>(get_object(id, oh, ty));
		g_last_rop_dir = ob->get_dir();
		return ob;
	}

	std::unique_ptr<LOGON_ITEM> p[256];
	std::string username;
};

struct object_node {
	object_node() = default;
	template<typename T> object_node(ems_objtype t, std::unique_ptr<T> &&p) :
		type(t), pobject(p.release())
	{}
	object_node(object_node &&) noexcept;
	~object_node() { clear(); }
	void operator=(object_node &&) noexcept;
	void clear() noexcept;

	uint32_t handle = 0;
	ems_objtype type = ems_objtype::none;
	void *pobject = nullptr;
	std::shared_ptr<object_node> parent;
};

extern void rop_processor_init(int scan_interval);
extern ec_error_t rop_processor_proc(uint32_t flags, const uint8_t *in, uint32_t cb_in, uint8_t *out, uint32_t *cb_out);
extern ec_error_t aoh_to_error(int);

extern unsigned int emsmdb_rop_chaining, emsmdb_max_cxh_per_user;
extern unsigned int emsmdb_max_obh_per_session, emsmdb_pvt_folder_softdel;
extern unsigned int emsmdb_backfill_transporthdr;
extern size_t ems_max_active_sessions, ems_max_active_users, emsmdb_compress_threshold;
extern size_t ems_max_active_notifh, ems_max_pending_sesnotif;
extern uint16_t server_normal_version[4];

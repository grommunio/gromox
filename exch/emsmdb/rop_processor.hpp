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
 * We cannot fixate the root to id 0, because alloc_handle_number could
 * yield *any* number for that matter; therefore it is not possible
 * to do without a member indicating the root (whether pointer or integer).
 */
struct LOGON_ITEM {
	~LOGON_ITEM();
	std::unordered_map<uint32_t, std::shared_ptr<object_node>> phash;
	std::shared_ptr<object_node> root;
};

extern thread_local const char *g_last_rop_dir;

/**
 * @username: RPC user. Only use this for log messages.
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

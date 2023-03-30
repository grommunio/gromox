#pragma once
#include <cstdint>
#include <ctime>
#include <memory>
#include <gromox/mapi_types.hpp>
#include "logon_object.h"

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
	std::unordered_map<uint32_t, std::shared_ptr<object_node>> phash;
	std::shared_ptr<object_node> root;
};

struct LOGMAP {
	std::unique_ptr<LOGON_ITEM> p[256];
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
using OBJECT_NODE = object_node;

extern std::unique_ptr<LOGMAP> rop_processor_create_logmap();
void rop_processor_init(int average_handles, int scan_interval);
extern int rop_processor_run();
extern void rop_processor_stop();
extern ec_error_t rop_processor_proc(uint32_t flags, const uint8_t *in, uint32_t cb_in, uint8_t *out, uint32_t *cb_out);
extern int32_t rop_processor_create_logon_item(LOGMAP *, uint8_t logon_id, std::unique_ptr<logon_object> &&);
extern int32_t rop_processor_add_object_handle(LOGMAP *, uint8_t logon_id, int32_t parent_handle, object_node &&);
extern void *rop_processor_get_object(LOGMAP *, uint8_t logon_id, uint32_t obj_handle, ems_objtype *);
template<typename T> T *rop_proc_get_obj(LOGMAP *l, uint8_t id, uint32_t oh, ems_objtype *ty) {
	return static_cast<T *>(rop_processor_get_object(l, id, oh, ty));
}
extern void rop_processor_release_object_handle(LOGMAP *, uint8_t logon_id, uint32_t obj_handle);
extern logon_object *rop_processor_get_logon_object(LOGMAP *, uint8_t logon_id);
extern ec_error_t aoh_to_error(int);

extern unsigned int emsmdb_rop_chaining, emsmdb_max_cxh_per_user;
extern unsigned int emsmdb_max_hoc;
extern unsigned int emsmdb_max_obh_per_session, emsmdb_pvt_folder_softdel;

#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>

struct folder_object;
struct ICS_STATE;
struct store_object;

struct icsupctx_object final {
	protected:
	icsupctx_object() = default;

	public:
	~icsupctx_object();
	static std::unique_ptr<icsupctx_object> create(folder_object *, uint8_t sync_type);
	BOOL upload_state(const BINARY *state);
	BINARY *get_state();
	store_object *get_store() const { return pstore; }
	uint8_t get_type() const { return sync_type; }
	uint64_t get_parent_folder_id() const { return folder_id; }

	store_object *pstore = nullptr;
	uint64_t folder_id = 0;
	ICS_STATE *pstate = nullptr; /* public member */
	uint8_t sync_type = 0;
};

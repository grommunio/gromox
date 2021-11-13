#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/mem_file.hpp>

struct folder_object;
struct ICS_STATE;
struct logon_object;

struct icsupctx_object final {
	protected:
	icsupctx_object() = default;
	NOMOVE(icsupctx_object);

	public:
	~icsupctx_object();
	static std::unique_ptr<icsupctx_object> create(logon_object *, folder_object *, uint8_t sync_type);
	uint8_t get_sync_type() const { return sync_type; }
	folder_object *get_parent_object() const { return pfolder; }
	BOOL begin_state_stream(uint32_t state_property);
	BOOL continue_state_stream(const BINARY *stream_data);
	BOOL end_state_stream();
	ICS_STATE *get_state() const { return pstate.get(); }
	void mark_started();

	logon_object *plogon = nullptr;
	folder_object *pfolder = nullptr;
	std::unique_ptr<ICS_STATE> pstate; /* public member */
	uint32_t state_property = 0;
	MEM_FILE f_state_stream{};
	BOOL b_started = false;
	uint8_t sync_type = 0;
};

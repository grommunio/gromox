#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mapi_types.hpp>
#include <gromox/mem_file.hpp>

struct FOLDER_OBJECT;
struct ICS_STATE;
struct LOGON_OBJECT;

struct ICSUPCTX_OBJECT final {
	protected:
	ICSUPCTX_OBJECT() = default;

	public:
	~ICSUPCTX_OBJECT();
	static std::unique_ptr<ICSUPCTX_OBJECT> create(LOGON_OBJECT *, FOLDER_OBJECT *, uint8_t sync_type);
	uint8_t get_sync_type() const { return sync_type; }
	FOLDER_OBJECT *get_parent_object() const { return pfolder; }
	BOOL begin_state_stream(uint32_t state_property);
	BOOL continue_state_stream(const BINARY *stream_data);
	BOOL end_state_stream();
	ICS_STATE *get_state() const { return pstate.get(); }
	void mark_started();

	LOGON_OBJECT *plogon = nullptr;
	FOLDER_OBJECT *pfolder = nullptr;
	std::unique_ptr<ICS_STATE> pstate; /* public member */
	uint32_t state_property = 0;
	MEM_FILE f_state_stream{};
	BOOL b_started = false;
	uint8_t sync_type = 0;
};
using icsupctx_object = ICSUPCTX_OBJECT;

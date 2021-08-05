#pragma once
#include <cstdint>
#include <memory>
#include <gromox/mem_file.hpp>
#include "ics_state.h"
#include <gromox/mapi_types.hpp>
#include "folder_object.h"
#include "ftstream_producer.h"

struct ICSDOWNCTX_OBJECT final {
	~ICSDOWNCTX_OBJECT();
	BOOL begin_state_stream(uint32_t state_property);
	BOOL continue_state_stream(const BINARY *stream_data);
	BOOL end_state_stream();
	BOOL check_started() const { return b_started; }
	BOOL make_sync();
	ICS_STATE *get_state() const { return pstate.get(); }
	BOOL get_buffer(void *buf, uint16_t *len, BOOL *last, uint16_t *progress, uint16_t *total);

	std::unique_ptr<FTSTREAM_PRODUCER> pstream;
	uint8_t sync_type = 0;
	FOLDER_OBJECT *pfolder = nullptr;
	std::unique_ptr<ICS_STATE> pstate; /* public member */
	uint32_t state_property = 0;
	MEM_FILE f_state_stream{};
	BOOL b_started = false;
	DOUBLE_LIST flow_list{}, group_list{};
	uint64_t last_readcn = 0, last_changenum = 0;
	PROGRESS_INFORMATION *pprogtotal = nullptr;
	EID_ARRAY *pmessages = nullptr, *pdeleted_messages = nullptr;
	EID_ARRAY *pnolonger_messages = nullptr, *pread_messags = nullptr;
	EID_ARRAY *punread_messags = nullptr;
	uint8_t send_options = 0;
	uint16_t sync_flags = 0;
	uint32_t extra_flags = 0;
	PROPTAG_ARRAY *pproptags = nullptr;
	RESTRICTION *prestriction = nullptr;
	uint64_t total_steps = 0, progress_steps = 0, next_progress_steps = 0;
	uint64_t ratio = 0;
	PROPERTY_GROUPINFO fake_gpinfo{};
};

extern std::unique_ptr<ICSDOWNCTX_OBJECT> icsdownctx_object_create(LOGON_OBJECT *, FOLDER_OBJECT *, uint8_t sync_type, uint8_t send_options, uint16_t sync_flags, const RESTRICTION *, uint32_t extra_flags, const PROPTAG_ARRAY *);

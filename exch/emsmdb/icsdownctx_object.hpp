#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>

struct folder_object;
struct fxstream_producer;
struct ics_state;
struct logon_object;

enum class ics_flow_func : uint8_t {
	immed32,
	progress,
	upd_msg_id,
	new_msg_id,
	deletions,
	read_state_chg,
	state,
};

using ics_flow_node = std::pair<ics_flow_func, uint64_t>;

struct ics_flow_list : public std::vector<ics_flow_node> {
	bool record_node(ics_flow_func, uint64_t = 0);
	bool record_node(ics_flow_func, const void *);
	bool record_tag(uint32_t t) { return record_node(ics_flow_func::immed32, t); }
};

struct icsdownctx_object final {
	protected:
	icsdownctx_object() = default;
	NOMOVE(icsdownctx_object);

	public:
	~icsdownctx_object();
	static std::unique_ptr<icsdownctx_object> create(logon_object *, folder_object *, uint8_t sync_type, uint8_t send_options, uint16_t sync_flags, const RESTRICTION *, uint32_t extra_flags, proptag_cspan);
	bool begin_state_stream(gromox::proptag_t state);
	BOOL continue_state_stream(const BINARY *stream_data);
	BOOL end_state_stream();
	BOOL check_started() const { return b_started; }
	BOOL make_sync();
	ics_state *get_state() const { return pstate.get(); }
	BOOL get_buffer(void *buf, uint16_t *len, BOOL *last, uint16_t *progress, uint16_t *total);

	std::unique_ptr<fxstream_producer> pstream;
	uint8_t sync_type = 0;
	folder_object *pfolder = nullptr;
	std::unique_ptr<ics_state> pstate; /* public member */
	std::string f_state_stream;
	gromox::proptag_t state_property{};
	BOOL b_started = false;
	ics_flow_list flow_list;
	uint64_t last_readcn = 0, last_changenum = 0;
	PROGRESS_INFORMATION *pprogtotal = nullptr;
	EID_ARRAY *pmessages = nullptr, *pdeleted_messages = nullptr;
	EID_ARRAY *pnolonger_messages = nullptr, *pread_messages = nullptr;
	EID_ARRAY *punread_messages = nullptr;
	uint8_t send_options = 0;
	uint16_t sync_flags = 0;
	uint32_t extra_flags = 0, divisor = 1;
	proptag_vector pproptags;
	RESTRICTION *prestriction = nullptr;
	uint64_t total_steps = 0, progress_steps = 0, next_progress_steps = 0;
};

struct icsupctx_object final {
	protected:
	icsupctx_object() = default;
	NOMOVE(icsupctx_object);

	public:
	static std::unique_ptr<icsupctx_object> create(logon_object *, folder_object *, uint8_t sync_type);
	uint8_t get_sync_type() const { return sync_type; }
	folder_object *get_parent_object() const { return pfolder; }
	BOOL begin_state_stream(uint32_t state_property);
	BOOL continue_state_stream(const BINARY *stream_data);
	BOOL end_state_stream();
	ics_state *get_state() const { return pstate.get(); }
	void mark_started() { b_started = TRUE; }

	logon_object *plogon = nullptr;
	folder_object *pfolder = nullptr;
	std::shared_ptr<ics_state> pstate; /* public member */
	std::string f_state_stream;
	uint32_t state_property = 0;
	BOOL b_started = false;
	uint8_t sync_type = 0;
};

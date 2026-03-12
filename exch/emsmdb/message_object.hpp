#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object;
struct ics_state;
struct logon_object;
struct stream_object;

struct message_object {
	protected:
	message_object() = default;
	NOMOVE(message_object)

	public:
	~message_object();
	static std::unique_ptr<message_object> create(logon_object *, BOOL b_new, cpid_t, uint64_t message_id, void *parent, uint32_t tag_access, uint8_t open_flags, std::shared_ptr<ics_state>);
	uint32_t get_instance_id() const { return instance_id; }
	ec_error_t check_original_touched() const;
	bool importing() const { return message_id != 0 && pstate != nullptr; }
	ec_error_t init_message(bool fai, cpid_t);
	eid_t get_id() const { return message_id; }
	cpid_t get_cpid() const { return cpid; }
	uint32_t get_tag_access() const { return tag_access; }
	uint8_t get_open_flags() const { return open_flags; }
	void set_open_flags(uint8_t open_flags);
	ec_error_t save();
	ec_error_t reload();
	PROPTAG_ARRAY *get_rcpt_columns() const { return precipient_columns; }
	ec_error_t read_recipients(uint32_t row_id, uint16_t need_count, TARRAY_SET *) const;
	ec_error_t get_recipient_num(uint16_t *) const;
	ec_error_t set_rcpts(const TARRAY_SET *);
	ec_error_t empty_rcpts();
	ec_error_t get_attachments_num(uint16_t *) const;
	ec_error_t delete_attachment(uint32_t attachment_num);
	ec_error_t get_attachment_table_all_proptags(PROPTAG_ARRAY *) const;
	ec_error_t query_attachment_table(proptag_cspan, uint32_t start_pos, int32_t row_needed, TARRAY_SET *) const;
	ec_error_t append_stream_object(stream_object *);
	ec_error_t commit_stream_object(stream_object *);
	ec_error_t flush_streams();
	ec_error_t clear_unsent();
	ec_error_t get_all_proptags(PROPTAG_ARRAY *) const;
	bool is_readonly_prop(gromox::proptag_t) const;
	ec_error_t get_properties(uint32_t size_limit, proptag_cspan tags, TPROPVAL_ARRAY *vals) const;
	ec_error_t set_properties(const TPROPVAL_ARRAY *vals, PROBLEM_ARRAY *);
	ec_error_t remove_properties(proptag_cspan tags, PROBLEM_ARRAY *);
	ec_error_t copy_to(message_object *src, proptag_cspan exclprop, BOOL force, BOOL *cycle, PROBLEM_ARRAY *);
	ec_error_t copy_rcpts(const message_object *src, BOOL force, BOOL *result);
	ec_error_t copy_attachments(const message_object *src, BOOL force, BOOL *result);
	ec_error_t set_readflag(uint8_t read_flag, BOOL *changed);

	logon_object *plogon = nullptr;
	BOOL b_new = false, b_touched = false;
	uint64_t change_num = 0;
	eid_t message_id{}, folder_id{};
	cpid_t cpid = CP_ACP;
	uint32_t instance_id = 0;
	uint32_t tag_access = 0;
	uint8_t open_flags = 0;
	attachment_object *pembedding = nullptr;
	std::shared_ptr<ics_state> pstate;
	PROPTAG_ARRAY *precipient_columns = nullptr;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
	std::vector<stream_object *> stream_list;
};

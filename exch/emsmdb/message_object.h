#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/double_list.hpp>
#include <gromox/mapi_types.hpp>

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object;
struct ics_state;
struct logon_object;
struct stream_object;

struct message_object {
	protected:
	message_object();
	NOMOVE(message_object)

	public:
	~message_object();
	static std::unique_ptr<message_object> create(logon_object *, BOOL b_new, uint32_t cpid, uint64_t message_id, void *parent, uint32_t tag_access, uint8_t open_flags, std::shared_ptr<ics_state>);
	uint32_t get_instance_id() const { return instance_id; }
	ec_error_t check_original_touched() const;
	bool importing() const { return message_id != 0 && pstate != nullptr; }
	gromox::errno_t init_message(bool fai, uint32_t cpid);
	uint64_t get_id() const { return message_id; }
	uint32_t get_cpid() const { return cpid; }
	uint32_t get_tag_access() const { return tag_access; }
	uint8_t get_open_flags() const { return open_flags; }
	void set_open_flags(uint8_t open_flags);
	gxerr_t save();
	BOOL reload();
	PROPTAG_ARRAY *get_rcpt_columns() const { return precipient_columns; }
	BOOL read_recipients(uint32_t row_id, uint16_t need_count, TARRAY_SET *);
	BOOL get_recipient_num(uint16_t *);
	BOOL set_rcpts(const TARRAY_SET *);
	BOOL empty_rcpts();
	BOOL get_attachments_num(uint16_t *);
	BOOL delete_attachment(uint32_t attachment_num);
	BOOL get_attachment_table_all_proptags(PROPTAG_ARRAY *);
	BOOL query_attachment_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);
	BOOL append_stream_object(stream_object *);
	BOOL commit_stream_object(stream_object *);
	BOOL flush_streams();
	BOOL clear_unsent();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	bool is_readonly_prop(uint32_t proptag) const;
	BOOL get_properties(uint32_t size_limit, const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals);
	BOOL set_properties(const TPROPVAL_ARRAY *vals, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *tags, PROBLEM_ARRAY *);
	BOOL copy_to(message_object *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle, PROBLEM_ARRAY *);
	BOOL copy_rcpts(message_object *src, BOOL force, BOOL *result);
	BOOL copy_attachments(message_object *src, BOOL force, BOOL *result);
	BOOL set_readflag(uint8_t read_flag, BOOL *changed);

	logon_object *plogon = nullptr;
	BOOL b_new = false, b_touched = false;
	uint32_t cpid = 0;
	uint64_t change_num = 0, message_id = 0, folder_id = 0;
	uint32_t instance_id = 0;
	attachment_object *pembedding = nullptr;
	uint32_t tag_access = 0;
	uint8_t open_flags = 0;
	std::shared_ptr<ics_state> pstate;
	PROPTAG_ARRAY *precipient_columns = nullptr;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
	DOUBLE_LIST stream_list{};
};

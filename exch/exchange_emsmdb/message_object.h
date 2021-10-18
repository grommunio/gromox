#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/double_list.hpp>

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */
struct ATTACHMENT_OBJECT;
struct ICS_STATE;
struct LOGON_OBJECT;
struct STREAM_OBJECT;

struct MESSAGE_OBJECT {
	protected:
	MESSAGE_OBJECT() = default;

	public:
	~MESSAGE_OBJECT();
	static std::unique_ptr<MESSAGE_OBJECT> create(LOGON_OBJECT *, BOOL b_new, uint32_t cpid, uint64_t message_id, void *parent, uint32_t tag_access, uint8_t open_flags, ICS_STATE *);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL check_orignal_touched(BOOL *touched);
	BOOL check_importing() const;
	BOOL init_message(BOOL fai, uint32_t cpid);
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
	BOOL append_stream_object(STREAM_OBJECT *);
	BOOL commit_stream_object(STREAM_OBJECT *);
	BOOL flush_streams();
	BOOL clear_unsent();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL check_readonly_property(uint32_t proptag) const;
	BOOL get_properties(uint32_t size_limit, const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals);
	BOOL set_properties(const TPROPVAL_ARRAY *vals, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *tags, PROBLEM_ARRAY *);
	BOOL copy_to(MESSAGE_OBJECT *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle, PROBLEM_ARRAY *);
	BOOL copy_rcpts(MESSAGE_OBJECT *src, BOOL force, BOOL *result);
	BOOL copy_attachments(MESSAGE_OBJECT *src, BOOL force, BOOL *result);
	BOOL set_readflag(uint8_t read_flag, BOOL *changed);

	LOGON_OBJECT *plogon = nullptr;
	BOOL b_new = false, b_touched = false;
	uint32_t cpid = 0;
	uint64_t change_num = 0, message_id = 0, folder_id = 0;
	uint32_t instance_id = 0;
	ATTACHMENT_OBJECT *pembedding = nullptr;
	uint32_t tag_access = 0;
	uint8_t open_flags = 0;
	ICS_STATE *pstate = nullptr;
	PROPTAG_ARRAY *precipient_columns = nullptr;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
	DOUBLE_LIST stream_list{};
};
using message_object = MESSAGE_OBJECT;

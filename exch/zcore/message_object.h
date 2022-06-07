#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object;
struct ics_state;
struct MESSAGE_CONTENT;
struct store_object;

struct message_object {
	protected:
	message_object() = default;
	NOMOVE(message_object);

	public:
	~message_object();
	static std::unique_ptr<message_object> create(store_object *, BOOL b_new, uint32_t cpid, uint64_t message_id, void *parent, uint32_t tag_access, BOOL b_writable, std::shared_ptr<ics_state>);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL check_original_touched(BOOL *touched);
	BOOL check_importing() const { return message_id != 0 && pstate != nullptr ? TRUE : false; }
	BOOL check_writable() const { return b_writable; }
	BOOL init_message(bool fai, uint32_t cpid);
	uint64_t get_id() const { return message_id; }
	store_object *get_store() const { return pstore; }
	gxerr_t save();
	BOOL reload();
	BOOL write_message(const MESSAGE_CONTENT *);
	BOOL get_recipient_all_proptags(PROPTAG_ARRAY *);
	BOOL read_recipients(uint32_t row_id, uint16_t need_count, TARRAY_SET *);
	BOOL get_rowid_begin(uint32_t *begin_id);
	BOOL get_recipient_num(uint16_t *);
	BOOL set_rcpts(const TARRAY_SET *);
	BOOL empty_rcpts();
	BOOL get_attachments_num(uint16_t *);
	BOOL delete_attachment(uint32_t attachment_num);
	BOOL get_attachment_table_all_proptags(PROPTAG_ARRAY *);
	BOOL query_attachment_table(const PROPTAG_ARRAY *, uint32_t start_pos, int32_t row_needed, TARRAY_SET *);
	BOOL clear_unsent();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_to(message_object *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	BOOL set_readflag(uint8_t read_flag, BOOL *changed);

	store_object *pstore = nullptr;
	BOOL b_new = false, b_writable = false, b_touched = false;
	uint32_t cpid = 0;
	uint64_t change_num = 0, message_id = 0, folder_id = 0;
	uint32_t instance_id = 0;
	attachment_object *pembedding = nullptr;
	uint32_t tag_access = 0;
	std::shared_ptr<ics_state> pstate;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
};

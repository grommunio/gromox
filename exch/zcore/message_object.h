#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */
struct ATTACHMENT_OBJECT;
struct ICS_STATE;
struct MESSAGE_CONTENT;
struct STORE_OBJECT;

struct MESSAGE_OBJECT {
	~MESSAGE_OBJECT();
	uint32_t get_instance_id() const { return instance_id; }
	BOOL check_orignal_touched(BOOL *touched);
	BOOL check_importing() const { return message_id != 0 && pstate != nullptr ? TRUE : false; }
	BOOL check_writable() const { return b_writable; }
	BOOL init_message(BOOL fai, uint32_t cpid);
	uint64_t get_id() const { return message_id; }
	STORE_OBJECT *get_store() const { return pstore; }
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
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_to(MESSAGE_OBJECT *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	BOOL set_readflag(uint8_t read_flag, BOOL *changed);

	STORE_OBJECT *pstore = nullptr;
	BOOL b_new = false, b_writable = false, b_touched = false;
	uint32_t cpid = 0;
	uint64_t change_num = 0, message_id = 0, folder_id = 0;
	uint32_t instance_id = 0;
	ATTACHMENT_OBJECT *pembedding = nullptr;
	uint32_t tag_access = 0;
	ICS_STATE *pstate = nullptr;
	PROPTAG_ARRAY *pchanged_proptags = nullptr, *premoved_proptags = nullptr;
};

extern std::unique_ptr<MESSAGE_OBJECT> message_object_create(STORE_OBJECT *, BOOL b_new, uint32_t cpid, uint64_t message_id, void *parent, uint32_t tag_access, BOOL b_writable, ICS_STATE *);

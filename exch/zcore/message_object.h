#pragma once
#include <cstdint>
#include <gromox/defs.h>
#include "ics_state.h"
#include <gromox/mapi_types.hpp>
#include "store_object.h"

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */
struct ATTACHMENT_OBJECT;

struct MESSAGE_OBJECT {
	STORE_OBJECT *pstore;
	BOOL b_new;
	BOOL b_writable;
	BOOL b_touched;
	uint32_t cpid;
	uint64_t change_num;
	uint64_t message_id;
	uint64_t folder_id;
	uint32_t instance_id;
	ATTACHMENT_OBJECT *pembedding;
	uint32_t tag_access;
	ICS_STATE *pstate;
	PROPTAG_ARRAY *pchanged_proptags;
	PROPTAG_ARRAY *premoved_proptags;
};

MESSAGE_OBJECT* message_object_create(STORE_OBJECT *pstore,
	BOOL b_new, uint32_t cpid, uint64_t message_id,
	void *pparent, uint32_t tag_access, BOOL b_writable,
	ICS_STATE *pstate);
uint32_t message_object_get_instance_id(MESSAGE_OBJECT *pmessage);
BOOL message_object_check_orignal_touched(
	MESSAGE_OBJECT *pmessage, BOOL *pb_touched);
BOOL message_object_check_importing(MESSAGE_OBJECT *pmessage);
BOOL message_object_check_writable(MESSAGE_OBJECT *pmessage);
BOOL message_object_init_message(MESSAGE_OBJECT *pmessage,
	BOOL b_fai, uint32_t cpid);
uint64_t message_object_get_id(MESSAGE_OBJECT *pmessage);
STORE_OBJECT* message_object_get_store(MESSAGE_OBJECT *pmessage);
void message_object_free(MESSAGE_OBJECT *pmessage);
extern gxerr_t message_object_save(MESSAGE_OBJECT *);
BOOL message_object_reload(MESSAGE_OBJECT *pmessage);
BOOL message_object_write_message(MESSAGE_OBJECT *pmessage,
	const MESSAGE_CONTENT *pmsgctnt);
BOOL message_object_get_recipient_all_proptags(
	MESSAGE_OBJECT *pmessage, PROPTAG_ARRAY *pproptags);
BOOL message_object_read_recipients(MESSAGE_OBJECT *pmessage,
	uint32_t row_id, uint16_t need_count, TARRAY_SET *pset);
BOOL message_object_get_rowid_begin(
	MESSAGE_OBJECT *pmessage, uint32_t *pbegin_id);
BOOL message_object_get_recipient_num(
	MESSAGE_OBJECT *pmessage, uint16_t *pnum);
BOOL message_object_set_rcpts(MESSAGE_OBJECT *pmessage,
	const TARRAY_SET *pset);
BOOL message_object_empty_rcpts(MESSAGE_OBJECT *pmessage);
BOOL message_object_get_attachments_num(
	MESSAGE_OBJECT *pmessage, uint16_t *pnum);
BOOL message_object_delele_attachment(MESSAGE_OBJECT *pmessage,
	uint32_t attachment_num);
BOOL message_object_get_attachment_table_all_proptags(
	MESSAGE_OBJECT *pmessage, PROPTAG_ARRAY *pproptags);
BOOL message_object_query_attachment_table(
	MESSAGE_OBJECT *pmessage, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset);
BOOL message_object_clear_unsent(MESSAGE_OBJECT *pmessage);
BOOL message_object_get_all_proptags(MESSAGE_OBJECT *pmessage,
	PROPTAG_ARRAY *pproptags);
BOOL message_object_get_properties(MESSAGE_OBJECT *pmessage,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);
BOOL message_object_set_properties(MESSAGE_OBJECT *pmessage,
	const TPROPVAL_ARRAY *ppropvals);
BOOL message_object_remove_properties(MESSAGE_OBJECT *pmessage,
	const PROPTAG_ARRAY *pproptags);
BOOL message_object_copy_to(
	MESSAGE_OBJECT *pmessage, MESSAGE_OBJECT *pmessage_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force,
	BOOL *pb_cycle);
BOOL message_object_set_readflag(MESSAGE_OBJECT *pmessage,
	uint8_t read_flag, BOOL *pb_changed);

#pragma once
#include <gromox/defs.h>
#include "ics_state.h"
#include <gromox/mapi_types.hpp>
#include <gromox/double_list.hpp>
#include "logon_object.h"
#include "stream_object.h"

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */

struct ATTACHMENT_OBJECT;

struct MESSAGE_OBJECT {
	LOGON_OBJECT *plogon;
	BOOL b_new;
	BOOL b_touched;
	uint32_t cpid;
	uint64_t change_num;
	uint64_t message_id;
	uint64_t folder_id;
	uint32_t instance_id;
	ATTACHMENT_OBJECT *pembedding;
	uint32_t tag_access;
	uint8_t open_flags;
	ICS_STATE *pstate;
	PROPTAG_ARRAY *precipient_columns;
	PROPTAG_ARRAY *pchanged_proptags;
	PROPTAG_ARRAY *premoved_proptags;
	DOUBLE_LIST stream_list;
};

#ifdef __cplusplus
extern "C" {
#endif

MESSAGE_OBJECT* message_object_create(LOGON_OBJECT *plogon,
	BOOL b_new, uint32_t cpid, uint64_t message_id, void *pparent,
	uint32_t tag_access, uint8_t open_flags, ICS_STATE *pstate);

uint32_t message_object_get_instance_id(MESSAGE_OBJECT *pmessage);

BOOL message_object_check_orignal_touched(
	MESSAGE_OBJECT *pmessage, BOOL *pb_touched);

BOOL message_object_check_importing(MESSAGE_OBJECT *pmessage);

BOOL message_object_init_message(MESSAGE_OBJECT *pmessage,
	BOOL b_fai, uint32_t cpid);

uint64_t message_object_get_id(MESSAGE_OBJECT *pmessage);

uint32_t message_object_get_cpid(MESSAGE_OBJECT *pmessage);

uint32_t message_object_get_tag_access(MESSAGE_OBJECT *pmessage);

uint8_t message_object_get_open_flags(MESSAGE_OBJECT *pmessage);

void message_object_set_open_flags(
	MESSAGE_OBJECT *pmessage, uint8_t open_flags);

void message_object_free(MESSAGE_OBJECT *pmessage);
extern gxerr_t message_object_save(MESSAGE_OBJECT *);
BOOL message_object_reload(MESSAGE_OBJECT *pmessage);

PROPTAG_ARRAY* message_object_get_rcpt_columns(MESSAGE_OBJECT *pmessage);

BOOL message_object_read_recipients(MESSAGE_OBJECT *pmessage,
	uint32_t row_id, uint16_t need_count, TARRAY_SET *pset);

BOOL message_object_get_recipient_num(
	MESSAGE_OBJECT *pmessage, uint16_t *pnum);

BOOL message_object_set_rcpts(MESSAGE_OBJECT *pmessage, TARRAY_SET *pset);
	
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

BOOL message_object_append_stream_object(
	MESSAGE_OBJECT *pmessage, STREAM_OBJECT *pstream);

BOOL message_object_commit_stream_object(
	MESSAGE_OBJECT *pmessage, STREAM_OBJECT *pstream);

BOOL message_object_flush_streams(MESSAGE_OBJECT *pmessage);

BOOL message_object_clear_unsent(MESSAGE_OBJECT *pmessage);

BOOL message_object_get_all_proptags(MESSAGE_OBJECT *pmessage,
	PROPTAG_ARRAY *pproptags);

BOOL message_object_check_readonly_property(
	MESSAGE_OBJECT *pmessage, uint32_t proptag);

BOOL message_object_get_properties(MESSAGE_OBJECT *pmessage,
	uint32_t size_limit, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals);

BOOL message_object_set_properties(MESSAGE_OBJECT *pmessage,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems);

BOOL message_object_remove_properties(MESSAGE_OBJECT *pmessage,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems);

BOOL message_object_copy_to(
	MESSAGE_OBJECT *pmessage, MESSAGE_OBJECT *pmessage_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force,
	BOOL *pb_cycle, PROBLEM_ARRAY *pproblems);

BOOL message_object_copy_rcpts(MESSAGE_OBJECT *pmessage,
	MESSAGE_OBJECT *pmessage_src, BOOL b_force, BOOL *pb_result);
	
BOOL message_object_copy_attachments(MESSAGE_OBJECT *pmessage,
	MESSAGE_OBJECT *pmessage_src, BOOL b_force, BOOL *pb_result);

BOOL message_object_set_readflag(MESSAGE_OBJECT *pmessage,
	uint8_t read_flag, BOOL *pb_changed);

#ifdef __cplusplus
} /* extern "C" */
#endif

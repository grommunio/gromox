#pragma once
#include <gromox/defs.h>
#include "message_object.h"

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */
struct ATTACHMENT_OBJECT {
	~ATTACHMENT_OBJECT();

	BOOL b_new = false, b_writable = false, b_touched = false;
	MESSAGE_OBJECT *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
};

extern std::unique_ptr<ATTACHMENT_OBJECT> attachment_object_create(MESSAGE_OBJECT *parent, uint32_t at_num);
uint32_t attachment_object_get_instance_id(
	ATTACHMENT_OBJECT *pattachment);
BOOL attachment_object_init_attachment(ATTACHMENT_OBJECT *pattachment);
uint32_t attachment_object_get_attachment_num(
	ATTACHMENT_OBJECT *pattachment);
uint32_t attachment_object_get_tag_access(ATTACHMENT_OBJECT *pattachment);
extern gxerr_t attachment_object_save(ATTACHMENT_OBJECT *);
BOOL attachment_object_get_all_proptags(
	ATTACHMENT_OBJECT *pattachment, PROPTAG_ARRAY *pproptags);
BOOL attachment_object_get_properties(ATTACHMENT_OBJECT *pattachment,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);
BOOL attachment_object_set_properties(ATTACHMENT_OBJECT *pattachment,
	const TPROPVAL_ARRAY *ppropvals);
BOOL attachment_object_remove_properties(ATTACHMENT_OBJECT *pattachment,
	const PROPTAG_ARRAY *pproptags);
BOOL attachment_object_copy_properties(
	ATTACHMENT_OBJECT *pattachment, ATTACHMENT_OBJECT *pattachment_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force, BOOL *pb_cycle);
STORE_OBJECT* attachment_object_get_store(ATTACHMENT_OBJECT *pattachment);
BOOL attachment_object_check_writable(ATTACHMENT_OBJECT *pattachment);

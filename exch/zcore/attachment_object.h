#pragma once
#include <gromox/defs.h>
#include "message_object.h"

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */


struct ATTACHMENT_OBJECT {
	BOOL b_new;
	BOOL b_writable;
	BOOL b_touched;
	MESSAGE_OBJECT *pparent;
	uint32_t instance_id;
	uint32_t attachment_num;
};

ATTACHMENT_OBJECT* attachment_object_create(
	MESSAGE_OBJECT *pparent, uint32_t attachment_num);

uint32_t attachment_object_get_instance_id(
	ATTACHMENT_OBJECT *pattachment);

BOOL attachment_object_init_attachment(ATTACHMENT_OBJECT *pattachment);

void attachment_object_free(ATTACHMENT_OBJECT *pattachment);

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

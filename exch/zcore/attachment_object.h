#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include "message_object.h"

/* MESSAGE_OBJECT and ATTACHMENT_OBJECT are friend classes,
	so they can operate internal variables of each other */
struct ATTACHMENT_OBJECT {
	~ATTACHMENT_OBJECT();
	uint32_t get_instance_id() const { return instance_id; }
	BOOL init_attachment();
	uint32_t get_attachment_num() const { return attachment_num; }
	uint32_t get_tag_access() const { return pparent->tag_access; }
	gxerr_t save();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_properties(ATTACHMENT_OBJECT *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	STORE_OBJECT *get_store() const { return pparent->pstore; }
	BOOL check_writable() const { return b_writable; }

	BOOL b_new = false, b_writable = false, b_touched = false;
	MESSAGE_OBJECT *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
};

extern std::unique_ptr<ATTACHMENT_OBJECT> attachment_object_create(MESSAGE_OBJECT *parent, uint32_t at_num);

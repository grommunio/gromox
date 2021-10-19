#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include "message_object.h"

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object {
	protected:
	attachment_object() = default;

	public:
	~attachment_object();
	static std::unique_ptr<attachment_object> create(message_object *parent, uint32_t at_num);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL init_attachment();
	uint32_t get_attachment_num() const { return attachment_num; }
	uint32_t get_tag_access() const { return pparent->tag_access; }
	gxerr_t save();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	BOOL get_properties(const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *);
	BOOL copy_properties(attachment_object *src, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle);
	store_object *get_store() const { return pparent->pstore; }
	BOOL check_writable() const { return b_writable; }

	BOOL b_new = false, b_writable = false, b_touched = false;
	message_object *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
};

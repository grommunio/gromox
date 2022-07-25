#pragma once
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapi_types.hpp>
#include "message_object.h"

struct stream_object;

/* message_object and attachment_object are friend classes,
	so they can operate internal variables of each other */
struct attachment_object {
	protected:
	attachment_object() = default;
	NOMOVE(attachment_object);

	public:
	~attachment_object();
	static std::unique_ptr<attachment_object> create(message_object *parent, uint32_t at_num, uint8_t open_flags);
	uint32_t get_instance_id() const { return instance_id; }
	BOOL init_attachment();
	uint32_t get_attachment_num() const { return attachment_num; }
	uint32_t get_tag_access() const { return pparent->tag_access; }
	uint8_t get_open_flags() const { return open_flags; }
	void set_open_flags(uint8_t open_flags);
	uint32_t get_cpid() const { return pparent->cpid; }
	gxerr_t save();
	BOOL append_stream_object(stream_object *);
	BOOL commit_stream_object(stream_object *);
	BOOL flush_streams();
	BOOL get_all_proptags(PROPTAG_ARRAY *);
	bool is_readonly_prop(uint32_t proptag) const;
	BOOL get_properties(uint32_t size_limit, const PROPTAG_ARRAY *, TPROPVAL_ARRAY *);
	BOOL set_properties(const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
	BOOL remove_properties(const PROPTAG_ARRAY *, PROBLEM_ARRAY *);
	BOOL copy_properties(attachment_object *atsrc, const PROPTAG_ARRAY *exclprop, BOOL force, BOOL *cycle, PROBLEM_ARRAY *);

	BOOL b_new = false, b_touched = false;
	message_object *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
	uint8_t open_flags = 0;
	DOUBLE_LIST stream_list{};
};

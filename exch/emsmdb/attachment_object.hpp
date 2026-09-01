#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/mapi_types.hpp>
#include <gromox/mapierr.hpp>
#include "message_object.hpp"

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
	ec_error_t init_attachment();
	uint32_t get_attachment_num() const { return attachment_num; }
	uint32_t get_tag_access() const { return pparent->tag_access; }
	uint8_t get_open_flags() const { return open_flags; }
	void set_open_flags(uint8_t open_flags);
	cpid_t get_cpid() const { return pparent->cpid; }
	ec_error_t save();
	ec_error_t append_stream_obj(stream_object *);
	ec_error_t commit_stream_obj(stream_object *);
	ec_error_t flush_streams();
	ec_error_t get_all_proptags(PROPTAG_ARRAY *) const;
	bool is_readonly_prop(gromox::proptag_t) const;
	ec_error_t get_props(uint32_t size_limit, proptag_cspan, TPROPVAL_ARRAY *) const;
	ec_error_t set_props(const TPROPVAL_ARRAY *, PROBLEM_ARRAY *);
	ec_error_t remove_props(proptag_cspan, PROBLEM_ARRAY *);
	ec_error_t copy_props(attachment_object *atsrc, proptag_cspan exclprop, BOOL force, BOOL *cycle, PROBLEM_ARRAY *);

	BOOL b_new = false, b_touched = false;
	message_object *pparent = nullptr;
	uint32_t instance_id = 0, attachment_num = 0;
	uint8_t open_flags = 0;
	std::vector<stream_object *> stream_list;
};

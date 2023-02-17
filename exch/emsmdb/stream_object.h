#pragma once
#include <cstdint>
#include <memory>
#include <utility>
#include <gromox/mapi_types.hpp>
#include "rop_processor.h"
#define MAX_LENGTH_FOR_FOLDER						64*1024

struct stream_object {
	protected:
	stream_object() = default;
	NOMOVE(stream_object)

	public:
	~stream_object();
	static std::unique_ptr<stream_object> create(void *parent, ems_objtype, uint32_t open_flags, uint32_t proptag, uint32_t max_length);
	BOOL check() const { return content_bin.pb != nullptr ? TRUE : false; }
	uint32_t get_max_length() const { return max_length; }
	uint32_t read(void *buf, uint32_t len);
	std::pair<uint16_t, ec_error_t> write(void *buf, uint16_t len);
	uint8_t get_open_flags() const { return open_flags; }
	ems_objtype get_parent_type() const { return object_type; }
	uint32_t get_proptag() const { return proptag; }
	void* get_content();
	uint32_t get_length() const { return content_bin.cb; }
	ec_error_t set_length(uint32_t len);
	ec_error_t seek(uint8_t opt, int64_t offset);
	uint32_t get_seek_position() const { return seek_ptr; }
	BOOL copy(stream_object *src, uint32_t *len);
	BOOL commit();

	void *pparent = nullptr;
	ems_objtype object_type = 0;
	uint8_t open_flags = 0;
	uint32_t proptag = 0, seek_ptr = 0;
	BINARY content_bin{};
	BOOL b_touched = false;
	uint32_t max_length = 0;
};

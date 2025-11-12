#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>

struct logon_object;

struct LOGMAP;
struct table_object {
	protected:
	struct bookmark_node {
		uint32_t index = 0, row_type = 0, inst_num = 0, position = 0;
		uint64_t inst_id = 0;
	};

	table_object() = default;
	NOMOVE(table_object)

	public:
	~table_object();
	static std::unique_ptr<table_object> create(logon_object *, void *parent, uint8_t table_flags, uint8_t rop_id, uint8_t logon_id);
	const proptag_vector *get_columns() const { return m_colset ? &m_columns : nullptr; }
	bool set_columns(proptag_cspan);
	const SORTORDER_SET *get_sorts() const { return m_sorts; }
	BOOL set_sorts(const SORTORDER_SET *);
	bool is_loaded() const { return rop_id == ropGetAttachmentTable || m_loaded; }
	BOOL load();
	void unload();
	BOOL query_rows(BOOL forward, uint16_t row_count, TARRAY_SET *);
	BOOL set_restriction(const RESTRICTION *);
	void seek_current(BOOL forward, uint16_t row_count);
	void set_handle(uint32_t h) { handle = h; }
	uint32_t get_position() const { return m_position; }
	void set_position(uint32_t position);
	void clear_position() { m_position = 0; }
	uint32_t get_total();
	BOOL create_bookmark(uint32_t *pindex);
	void remove_bookmark(uint32_t index);
	void clear_bookmarks() { bookmark_list.clear(); }
	BOOL retrieve_bookmark(uint32_t index, BOOL *exist);
	void reset();
	BOOL get_all_columns(PROPTAG_ARRAY *cols) const;
	BOOL match_row(BOOL forward, const RESTRICTION *, int32_t *pposition, TPROPVAL_ARRAY *) const;
	BOOL read_row(uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *) const;
	BOOL expand(uint64_t inst_id, BOOL *found, int32_t *pos, uint32_t *row_count) const;
	BOOL collapse(uint64_t inst_id, BOOL *found, int32_t *pos, uint32_t *row_count) const;
	BOOL store_state(uint64_t inst_id, uint32_t inst_num, uint32_t *state_id) const;
	BOOL restore_state(uint32_t state_id, uint32_t *index);

	logon_object *plogon = nullptr;
	CXH cxh{};
	LOGMAP *plogmap = nullptr;
	void *pparent_obj = nullptr;
	uint8_t logon_id = 0, rop_id = 0, table_flags = 0;
	bool m_loaded = false, m_colset = false;
	proptag_vector m_columns;
	SORTORDER_SET *m_sorts = nullptr;
	RESTRICTION *m_restriction = nullptr;
	uint32_t m_position = 0;
	uint32_t handle = 0, m_table_id = 0, bookmark_index = 0;
	std::vector<bookmark_node> bookmark_list;
};

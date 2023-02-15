#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <gromox/mapi_types.hpp>

enum class zcore_tbltype {
	invalid = 0,
	store = 1,       /* pparent_obj is a nullptr */
	hierarchy = 2,   /* pparent_obj is a folder_object */
	content = 3,     /* pparent_obj is a folder_object */
	rule = 4,        /* pparent_obj is a uint64_t */
	attachment = 5,  /* pparent_obj is a message_object */
	recipient = 6,   /* pparent_obj is a message_object */
	container = 7,   /* pparent_obj is a container_object */
	abcontusr = 8,   /* pparent_obj is a container_object */
};

struct store_object;

struct bookmark_node {
	uint32_t index = 0, row_type = 0, inst_num = 0, position = 0;
	uint64_t inst_id = 0;
};

/**
 * @fixed_data:		in case @pparent_obj (i.e. the provider of table data)
 *  			is nullptr, data can be statically placed in fixed_data.
 */
struct table_object {
	protected:
	table_object() = default;
	NOMOVE(table_object);

	public:
	~table_object();
	static std::unique_ptr<table_object> create(store_object *, void *parent, zcore_tbltype, uint32_t table_flags);
	const PROPTAG_ARRAY *get_columns() const { return pcolumns; }
	BOOL set_columns(const PROPTAG_ARRAY *);
	BOOL set_sorts(const SORTORDER_SET *);
	BOOL load();
	void unload();
	BOOL query_rows(const PROPTAG_ARRAY *cols, uint32_t row_count, TARRAY_SET *);
	BOOL set_restriction(const RESTRICTION *);
	void seek_current(BOOL forward, uint32_t row_count);
	uint32_t get_position() const { return position; }
	void set_position(uint32_t pos);
	void clear_position() { position = 0; }
	uint32_t get_total();
	BOOL create_bookmark(uint32_t *index);
	void remove_bookmark(uint32_t index);
	void clear_bookmarks() { bookmark_list.clear(); }
	BOOL retrieve_bookmark(uint32_t index, BOOL *exist);
	BOOL filter_rows(uint32_t count, const RESTRICTION *, const PROPTAG_ARRAY *cols, TARRAY_SET *);
	BOOL match_row(BOOL forward, const RESTRICTION *, int32_t *pos);

	store_object *pstore = nullptr;
	uint32_t handle = 0;
	void *pparent_obj = nullptr;
	zcore_tbltype table_type{};
	uint32_t table_flags = 0;
	tarray_set *fixed_data = nullptr;
	PROPTAG_ARRAY *pcolumns = nullptr;
	SORTORDER_SET *psorts = nullptr;
	RESTRICTION *prestriction = nullptr;
	uint32_t position = 0, table_id = 0, bookmark_index = 0;
	std::vector<bookmark_node> bookmark_list;
};

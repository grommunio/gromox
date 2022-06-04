#pragma once
#include <gromox/double_list.hpp>
#include <gromox/mem_file.hpp>
#include <gromox/single_list.hpp>
#include <gromox/util.hpp>
#define XARRAY_CACHEITEM_NUMBER  (16*1024)
#define XARRAY_HASHITEM_NUMBER   (4*1024)

struct MITEM {
	SINGLE_LIST_NODE node;
	char mid[128];
	int id;
	int uid;
	char flag_bits;
	MEM_FILE f_digest;
};

struct XARRAY_UNIT {
	DOUBLE_LIST_NODE    node;
	DOUBLE_LIST_NODE    node_hash;
	int                 index;
	unsigned int        xtag;

	struct MITEM mitem;
};

struct GX_EXPORT XARRAY {
	XARRAY(alloc_limiter<XARRAY_UNIT> *);
	~XARRAY();
	int append(MITEM *data, unsigned int xtag);
	MITEM *get_item(size_t index) const;
	MITEM *get_itemx(unsigned int xtag) const;
	inline size_t get_capacity() const { return cur_size; }
	void clear();

	alloc_limiter<XARRAY_UNIT> *mbuf_pool = nullptr;
	DOUBLE_LIST mlist{};
	size_t data_size = 0, cur_size = 0;
	MITEM *cache_ptrs[XARRAY_CACHEITEM_NUMBER]{};
	DOUBLE_LIST hash_lists[XARRAY_HASHITEM_NUMBER]{};
};

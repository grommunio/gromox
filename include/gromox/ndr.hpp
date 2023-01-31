#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/rpc_types.hpp>

enum {
	NDR_ERR_SUCCESS = EXT_ERR_SUCCESS,
	NDR_ERR_FAILURE = EXT_ERR_FAILURE,
	NDR_ERR_CHARCNV = EXT_ERR_CHARCNV,
	NDR_ERR_BUFSIZE = EXT_ERR_BUFSIZE,
	NDR_ERR_ALLOC = EXT_ERR_ALLOC,
	NDR_ERR_NDR64 = EXT_ERR_NDR64,
	NDR_ERR_PADDING = EXT_ERR_PADDING,
	NDR_ERR_RANGE = EXT_ERR_RANGE,
	NDR_ERR_ARRAY_SIZE = EXT_ERR_ARRAY_SIZE,
	NDR_ERR_BAD_SWITCH = EXT_ERR_BAD_SWITCH,
	NDR_ERR_IPV6ADDRESS = EXT_ERR_IPV6ADDRESS,
};

#define NDR_FLAG_BIGENDIAN				(1<<0)
#define NDR_FLAG_NOALIGN				(1<<1)
/* set if relative pointers should *not* be marshalled in reverse order */
#define NDR_FLAG_NO_RELATIVE_REVERSE	(1<<2)
/* set if relative pointers are marshalled in reverse order */
#define NDR_FLAG_RELATIVE_REVERSE		(1<<3)
#define NDR_FLAG_REMAINING				(1<<4)
#define NDR_FLAG_ALIGN2					(1<<5)
#define NDR_FLAG_ALIGN4					(1<<6)
#define NDR_FLAG_ALIGN8					(1<<7)
/* used to check if alignment padding is zero */
#define NDR_FLAG_PAD_CHECK				(1<<8)
#define NDR_FLAG_NDR64					(1<<9)
/* set if an object uuid will be present */
#define NDR_FLAG_OBJECT_PRESENT			(1<<10)

#define NDR_ALIGN_FLAGS (NDR_FLAG_NOALIGN|NDR_FLAG_REMAINING|NDR_FLAG_ALIGN2|NDR_FLAG_ALIGN4|NDR_FLAG_ALIGN8)

struct NDR_PULL;
struct NDR_PUSH;

void ndr_set_flags(uint32_t *pflags, uint32_t new_flags);
void ndr_free_data_blob(DATA_BLOB *pblob);

struct GX_EXPORT NDR_PULL {
	void init(const void *d, uint32_t z, uint32_t f);
	uint32_t get_ptrcnt() const { return ptr_count; }
	int advance(uint32_t);
	int align(size_t);
	int union_align(size_t);
	int trailer_align(size_t);
	int g_str(char *v, uint32_t z);
	int g_uint8(uint8_t *);
	int g_uint16(uint16_t *);
	int g_int32(int32_t *);
	int g_uint32(uint32_t *);
	int g_uint64(uint64_t *);
	int g_ulong(uint32_t *);
	int g_uint8_a(uint8_t *v, uint32_t z);
	int g_guid(GUID *);
	int g_syntax(SYNTAX_ID *);
	int g_blob(DATA_BLOB *);
	int check_str(uint32_t c, uint32_t z);
	int g_genptr(uint32_t *v);
	int g_ctx_handle(CONTEXT_HANDLE *);

	const uint8_t *data = nullptr;
	uint32_t flags = 0, data_size = 0, offset = 0, ptr_count = 0;
};

struct GX_EXPORT NDR_PUSH {
	void init(void *d, uint32_t asize, uint32_t fl);
	void set_ptrcnt(uint32_t c) { ptr_count = c; }
	void destroy();
	int align(size_t);
	int union_align(size_t);
	int trailer_align(size_t);
	int p_str(const char *v, uint32_t req);
	int p_uint8(uint8_t);
	int p_uint16(uint16_t);
	int p_uint32(uint32_t);
	int p_int32(int32_t v) { return p_uint32(v); }
	int p_uint64(uint64_t);
	int p_ulong(uint32_t);
	int p_uint8_a(const uint8_t *v, uint32_t z);
	int p_guid(const GUID &);
	int p_syntax(const SYNTAX_ID &);
	int p_blob(DATA_BLOB);
	int p_zero(uint32_t z);
	int p_unique_ptr(const void *v);
	int p_ctx_handle(const CONTEXT_HANDLE &);

	uint8_t *data = nullptr;
	uint32_t flags = 0, alloc_size = 0, offset = 0, ptr_count = 0;
	DOUBLE_LIST full_ptr_list{};
};

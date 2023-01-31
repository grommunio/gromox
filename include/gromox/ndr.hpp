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
extern GX_EXPORT uint32_t ndr_pull_get_ptrcnt(const NDR_PULL *);
extern GX_EXPORT void ndr_pull_init(NDR_PULL *, const void *, uint32_t size, uint32_t flags);
int ndr_pull_advance(NDR_PULL *pndr, uint32_t size);
int ndr_pull_align(NDR_PULL *pndr, size_t size);
int ndr_pull_union_align(NDR_PULL *pndr, size_t size);
int ndr_pull_trailer_align(NDR_PULL *pndr, size_t size);
int ndr_pull_string(NDR_PULL *pndr, char *buff, uint32_t inbytes);
int ndr_pull_uint8(NDR_PULL *pndr, uint8_t *v);
int ndr_pull_uint16(NDR_PULL *pndr, uint16_t *v);
int ndr_pull_int32(NDR_PULL *pndr, int32_t *v);
int ndr_pull_uint32(NDR_PULL *pndr, uint32_t *v);
int ndr_pull_uint64(NDR_PULL *pndr, uint64_t *v);
int ndr_pull_ulong(NDR_PULL *pndr, uint32_t *v);
int ndr_pull_array_uint8(NDR_PULL *pndr, uint8_t *data, uint32_t n);
int ndr_pull_guid(NDR_PULL *pndr, GUID *r);
int ndr_pull_syntax_id(NDR_PULL *pndr, SYNTAX_ID *r);
int ndr_pull_data_blob(NDR_PULL *pndr, DATA_BLOB *pblob);
void ndr_free_data_blob(DATA_BLOB *pblob);
int ndr_pull_check_string(NDR_PULL *pndr,
	uint32_t count, uint32_t element_size);
int ndr_pull_generic_ptr(NDR_PULL *pndr, uint32_t *v);
int ndr_pull_context_handle(NDR_PULL *pndr, CONTEXT_HANDLE *r);

struct GX_EXPORT NDR_PULL {
	void init(const void *d, uint32_t z, uint32_t f) { return ndr_pull_init(this, d, z, f); }
	uint32_t get_ptrcnt() const { return ptr_count; }
	int advance(uint32_t z) { return ndr_pull_advance(this, z); }
	int align(size_t z) { return ndr_pull_align(this, z); }
	int union_align(size_t z) { return ndr_pull_union_align(this, z); }
	int trailer_align(size_t z) { return ndr_pull_trailer_align(this, z); }
	int g_str(char *v, uint32_t z) { return ndr_pull_string(this, v, z); }
	int g_uint8(uint8_t *v) { return ndr_pull_uint8(this, v); }
	int g_uint16(uint16_t *v) { return ndr_pull_uint16(this, v); }
	int g_int32(int32_t *v) { return g_uint32(reinterpret_cast<uint32_t *>(v)); }
	int g_uint32(uint32_t *v) { return ndr_pull_uint32(this, v); }
	int g_uint64(uint64_t *v) { return ndr_pull_uint64(this, v); }
	int g_ulong(uint32_t *v) { return ndr_pull_ulong(this, v); }
	int g_uint8_a(uint8_t *v, uint32_t n) { return ndr_pull_array_uint8(this, v, n); }
	int g_guid(GUID *v) { return ndr_pull_guid(this, v); }
	int g_syntax(SYNTAX_ID *v) { return ndr_pull_syntax_id(this, v); }
	int g_blob(DATA_BLOB *v) { return ndr_pull_data_blob(this, v); }
	int check_str(uint32_t c, uint32_t z) { return ndr_pull_check_string(this, c, z); }
	int g_genptr(uint32_t *v) { return ndr_pull_generic_ptr(this, v); }
	int g_ctx_handle(CONTEXT_HANDLE *v) { return ndr_pull_context_handle(this, v); }

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

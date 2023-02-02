#pragma once
#include <cstdint>
#include <gromox/common_types.hpp>
#include <gromox/double_list.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/rpc_types.hpp>

#define NDR_ERR_SUCCESS pack_result::success
#define NDR_ERR_FAILURE pack_result::failure
#define NDR_ERR_CHARCNV pack_result::charconv
#define NDR_ERR_BUFSIZE pack_result::bufsize
#define NDR_ERR_ALLOC pack_result::alloc
#define NDR_ERR_NDR64 pack_result::ndr64
#define NDR_ERR_PADDING pack_result::padding
#define NDR_ERR_RANGE pack_result::range
#define NDR_ERR_ARRAY_SIZE pack_result::array_size
#define NDR_ERR_BAD_SWITCH pack_result::bad_switch
#define NDR_ERR_IPV6ADDRESS pack_result::ipv6addr

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
	pack_result advance(uint32_t);
	pack_result align(size_t);
	pack_result union_align(size_t);
	pack_result trailer_align(size_t);
	pack_result g_str(char *v, uint32_t z);
	pack_result g_uint8(uint8_t *);
	pack_result g_uint16(uint16_t *);
	pack_result g_int32(int32_t *);
	pack_result g_uint32(uint32_t *);
	pack_result g_uint64(uint64_t *);
	pack_result g_ulong(uint32_t *);
	pack_result g_uint8_a(uint8_t *v, uint32_t z);
	pack_result g_guid(GUID *);
	pack_result g_syntax(SYNTAX_ID *);
	pack_result g_blob(DATA_BLOB *);
	pack_result check_str(uint32_t c, uint32_t z);
	pack_result g_genptr(uint32_t *v);
	pack_result g_ctx_handle(CONTEXT_HANDLE *);

	const uint8_t *data = nullptr;
	uint32_t flags = 0, data_size = 0, offset = 0, ptr_count = 0;
};

struct GX_EXPORT NDR_PUSH {
	void init(void *d, uint32_t asize, uint32_t fl);
	void set_ptrcnt(uint32_t c) { ptr_count = c; }
	void destroy();
	pack_result align(size_t);
	pack_result union_align(size_t);
	pack_result trailer_align(size_t);
	pack_result p_str(const char *v, uint32_t req);
	pack_result p_uint8(uint8_t);
	pack_result p_uint16(uint16_t);
	pack_result p_uint32(uint32_t);
	pack_result p_int32(int32_t v) { return p_uint32(v); }
	pack_result p_uint64(uint64_t);
	pack_result p_ulong(uint32_t);
	pack_result p_uint8_a(const uint8_t *v, uint32_t z);
	pack_result p_guid(const GUID &);
	pack_result p_syntax(const SYNTAX_ID &);
	pack_result p_blob(DATA_BLOB);
	pack_result p_zero(uint32_t z);
	pack_result p_unique_ptr(const void *v);
	pack_result p_ctx_handle(const CONTEXT_HANDLE &);

	uint8_t *data = nullptr;
	uint32_t flags = 0, alloc_size = 0, offset = 0, ptr_count = 0;
	DOUBLE_LIST full_ptr_list{};
};

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

struct NDR_PULL {
	uint32_t flags;
	const uint8_t *data;
	uint32_t data_size;
	uint32_t offset;
	uint32_t ptr_count;
};

struct NDR_PUSH {
	uint32_t flags;
	uint8_t *data;
	uint32_t alloc_size;
	uint32_t offset;
	uint32_t ptr_count;
	DOUBLE_LIST full_ptr_list;
};

void ndr_set_flags(uint32_t *pflags, uint32_t new_flags);
extern GX_EXPORT uint32_t ndr_pull_get_ptrcnt(const NDR_PULL *);
extern GX_EXPORT void ndr_pull_init(NDR_PULL *, const void *, uint32_t size, uint32_t flags);
void ndr_pull_destroy(NDR_PULL *pndr);
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
void ndr_push_set_ptrcnt(NDR_PUSH *pndr, uint32_t ptr_count);
extern void ndr_push_init(NDR_PUSH *pndr, void *pdata,
	uint32_t alloc_size, uint32_t flags);
void ndr_push_destroy(NDR_PUSH *pndr);
int ndr_push_align(NDR_PUSH *pndr, size_t size);
int ndr_push_union_align(NDR_PUSH *pndr, size_t size);
int ndr_push_trailer_align(NDR_PUSH *pndr, size_t size);
int ndr_push_string(NDR_PUSH *pndr, const char *var, uint32_t required);
int ndr_push_uint8(NDR_PUSH *pndr, uint8_t v);
int ndr_push_uint16(NDR_PUSH *pndr, uint16_t v);
#define ndr_push_int32(e, v) ndr_push_uint32((e), (v))
int ndr_push_uint32(NDR_PUSH *pndr, uint32_t v);
int ndr_push_uint64(NDR_PUSH *pndr, uint64_t v);
int ndr_push_ulong(NDR_PUSH *pndr, uint32_t v);
int ndr_push_array_uint8(NDR_PUSH *pndr, const uint8_t *data, uint32_t n);
int ndr_push_guid(NDR_PUSH *pndr, const GUID *r);
int ndr_push_syntax_id(NDR_PUSH *pndr, const SYNTAX_ID *r);
int ndr_push_data_blob(NDR_PUSH *pndr, DATA_BLOB blob);
int ndr_push_zero(NDR_PUSH *pndr, uint32_t n);
int ndr_push_unique_ptr(NDR_PUSH *pndr, const void *p);
int ndr_push_context_handle(NDR_PUSH *pndr, const CONTEXT_HANDLE *r);

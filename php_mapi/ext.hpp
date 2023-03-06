#pragma once
#include <cstdint>
#include <memory>
#include <gromox/ext_buffer.hpp>
#include "php.h"
#undef slprintf
#undef vslprintf
#undef snprintf
#undef vsnprintf
#undef vasprintf
#undef asprintf

#define SYNC_DELETES_FLAG_HARDDELETE				0x02
#define ROOT_HANDLE 0
#define INVALID_HANDLE 0xFFFFFFFF
#define SYNC_NEW_MESSAGE 0x800
#define SYNC_SOFT_DELETE 0x01

struct zcreq;
struct zcresp;

struct zstr_delete {
	inline void operator()(zend_string *s) const { zend_string_release(s); };
};

using zstrplus = std::unique_ptr<zend_string, zstr_delete>;

extern void *ext_pack_alloc(size_t);
extern const struct EXT_BUFFER_MGT ext_buffer_mgt;

struct PULL_CTX : public EXT_PULL {
	inline void init(void *d, uint32_t s) {
		return EXT_PULL::init(d, s, ext_pack_alloc,
		       EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE);
	}
	pack_result g_perm_set(PERMISSION_SET *);
	pack_result g_state_a(STATE_ARRAY *);
	pack_result g_znotif_a(ZNOTIFICATION_ARRAY *);
};

struct PUSH_CTX : public EXT_PUSH {
	inline bool init() {
		return EXT_PUSH::init(nullptr, 0,
		       EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE, &ext_buffer_mgt);
	}
	pack_result p_perm_set(const PERMISSION_SET *);
	pack_result p_rule_data(const RULE_DATA *);
	pack_result p_rule_list(const RULE_LIST *);
	pack_result p_state_a(const STATE_ARRAY *);
};

extern pack_result rpc_ext_push_request(const zcreq *, BINARY *);
extern pack_result rpc_ext_pull_response(const BINARY *, zcresp *);

template<typename T> T *st_malloc() { return static_cast<T *>(emalloc(sizeof(T))); }
template<typename T> T *sta_malloc(size_t elem) { return static_cast<T *>(emalloc(sizeof(T) * elem)); }
template<typename T> T *sta_realloc(T *orig, size_t elem) { return static_cast<T *>(erealloc(orig, sizeof(T) * elem)); }
template<typename T> T *st_calloc() { return static_cast<T *>(ecalloc(1, sizeof(T))); }

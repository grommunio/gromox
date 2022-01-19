#pragma once
#include <cstdint>
#include <gromox/ext_buffer.hpp>
#include "types.h"
#include "php.h"
#undef slprintf
#undef vslprintf
#undef snprintf
#undef vsnprintf
#undef vasprintf
#undef asprintf

extern void *ext_pack_alloc(size_t);
extern const struct EXT_BUFFER_MGT ext_buffer_mgt;

struct PULL_CTX : public EXT_PULL {
	inline void init(void *d, uint32_t s) {
		return EXT_PULL::init(d, s, ext_pack_alloc,
		       EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE);
	}
	int g_perm_set(PERMISSION_SET *);
	int g_state_a(STATE_ARRAY *);
	int g_znotif_a(ZNOTIFICATION_ARRAY *);
};

struct PUSH_CTX : public EXT_PUSH {
	inline bool init() {
		return EXT_PUSH::init(nullptr, 0,
		       EXT_FLAG_WCOUNT | EXT_FLAG_ZCORE, &ext_buffer_mgt);
	}
	int p_perm_set(const PERMISSION_SET *);
	int p_rule_data(const RULE_DATA *);
	int p_rule_list(const RULE_LIST *);
	int p_state_a(const STATE_ARRAY *);
};

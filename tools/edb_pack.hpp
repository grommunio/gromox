#pragma once
#include <gromox/ext_buffer.hpp>

/**
 * @alloc_hint:		number of elements multiplied by element size, or,
 * 			in case of strings, UTF-16 presentation size
 * @sp_ulen:		length of SeparatedProperty<slot> (when uncompressed)
 */
struct edb_postproc {
	bool active = false;
	uint16_t slot = 0;
	uint16_t new_enc_type = 0;
	union {
		uint32_t far_alloc_hint = 0;
		uint32_t near_offset;
	};
	uint32_t sp_ulen = 0;
};

struct edb_pull : public EXT_PULL {
	pack_result g_edb_propval(void **, edb_postproc &);
	pack_result g_edb_propval_a(TPROPVAL_ARRAY *);
};

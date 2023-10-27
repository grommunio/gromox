// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <gromox/ext_buffer.hpp>
#include "edb_pack.hpp"
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != EXT_ERR_SUCCESS) return klfdv; } while (false)

enum { /* property types (in the metadata) */
	EPT_BOOL         = 0x08, // mv 0x88
	EPT_SHORT        = 0x10, // mv 0x90
	EPT_LONG         = 0x18, // mv 0x98
	EPT_I8           = 0x20, // mv 0xa0
	EPT_CURRENCY     = 0x24, // mv 0xa4
	EPT_FLOAT        = 0x28, // mv 0xa8
	EPT_DOUBLE       = 0x30, // mv 0xb0
	EPT_APPTIME      = 0x34, // mv 0xb4
	EPT_SYSTIME      = 0x38, // mv 0xb8
	EPT_CLSID        = 0x40, // mv 0xc0
	EPT_UNICODE      = 0x48, // mv 0xc8
	EPT_BINARY       = 0x50, // mv 0xd0
};

enum { /* encodings for EDB property values */
	EPV_TOMBSTONE    = 0x00,
	EPV_BOOL_0       = 0x08,
	EPV_BOOL_1       = 0x09,
	EPV_SHORT_0      = 0x10,
	EPV_SHORT_1      = 0x11,
	EPV_SHORT_2      = 0x12,
	EPV_LONG_0       = 0x18,
	EPV_LONG_1       = 0x19,
	EPV_LONG_2       = 0x1a,
	EPV_LONG_4       = 0x1b,
	EPV_I8_0         = 0x20,
	EPV_I8_1         = 0x21,
	EPV_I8_2         = 0x22,
	EPV_I8_4         = 0x23,
	EPV_I8_8         = 0x24,
	EPV_CURRENCY     = 0x24, /* no short forms */
	EPV_FLOAT_4      = 0x28,
	EPV_FLOAT_0      = 0x2a, /* no 1B/2B forms */
	EPV_DOUBLE_8     = 0x30, /* no 1B/2B/4B forms */
	EPV_APPTIME_8    = 0x30,
	EPV_DOUBLE_0     = 0x32,
	EPV_APPTIME_0    = 0x32,
	EPV_SYSTIME_8    = 0x38,
	EPV_SYSTIME_4    = 0x39, /* no 0B/1B/2B forms */
	EPV_CLSID        = 0x40, /* no short forms */
	EPV_UNICODE_0    = 0x48,
	EPV_UNICODE_1    = 0x4d,
	EPV_UNICODE_2    = 0x4e,
	EPV_BINARY_0     = 0x50,
	EPV_BINARY_1     = 0x51,
	EPV_BINARY_2     = 0x52,
	/* If the propval is >=2049 bytes, it gets replaced. */
	EPV_NEAR         = 0x78,
	EPV_FAR          = 0x7a,
	/*
	 * 90/98/a0/a4/a8/b0/b4/b8/c0/c8/d0 do not happen, because MV props
	 * cannot exist with 0 elements.
	 */
	EPV_MV_SHORT_1   = 0x91,
	EPV_MV_SHORT_2   = 0x92,
	EPV_MV_LONG_1    = 0x99,
	EPV_MV_LONG_2    = 0x9a,
	EPV_MV_I8_1      = 0xa1,
	EPV_MV_I8_2      = 0xa2,
	EPV_MV_FLOAT_1   = 0xa9,
	EPV_MV_FLOAT_2   = 0xaa,
	EPV_MV_DOUBLE_1  = 0xb1,
	EPV_MV_DOUBLE_2  = 0xb2,
	EPV_MV_SYSTIME_1 = 0xb9,
	EPV_MV_SYSTIME_2 = 0xba,
	EPV_MV_CLSID_1   = 0xc1,
	EPV_MV_CLSID_2   = 0xc2,
	EPV_MV_UNICODE_1 = 0xc9,
	EPV_MV_UNICODE_2 = 0xca,
	EPV_MV_BINARY_1  = 0xd1,
	EPV_MV_BINARY_2  = 0xd2,
};

static constexpr uint16_t decode_edb_proptype2(uint8_t t)
{
	switch (t) {
	case EPT_BOOL:     return PT_BOOLEAN;
	case EPT_SHORT:    return PT_SHORT;
	case EPT_LONG:     return PT_LONG;
	case EPT_I8:       return PT_I8;
	case EPT_CURRENCY: return PT_CURRENCY;
	case EPT_FLOAT:    return PT_FLOAT;
	case EPT_DOUBLE:   return PT_DOUBLE;
	case EPT_APPTIME:  return PT_APPTIME;
	case EPT_SYSTIME:  return PT_SYSTIME;
	case EPT_CLSID:    return PT_CLSID;
	case EPT_UNICODE:  return PT_UNICODE;
	case EPT_BINARY:   return PT_BINARY;
	default:           return PT_UNSPECIFIED;
	}
}

static constexpr uint16_t decode_edb_proptype(uint8_t t)
{
	return ((t & 0x80) ? MV_FLAG : 0) | decode_edb_proptype2(t & ~0x80);
}

pack_result edb_pull::g_edb_propval(void **vval, edb_postproc &proc)
{
	uint8_t type;
	TRY(g_uint8(&type));
	union { int8_t i; uint8_t u; } x8{};
	union { int16_t i; uint16_t u; } x16{};
	union { int32_t i; uint32_t u; } x32{};
	union { int64_t i; uint64_t u; } x64{};
	switch (type) {
	case EPV_SHORT_1:
	case EPV_LONG_1:
	case EPV_I8_1:
	case EPV_UNICODE_1:
	case EPV_BINARY_1:
		TRY(g_uint8(&x8.u));
		break;
	case EPV_SHORT_2:
	case EPV_LONG_2:
	case EPV_I8_2:
	case EPV_UNICODE_2:
	case EPV_BINARY_2:
		TRY(g_uint16(&x16.u));
		break;
	case EPV_LONG_4:
	case EPV_I8_4:
	case EPV_SYSTIME_4:
		TRY(g_uint32(&x32.u));
		break;
	case EPV_I8_8:
	case EPV_SYSTIME_8:
		TRY(g_uint64(&x64.u));
		break;
	case EPV_MV_SHORT_1:
	case EPV_MV_LONG_1:
	case EPV_MV_FLOAT_1:
	case EPV_MV_DOUBLE_1:
	case EPV_MV_I8_1:
	case EPV_MV_UNICODE_1:
	case EPV_MV_SYSTIME_1:
	case EPV_MV_CLSID_1:
	case EPV_MV_BINARY_1:
		TRY(g_uint8(&x8.u));
		x16.u = x8.u;
		break;
	case EPV_MV_SHORT_2:
	case EPV_MV_LONG_2:
	case EPV_MV_I8_2:
	case EPV_MV_FLOAT_2:
	case EPV_MV_DOUBLE_2:
	case EPV_MV_UNICODE_2:
	case EPV_MV_SYSTIME_2:
	case EPV_MV_CLSID_2:
	case EPV_MV_BINARY_2:
		TRY(g_uint16(&x16.u));
		break;
	}

	proc.new_enc_type = type;
	switch (type) {
	case EPV_BOOL_0 ... EPV_BOOL_1: {
		auto r = anew<uint8_t>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		*r = type & 0x1;
		return pack_result::ok;
	}
	case EPV_SHORT_0 ... EPV_SHORT_2: {
		auto r = anew<uint16_t>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		if (type == EPV_SHORT_0)      *r = 0;
		else if (type == EPV_SHORT_1) *r = x8.i;
		else if (type == EPV_SHORT_2) *r = x16.i;
		return pack_result::ok;
	}
	case EPV_LONG_0 ... EPV_LONG_4: {
		auto r = anew<uint32_t>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		if (type == EPV_LONG_0)      *r = 0;
		else if (type == EPV_LONG_1) *r = x8.i;
		else if (type == EPV_LONG_2) *r = x16.i;
		else if (type == EPV_LONG_4) *r = x32.i;
		return pack_result::ok;
	}
	case EPV_I8_0 ... EPV_I8_8:
	case EPV_SYSTIME_8 ... EPV_SYSTIME_4: {
		auto r = anew<uint64_t>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		switch (type) {
		case EPV_I8_0: *r = 0; break;
		case EPV_I8_1: *r = x8.i; break;
		case EPV_I8_2: *r = x16.i; break;
		case EPV_I8_4:
		case EPV_SYSTIME_4: *r = x32.i; break;
		case EPV_I8_8:
		case EPV_SYSTIME_8: *r = x64.i; break;
		}
		return pack_result::ok;
	}
	case EPV_FLOAT_4 ... EPV_FLOAT_0: {
		auto r = anew<float>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		if (type == EPV_FLOAT_4)
			return g_float(r);
		*r = 0;
		return pack_result::ok;
	}
	case EPV_DOUBLE_8 ... EPV_DOUBLE_0: {
		auto r = anew<double>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		if (type == EPV_DOUBLE_8)
			return g_double(r);
		*r = 0;
		return pack_result::ok;
	}
	case EPV_CLSID: {
		auto r = anew<GUID>();
		*vval = r;
		return r != nullptr ? g_guid(r) : pack_result::alloc;
	}
	case EPV_BINARY_0: {
		auto r = anew<BINARY>();
		if (r == nullptr)
			return pack_result::alloc;
		r->cb = 0;
		r->pv = nullptr;
		*vval = r;
		return pack_result::ok;
	}
	case EPV_BINARY_1:
	case EPV_BINARY_2: {
		auto r = anew<BINARY>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		r->cb = type == EPV_BINARY_1 ? x8.u : x16.u;
		if (r->cb == 0) {
			r->pb = nullptr;
			return pack_result::ok;
		}
		r->pv = m_alloc(r->cb);
		if (r->pv == nullptr) {
			r->cb = 0;
			return pack_result::alloc;
		}
		return g_bytes(r->pv, r->cb);
	}
	case EPV_UNICODE_0: {
		auto r = anew<char>(1);
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		*r = '\0';
		return pack_result::ok;
	}
	case EPV_UNICODE_1:
	case EPV_UNICODE_2: {
		if (type == EPV_UNICODE_1)
			x16.u = x8.u;
		auto r = anew<char>(x16.u + 1);
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		r[x16.u] = '\0';
		return g_bytes(r, x16.u);
	}
	case EPV_MV_SHORT_1:
	case EPV_MV_SHORT_2: {
		auto r = anew<SHORT_ARRAY>();
		*vval = r;
		return r != nullptr ? g_uint16_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_LONG_1:
	case EPV_MV_LONG_2: {
		auto r = anew<LONG_ARRAY>();
		*vval = r;
		return r != nullptr ? g_uint32_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_I8_1:
	case EPV_MV_I8_2:
	case EPV_MV_SYSTIME_1:
	case EPV_MV_SYSTIME_2: {
		auto r = anew<LONGLONG_ARRAY>();
		*vval = r;
		return r != nullptr ? g_uint64_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_FLOAT_1:
	case EPV_MV_FLOAT_2: {
		auto r = anew<FLOAT_ARRAY>();
		*vval = r;
		return r != nullptr ? g_float_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_DOUBLE_1:
	case EPV_MV_DOUBLE_2: {
		auto r = anew<DOUBLE_ARRAY>();
		*vval = r;
		return r != nullptr ? g_double_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_UNICODE_1:
	case EPV_MV_UNICODE_2: {
		auto r = anew<STRING_ARRAY>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		r->ppstr = anew<char *>(x16.u + 1);
		if (r->ppstr == nullptr)
			return pack_result::alloc;
		r->count = x16.u;
		r->ppstr[r->count] = nullptr;
		for (unsigned int i = 0; i < r->count; ++i) {
			if (m_offset >= m_data_size)
				return pack_result::format;
			TRY(g_uint8(&x8.u));
			switch (x8.u) {
			case EPV_UNICODE_0:
				x16.u = 0;
				break;
			case EPV_UNICODE_1:
				TRY(g_uint8(&x8.u));
				x16.u = x8.u;
				break;
			case EPV_UNICODE_2:
				TRY(g_uint16(&x16.u));
				break;
			default:
				return pack_result::format;
			}
			r->ppstr[i] = anew<char>(x16.u + 1);
			if (r->ppstr[i] == nullptr)
				return pack_result::alloc;
			TRY(g_bytes(r->ppstr[i], x16.u));
			r->ppstr[i][x16.u] = '\0';
		}
		return pack_result::ok;
	}
	case EPV_MV_CLSID_1:
	case EPV_MV_CLSID_2: {
		auto r = anew<GUID_ARRAY>();
		*vval = r;
		return r != nullptr ? g_guid_an(r, x16.u) : pack_result::alloc;
	}
	case EPV_MV_BINARY_1:
	case EPV_MV_BINARY_2: {
		auto r = anew<BINARY_ARRAY>();
		if (r == nullptr)
			return pack_result::alloc;
		*vval = r;
		r->pbin = anew<BINARY>(x16.u);
		if (r->pbin == nullptr)
			return pack_result::alloc;
		r->count = x16.u;
		for (unsigned int i = 0; i < r->count; ++i) {
			if (m_offset >= m_data_size)
				return pack_result::format;
			TRY(g_uint8(&x8.u));
			switch (x8.u) {
			case EPV_BINARY_0:
				r->pbin[i].cb = 0;
				break;
			case EPV_BINARY_1:
				TRY(g_uint8(&x8.u));
				r->pbin[i].cb = x8.u;
				break;
			case EPV_BINARY_2:
				TRY(g_uint16(&x16.u));
				r->pbin[i].cb = x16.u;
				break;
			default:
				return pack_result::format;
			}
			if (r->pbin[i].cb == 0) {
				r->pbin[i].pb = nullptr;
				continue;
			}
			r->pbin[i].pv = m_alloc(r->pbin[i].cb);
			if (r->pbin[i].pv == nullptr) {
				r->pbin[i].cb = 0;
				return pack_result::alloc;
			}
			TRY(g_bytes(r->pbin[i].pv, r->pbin[i].cb));
		}
		return pack_result::ok;
	}
	case EPV_NEAR:
	case EPV_FAR: {
		*vval = nullptr;
		proc.active = true;
		TRY(g_uint16(&proc.slot));
		TRY(g_uint32(&proc.far_alloc_hint));
		TRY(g_uint16(&proc.new_enc_type));
		TRY(g_uint32(&proc.sp_ulen));
		return pack_result::ok;
	}
	case EPV_TOMBSTONE:
		*vval = nullptr;
		proc.active = true;
		return pack_result::ok;
	default:
		fprintf(stderr, "edb_pack: unrecognized EPV value 0x%02x\n", type);
		return pack_result::format;
	}
}

pack_result edb_pull::g_edb_propval_a(TPROPVAL_ARRAY *r)
{
	char sig[4];
	TRY(g_bytes(sig, 4));
	if (memcmp(sig, "ProP", 4) != 0)
		return pack_result::format;
	uint8_t abyte;
	uint16_t glflags, ashort;
	uint32_t along;
	TRY(g_uint16(&glflags));
	TRY(g_uint16(&ashort)); /* propcount */
	if (glflags == 0x400)
		;
	else if (glflags == 0x401)
		TRY(g_uint32(&along));
	else
		return pack_result::format;
	r->count = ashort;
	if (r->count == 0) {
		r->ppropval = nullptr;
		return pack_result::ok;
	}
	r->ppropval = anew<TAGGED_PROPVAL>(strange_roundup(r->count, SR_GROW_TAGGED_PROPVAL));
	if (r->ppropval == nullptr) {
		r->count = 0;
		return pack_result::alloc;
	}
	for (unsigned int i = 0; i < r->count; ++i) {
		TRY(g_uint8(&abyte));
		TRY(g_uint16(&ashort));
		auto type = decode_edb_proptype(abyte);
		if (type == PT_UNSPECIFIED)
			return pack_result::format;
		r->ppropval[i].proptag = PROP_TAG(type, ashort);
	}
	bool filter = false;
	for (unsigned int i = 0; i < r->count; ++i) {
		edb_postproc proc;
		auto ret = g_edb_propval(&r->ppropval[i].pvalue, proc);
		if (ret != pack_result::ok) {
			return ret;
		} else if (!proc.active) {
			continue;
		} else if (proc.new_enc_type == EPV_TOMBSTONE) {
			r->ppropval[i].proptag = PROP_TAG(PR_NULL, PT_NULL);
			filter = true;
		} else if (proc.active) {
			/* e.g. EPV_FAR not implemented yet, so strip */
			r->ppropval[i].proptag = CHANGE_PROP_TYPE(r->ppropval[i].proptag, PT_NULL);
			filter = true;
		}
	}
	if (filter) {
		auto m = std::remove_if(&r->ppropval[0], &r->ppropval[r->count],
		         [](const TAGGED_PROPVAL &tp) { return PROP_TYPE(tp.proptag) == PT_NULL; });
		r->count = m - &r->ppropval[0];
	}
	return pack_result::ok;
}

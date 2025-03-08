// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <vector>
#include <libHX/endian.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

using namespace gromox;

namespace {
struct STACK_NODE {
	STACK_NODE(const uint8_t *b, uint8_t l) noexcept : common_length(l)
		{ memcpy(pcommon_bytes, b, common_length); }
	uint8_t common_length;
	uint8_t pcommon_bytes[6];
};
using byte_stack = std::vector<STACK_NODE>;

struct mdel {
	inline void operator()(BINARY *x) const { rop_util_free_binary(x); }
};
}

std::unique_ptr<idset> idset::create(idset::type t) try
{
	return std::make_unique<idset>(t);
} catch (const std::bad_alloc &) {
	return nullptr;
}

BOOL idset::register_mapping(void *p, REPLICA_MAPPING m)
{
	auto pset = this;
	if (pset->pparam != nullptr || pset->mapping != nullptr)
		return FALSE;
	if (p == nullptr)
		return false;
	pset->pparam = p;
	pset->mapping = m;
	return TRUE;
}

BOOL idset::append(uint64_t eid)
{
	auto x = rop_util_get_gc_value(eid);
	return append_range(rop_util_get_replid(eid), x, x);
}

BOOL idset::append_range(uint16_t replid,
    uint64_t low_value, uint64_t high_value) try
{
	if (packed() || low_value > high_value)
		return FALSE;
	auto prepl_node = std::find_if(repl_list.begin(), repl_list.end(),
	                  [&](const repl_node &n) { return n.replid == replid; });
	if (prepl_node == repl_list.end())
		prepl_node = repl_list.emplace(repl_list.end(), replid);
	prepl_node->range_list.insert(low_value, high_value);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1614: ENOMEM");
	return false;
}

void idset::remove(uint64_t eid) try
{
	if (packed())
		return;
	auto replid = rop_util_get_replid(eid);
	auto value = rop_util_get_gc_value(eid);
	auto prepl_node = std::find_if(repl_list.begin(), repl_list.end(),
	                  [&](const repl_node &n) { return n.replid == replid; });
	if (prepl_node == repl_list.end())
		return;
	prepl_node->range_list.erase(value);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1615: ENOMEM");
}

BOOL idset::concatenate(const idset *pset_src)
{
	if (packed() || pset_src->packed())
		return FALSE;
	auto &src_list = pset_src->repl_list;
	for (auto prepl_node = src_list.begin();
	     prepl_node != src_list.end(); ++prepl_node)
		for (const auto &range_node : prepl_node->range_list)
			if (!append_range(prepl_node->replid,
			    range_node.lo, range_node.hi))
				return FALSE;
	return TRUE;
}

bool idset::contains(uint64_t eid) const
{
	auto pset = this;
	
	if (pset->repl_type == idset::type::guid_packed)
		return FALSE;	
	auto replid = rop_util_get_replid(eid);
	auto value = rop_util_get_gc_value(eid);
	auto prepl_node = std::find_if(repl_list.begin(), repl_list.end(),
	                  [&](const repl_node &n) { return n.replid == replid; });
	if (prepl_node == repl_list.end())
		return false;
	return prepl_node->range_list.contains(value);
}

static std::unique_ptr<BINARY, mdel> idset_init_binary()
{
	std::unique_ptr<BINARY, mdel> pbin(gromox::me_alloc<BINARY>());
	if (pbin == nullptr)
		return NULL;
	pbin->cb = 0;
	pbin->pv = malloc(4096);
	if (pbin->pv == nullptr)
		return NULL;
	return pbin;
}

static BOOL idset_write_to_binary(BINARY *pbin, const void *pb, uint8_t len)
{
	uint32_t alloc_len = strange_roundup(pbin->cb, 4096);
	if (pbin->cb + len >= alloc_len) {
		alloc_len = strange_roundup(pbin->cb + len, 4096);
		auto pdata = gromox::re_alloc<uint8_t>(pbin->pb, alloc_len);
		if (pdata == nullptr)
			return FALSE;
		pbin->pb = pdata;
	}
	memcpy(pbin->pb + pbin->cb, pb, len);
	pbin->cb += len;
	return TRUE;
}

static BOOL idset_encoding_push_command(BINARY *pbin,
    uint8_t length, const uint8_t *pcommon_bytes)
{
	if (length > 6)
		return FALSE;
	return idset_write_to_binary(pbin, &length, sizeof(uint8_t)) &&
	       idset_write_to_binary(pbin, pcommon_bytes, length);
}

static BOOL idset_encoding_pop_command(BINARY *pbin)
{
	uint8_t command = 0x50;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t));
}


static BOOL idset_encode_range_command(BINARY *pbin, uint8_t length,
    const uint8_t *plow_bytes, const uint8_t *phigh_bytes)
{
	if (length > 6 || 0 == length)
		return FALSE;
	uint8_t command = 0x52;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t)) &&
	       idset_write_to_binary(pbin, plow_bytes, length) &&
	       idset_write_to_binary(pbin, phigh_bytes, length);
}

static BOOL idset_encode_end_command(BINARY *pbin)
{
	uint8_t command = 0;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t));
}

static uint8_t idset_stack_get_common_bytes(const byte_stack &stack, GLOBCNT &common_bytes)
{
	uint8_t common_length = 0;
	
	for (const auto &limb : stack) {
		if (common_length + limb.common_length <= 6)
			memcpy(&common_bytes.ab[common_length],
			       limb.pcommon_bytes, limb.common_length);
		common_length += limb.common_length;
	}
	return common_length;
}

static BOOL idset_encode_globset(BINARY *pbin, const repl_node::range_list_t &globset)
{
	if (globset.size() == 1) {
		auto prange_node = globset.begin();
		auto common_bytes = rop_util_value_to_gc(prange_node->lo);
		if (prange_node->hi == prange_node->lo) {
			if (!idset_encoding_push_command(pbin, 6, common_bytes.ab))
				return FALSE;
		} else {
			auto common_bytes1 = rop_util_value_to_gc(prange_node->hi);
			if (!idset_encode_range_command(pbin, 6,
			    common_bytes.ab, common_bytes1.ab))
				return FALSE;
		}
		return idset_encode_end_command(pbin);
	}
	auto common_bytes  = rop_util_value_to_gc(globset.front().lo);
	auto common_bytes1 = rop_util_value_to_gc(globset.back().hi);
	uint8_t stack_length;
	for (stack_length = 0; stack_length < 6; ++stack_length)
		if (common_bytes.ab[stack_length] != common_bytes1.ab[stack_length])
			break;
	if (stack_length != 0 &&
	    !idset_encoding_push_command(pbin, stack_length, common_bytes.ab))
		return FALSE;
	for (const auto &range_node : globset) {
		common_bytes = rop_util_value_to_gc(range_node.lo);
		if (range_node.hi == range_node.lo) {
			if (!idset_encoding_push_command(pbin,
			    6 - stack_length, &common_bytes.ab[stack_length]))
				return FALSE;
			continue;
		}
		common_bytes1 = rop_util_value_to_gc(range_node.hi);
		int i;
		for (i = stack_length; i < 6; ++i)
			if (common_bytes.ab[i] != common_bytes1.ab[i])
				break;
		if (stack_length != i && !idset_encoding_push_command(pbin,
		    i - stack_length, &common_bytes.ab[stack_length]))
			return FALSE;
		if (!idset_encode_range_command(pbin, 6 - i,
		    &common_bytes.ab[i], &common_bytes1.ab[i]))
			return FALSE;
		if (stack_length != i && !idset_encoding_pop_command(pbin))
			return FALSE;
	}
	if (stack_length != 0 && !idset_encoding_pop_command(pbin))
		return FALSE;
	return idset_encode_end_command(pbin);
}

static BOOL idset_write_uint16(BINARY *pbin, uint16_t v)
{
	v = cpu_to_le16(v);
	return idset_write_to_binary(pbin, &v, sizeof(v));
}

static BOOL idset_write_uint32(BINARY *pbin, uint32_t v)
{
	v = cpu_to_le32(v);
	return idset_write_to_binary(pbin, &v, sizeof(v));
}

static BOOL idset_write_guid(BINARY *pbin, const GUID *pguid)
{
	return idset_write_uint32(pbin, pguid->time_low) &&
	       idset_write_uint16(pbin, pguid->time_mid) &&
	       idset_write_uint16(pbin, pguid->time_hi_and_version) &&
	       idset_write_to_binary(pbin, pguid->clock_seq, 2) &&
	       idset_write_to_binary(pbin, pguid->node, 6);
}

BINARY *idset::serialize_replid() const
{
	if (packed())
		return NULL;
	auto pbin = idset_init_binary();
	if (pbin == nullptr)
		return NULL;
	for (const auto &repl_node : repl_list) {
		if (repl_node.range_list.size() == 0)
			continue;
		if (!idset_write_uint16(pbin.get(), repl_node.replid) ||
		    !idset_encode_globset(pbin.get(), repl_node.range_list))
			return NULL;
	}
	return pbin.release();
}

BINARY *idset::serialize_replguid()
{
	auto pset = this;
	GUID tmp_guid;
	
	if (packed() || pset->mapping == nullptr)
		return NULL;
	auto pbin = idset_init_binary();
	if (pbin == nullptr)
		return NULL;
	for (auto &repl_node : repl_list) {
		if (repl_node.range_list.size() == 0)
			continue;
		if (!pset->mapping(TRUE, pset->pparam,
		    &repl_node.replid, &tmp_guid) ||
		    !idset_write_guid(pbin.get(), &tmp_guid) ||
		    !idset_encode_globset(pbin.get(), repl_node.range_list))
			return NULL;
	}
	return pbin.release();
}

BINARY *idset::serialize()
{
	switch (repl_type) {
	case type::id_loose:   return serialize_replid();
	case type::guid_loose: return serialize_replguid();
	default: return nullptr;
	}
}

static uint32_t idset_decode_globset(const BINARY *pbin, repl_node::range_list_t &globset) try
{
	uint32_t offset = 0;
	byte_stack bytes_stack;
	bytes_stack.reserve(6);
	
	while (offset < pbin->cb) {
		uint8_t command = pbin->pb[offset++];
		switch (command) {
		case 0x0: /* end */
			return offset;
		case 0x1:
		case 0x2:
		case 0x3:
		case 0x4:
		case 0x5:
		case 0x6: { /* push */
			if (offset + command >= pbin->cb) {
				mlog(LV_DEBUG, "D-1651: not enough bytes left");
				return 0;
			}
			GLOBCNT common_bytes;
			memcpy(common_bytes.ab, &pbin->pb[offset], command);
			offset += command;
			bytes_stack.emplace_back(common_bytes.ab, command);
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (stack_length > 6) {
				mlog(LV_DEBUG, "idset: length of common bytes in"
					" stack is too long when deserializing");
				return 0;
			}
			if (stack_length != 6)
				break;
			try {
				auto x = rop_util_gc_to_value(common_bytes);
				globset.vec().emplace_back(x, x);
			} catch (const std::bad_alloc &) {
				mlog(LV_ERR, "E-1616: ENOMEM");
				return 0;
			}
			/* MS-OXCFXICS 3.1.5.4.3.1.1 */
			/* pop the stack without pop command */
			if (bytes_stack.size() > 0)
				bytes_stack.pop_back();
			break;
		}
		case 0x42: { /* bitmask */
			if (offset + 2 >= pbin->cb) {
				mlog(LV_DEBUG, "D-1652: not enough bytes left");
				return 0;
			}
			GLOBCNT common_bytes;
			uint8_t start_value = pbin->pb[offset++];
			uint8_t bitmask = pbin->pb[offset++];
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (5 != stack_length) {
				mlog(LV_DEBUG, "idset: bitmask command error when "
					"deserializing, length of common bytes in "
					"stack should be 5");
				return 0;
			}
			common_bytes.ab[5] = start_value;
			auto low_value = rop_util_gc_to_value(common_bytes);
			std::optional<range_node<uint64_t>> prange_node;
			prange_node.emplace(low_value, low_value);
			for (int i = 0; i < 8; ++i) {
				if (!(bitmask & (1U << i))) {
					if (prange_node.has_value()) {
						globset.vec().push_back(std::move(*prange_node));
						prange_node.reset();
					}
				} else if (!prange_node.has_value()) {
					auto x = low_value + i + 1;
					prange_node.emplace(x, x);
				} else {
					++prange_node->hi;
				}
			}
			if (prange_node.has_value()) {
				globset.vec().push_back(std::move(*prange_node));
				//prange_node.reset();
			}
			break;
		}
		case 0x50: /* pop */
			if (bytes_stack.size() > 0)
				bytes_stack.pop_back();
			break;
		case 0x52: { /* range */
			GLOBCNT common_bytes;
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (stack_length > 5) {
				mlog(LV_DEBUG, "idset: range command error when "
					"deserializing, length of common bytes in "
					"stack should be less than 5");
				return 0;
			}
			if (offset + 6 - stack_length >= pbin->cb) {
				mlog(LV_DEBUG, "D-1653: not enough bytes left");
				return 0;
			}
			memcpy(&common_bytes.ab[stack_length],
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			auto low_value = rop_util_gc_to_value(common_bytes);
			memcpy(&common_bytes.ab[stack_length],
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			auto high_value = rop_util_gc_to_value(common_bytes);
			globset.vec().emplace_back(low_value, high_value);
			break;
		}
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1618: ENOMEM");
	return 0;
}

static void idset_read_guid(const void *pv, uint32_t offset, GUID *pguid)
{
	auto pb = static_cast<const uint8_t *>(pv);
	pguid->time_low = le32p_to_cpu(&pb[offset]);
	offset += sizeof(uint32_t);
	pguid->time_mid = le16p_to_cpu(&pb[offset]);
	offset += sizeof(uint16_t);
	pguid->time_hi_and_version = le16p_to_cpu(&pb[offset]);
	offset += sizeof(uint16_t);
	memcpy(pguid->clock_seq, pb + offset, 2);
	offset += 2;
	memcpy(pguid->node, pb + offset, 6);
}

BOOL idset::deserialize(const BINARY &bin) try
{
	auto pbin = &bin;
	auto pset = this;
	uint32_t offset = 0;
	
	if (!pset->packed())
		return FALSE;
	while (offset < pbin->cb) {
		repl_node repl_node;

		if (pset->repl_type == idset::type::id_packed) {
			repl_node.replid = le16p_to_cpu(&pbin->pb[offset]);
			offset += sizeof(uint16_t);
		} else {
			idset_read_guid(pbin->pb, offset, &repl_node.replguid);
			offset += 16;
		}
		if (offset >= pbin->cb)
			return FALSE;
		BINARY bin1;
		bin1.pb = pbin->pb + offset;
		bin1.cb = pbin->cb - offset;
		uint32_t length = idset_decode_globset(&bin1, repl_node.range_list);
		if (length == 0)
			return FALSE;
		offset += length;
		repl_list.push_back(std::move(repl_node));
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1617: ENOMEM");
	return false;
}

BOOL idset::convert() try
{
	auto pset = this;
	std::vector<repl_node> temp_list;
	
	if (pset->repl_type == idset::type::id_loose ||
	    pset->repl_type == idset::type::guid_loose) {
		return FALSE;
	} else if (pset->repl_type == idset::type::id_packed) {
		pset->repl_type = idset::type::id_loose;
		return TRUE;
	} else if (pset->repl_type == idset::type::guid_packed) {
		if (pset->mapping == nullptr)
			return FALSE;
		for (auto &replguid_node : repl_list) {
			uint16_t replid;
			if (!pset->mapping(false, pset->pparam,
			    &replid, &replguid_node.replguid))
				return false;
			repl_node repl_node;
			repl_node.replid = replid;
			repl_node.range_list = replguid_node.range_list;
			temp_list.push_back(std::move(repl_node));
		}
		repl_list = std::move(temp_list);
		pset->repl_type = idset::type::guid_loose;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1619: ENOMEM");
	return false;
}

std::pair<bool, repl_node::range_list_t *> idset::get_range_by_id(uint16_t replid)
{
	auto &set = *this;
	if (set.repl_type != idset::type::guid_packed) {
		for (auto &repl_node : set.repl_list)
			if (replid == repl_node.replid)
				return {true, &repl_node.range_list};
		return {true, nullptr};
	}
	if (set.mapping == nullptr)
		return {false, nullptr};
	for (auto &replguid_node : set.repl_list) {
		uint16_t tmp_replid;
		if (!set.mapping(false, set.pparam,
		    &tmp_replid, &replguid_node.replguid))
			return {false, nullptr};
		if (tmp_replid == replid)
			return {true, &replguid_node.range_list};
	}
	return {true, nullptr};
}

BOOL idset::get_repl_first_max(uint16_t replid, uint64_t *peid)
{
	auto [succ, prange_list] = get_range_by_id(replid);
	if (!succ)
		return false;
	if (NULL == prange_list) {
		*peid = rop_util_make_eid_ex(replid, 0);
		return TRUE;
	}
	auto pnode = prange_list->begin();
	*peid = rop_util_make_eid_ex(replid, pnode == prange_list->end() ? 0 :
	        prange_list->front().hi);
	return TRUE;
}

BOOL idset::enum_replist(void *p, REPLIST_ENUM replist_enum)
{
	auto pset = this;
	
	if (pset->repl_type != idset::type::guid_packed) {
		for (const auto &repl_node : repl_list)
			replist_enum(p, repl_node.replid);
		return TRUE;
	}
	if (pset->mapping == nullptr)
		return FALSE;
	for (auto &replguid_node : repl_list) {
		uint16_t tmp_replid;
		if (!pset->mapping(false, pset->pparam,
		    &tmp_replid, &replguid_node.replguid))
			return FALSE;
		replist_enum(p, tmp_replid);
	}
	return TRUE;
}

BOOL idset::enum_repl(uint16_t replid, void *p, REPLICA_ENUM repl_enum)
{
	auto [succ, prange_list] = get_range_by_id(replid);
	if (!succ)
		return false;
	if (prange_list == nullptr)
		return TRUE;
	for (auto &range_node : *prange_list) {
		for (auto ival = range_node.lo; ival <= range_node.hi; ++ival) {
			auto tmp_eid = rop_util_make_eid_ex(replid, ival);
			repl_enum(p, tmp_eid);
		}
	}
	return TRUE;
}

void idset::dump(FILE *fh) const
{
	if (fh == nullptr)
		fh = stderr;
	fprintf(fh, "idset@%p={\n", this);
	for (const auto &repl_node : repl_list) {
		for (const auto &range : repl_node.range_list) {
			if (repl_type == idset::type::guid_packed)
				fprintf(fh, "\t%s ", gromox::bin2hex(repl_node.replguid).c_str());
			else
				fprintf(fh, "\t#%u ", repl_node.replid);
			using LLU = unsigned long long;
			fprintf(fh, "%llxh--%llxh\n", LLU{range.lo}, LLU{range.hi});
		}
	}
	fprintf(fh, "}\n");
}

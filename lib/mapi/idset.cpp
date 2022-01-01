// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <cstdint>
#include <vector>
#include <gromox/endian.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>
#include <cstdlib>
#include <cstring>

namespace {
struct RANGE_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t low_value;
	uint64_t high_value;
};

struct REPLID_NODE {
	DOUBLE_LIST_NODE node;
	uint16_t replid;
	DOUBLE_LIST range_list; /* GLOBSET */
};

struct REPLGUID_NODE {
	DOUBLE_LIST_NODE node;
	GUID replguid;
	DOUBLE_LIST range_list; /* GLOBSET */
};

struct STACK_NODE {
	STACK_NODE(const uint8_t *b, uint8_t l) noexcept : common_length(l)
		{ memcpy(pcommon_bytes, b, common_length); }
	uint8_t common_length;
	uint8_t pcommon_bytes[6];
};
using byte_stack = std::vector<STACK_NODE>;
}

idset::idset(bool ser, uint8_t type) :
	b_serialize(ser), repl_type(type)
{
	double_list_init(&repl_list);
}

std::unique_ptr<idset> idset::create(bool ser, uint8_t type) try
{
	return std::make_unique<idset>(ser, type);
} catch (const std::bad_alloc &) {
	return nullptr;
}

BOOL idset::register_mapping(BINARY *pparam, REPLICA_MAPPING mapping)
{
	auto pset = this;
	if (NULL != pset->pparam ||
		NULL != pset->mapping) {
		return FALSE;
	}
	if (NULL == pparam) {
		pset->pparam = NULL;
	} else if (pparam->cb == 0) {
		pset->pparam = NULL;
	} else {
		pset->pparam = malloc(pparam->cb);
		if (NULL == pset->pparam) {
			return FALSE;
		}
		memcpy(pset->pparam, pparam->pb, pparam->cb);
	}
	pset->mapping = mapping;
	return TRUE;
}

void idset::clear()
{
	auto pset = this;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	while ((pnode = double_list_pop_front(&pset->repl_list)) != nullptr) {
		auto plist = !pset->b_serialize && pset->repl_type == REPL_TYPE_GUID ?
		        &static_cast<REPLGUID_NODE *>(pnode->pdata)->range_list :
		        &static_cast<REPLID_NODE *>(pnode->pdata)->range_list;
		while ((pnode1 = double_list_pop_front(plist)) != nullptr)
			free(pnode1->pdata);
		double_list_free(plist);
		free(pnode->pdata);
	}
}

idset::~idset()
{
	auto pset = this;
	pset->clear();
	double_list_free(&pset->repl_list);
	if (NULL != pset->pparam) {
		free(pset->pparam);
	}
}

BOOL idset::check_empty() const
{
	auto pset = this;
	if (0 == double_list_get_nodes_num(&pset->repl_list)) {
		return TRUE;
	}
	return FALSE;
}

static BOOL idset_append_internal(IDSET *pset,
	uint16_t replid, uint64_t value)
{
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (!pset->b_serialize)
		return FALSE;
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		if (replid == prepl_node->replid) {
			break;
		}
	}
	if (NULL == pnode) {
		prepl_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
		if (NULL == prepl_node) {
			return FALSE;
		}
		prepl_node->node.pdata = prepl_node;
		prepl_node->replid = replid;
		double_list_init(&prepl_node->range_list);
		double_list_append_as_tail(&pset->repl_list, &prepl_node->node);
	}
	for (auto pnode = double_list_get_head(&prepl_node->range_list); pnode != nullptr;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		auto prange_node = static_cast<RANGE_NODE *>(pnode->pdata);
		if (value >= prange_node->low_value &&
			value <= prange_node->high_value) {
			return TRUE;
		} else if (value == prange_node->low_value - 1) {
			prange_node->low_value = value;
			pnode = double_list_get_before(&prepl_node->range_list, pnode);
			if (NULL != pnode) {
				auto prange_node1 = static_cast<RANGE_NODE *>(pnode->pdata);
				if (prange_node1->high_value >= prange_node->low_value) {
					prange_node->low_value = prange_node1->low_value;
					double_list_remove(&prepl_node->range_list, pnode);
					free(prange_node1);
				}
			}
			return TRUE;
		} else if (value == prange_node->high_value + 1) {
			prange_node->high_value = value;
			pnode = double_list_get_after(&prepl_node->range_list, pnode);
			if (NULL != pnode) {
				auto prange_node1 = static_cast<RANGE_NODE *>(pnode->pdata);
				if (prange_node1->low_value <= prange_node->high_value) {
					prange_node->high_value = prange_node1->high_value;
					double_list_remove(&prepl_node->range_list, pnode);
					free(prange_node1);
				}
			}
			return TRUE;
		} else if (prange_node->low_value > value) {
			break;
		}
	}
	auto prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
	if (NULL == prange_node) {
		return FALSE;
	}
	prange_node->node.pdata = prange_node;
	prange_node->low_value = value;
	prange_node->high_value = value;
	if (NULL != pnode) {
		double_list_insert_before(&prepl_node->range_list,
			pnode, &prange_node->node);
	} else {
		double_list_append_as_tail(&prepl_node->range_list,
			&prange_node->node);
	}
	return TRUE;
}

BOOL idset::append(uint64_t eid)
{
	return idset_append_internal(this, rop_util_get_replid(eid),
	       rop_util_get_gc_value(eid));
}

BOOL idset::append_range(uint16_t replid, uint64_t low_value, uint64_t high_value)
{
	auto pset = this;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (!pset->b_serialize)
		return FALSE;
	if (low_value > high_value) {
		return FALSE;
	}
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		if (replid == prepl_node->replid) {
			break;
		}
	}
	if (NULL == pnode) {
		prepl_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
		if (NULL == prepl_node) {
			return FALSE;
		}
		prepl_node->node.pdata = prepl_node;
		prepl_node->replid = replid;
		double_list_init(&prepl_node->range_list);
		double_list_append_as_tail(&pset->repl_list, &prepl_node->node);
	}
	RANGE_NODE *prange_node1 = nullptr;
	for (pnode=double_list_get_head(&prepl_node->range_list); NULL!=pnode;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		auto pnode1 = double_list_get_after(&prepl_node->range_list, pnode);
		auto prange_node = static_cast<RANGE_NODE *>(pnode->pdata);
		if (NULL == prange_node1) {
			if (low_value == prange_node->high_value) {
				prange_node1 = prange_node;
				prange_node1->high_value = high_value;
			} else if (low_value > prange_node->high_value && (NULL == pnode1
			    || high_value <= ((RANGE_NODE *)pnode1->pdata)->low_value)) {
				prange_node1 = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
				if (NULL == prange_node1) {
					return FALSE;
				}
				prange_node1->node.pdata = prange_node1;
				prange_node1->low_value = low_value;
				prange_node1->high_value = high_value;
				double_list_append_after(&prepl_node->range_list,
					pnode, &prange_node1->node);
				pnode = &prange_node1->node;
			}
			continue;
		}
		if (high_value == prange_node->low_value) {
			prange_node1->high_value = prange_node->high_value;
			double_list_remove(&prepl_node->range_list, pnode);
			free(prange_node);
			return TRUE;
		} else if (high_value < prange_node->low_value) {
			return TRUE;
		}
		pnode = double_list_get_after(&prepl_node->range_list, pnode);
		double_list_remove(&prepl_node->range_list, &prange_node->node);
		free(prange_node);
		if (NULL == pnode) {
			return TRUE;
		}
	}
	if (NULL != prange_node1) {
		return TRUE;
	}
	auto prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
	if (NULL == prange_node) {
		return FALSE;
	}
	prange_node->node.pdata = prange_node;
	prange_node->low_value = low_value;
	prange_node->high_value = high_value;
	double_list_append_as_tail(&prepl_node->range_list, &prange_node->node);
	return TRUE;
}

void idset::remove(uint64_t eid)
{
	auto pset = this;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (!pset->b_serialize)
		return;
	auto replid = rop_util_get_replid(eid);
	auto value = rop_util_get_gc_value(eid);
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		if (replid == prepl_node->replid) {
			break;
		}
	}
	if (NULL == pnode) {
		return;
	}
	for (pnode=double_list_get_head(&prepl_node->range_list); NULL!=pnode;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		auto prange_node = static_cast<RANGE_NODE *>(pnode->pdata);
		if (value == prange_node->low_value &&
			value == prange_node->high_value) {
			double_list_remove(&prepl_node->range_list, pnode);
			free(prange_node);
			return;
		} else if (value == prange_node->low_value) {
			prange_node->low_value ++;
			return;
		} else if (value == prange_node->high_value) {
			prange_node->high_value --;
			return;
		} else if (value > prange_node->low_value &&
			value < prange_node->high_value) {
			auto prange_node1 = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node1) {
				return;
			}
			prange_node1->node.pdata = prange_node1;
			prange_node1->low_value = prange_node->low_value;
			prange_node->low_value = value + 1;
			prange_node1->high_value = value - 1;
			double_list_append_after(&prepl_node->range_list,
								pnode, &prange_node1->node);
			return;
		}
	}
}

BOOL idset::concatenate(const IDSET *pset_src)
{
	auto pset_dst = this;
	
	if (!pset_dst->b_serialize || !pset_src->b_serialize)
		return FALSE;
	auto prepl_list = static_cast<const DOUBLE_LIST *>(&pset_src->repl_list);
	for (auto pnode = double_list_get_head(prepl_list); pnode != nullptr;
		pnode=double_list_get_after(prepl_list, pnode)) {
		auto prepl_node = static_cast<const REPLID_NODE *>(pnode->pdata);
		for (auto pnode1 = double_list_get_head(&prepl_node->range_list); pnode1 != nullptr;
			pnode1=double_list_get_after(&prepl_node->range_list, pnode1)) {
			auto prange_node = static_cast<const RANGE_NODE *>(pnode1->pdata);
			if (prange_node->high_value == prange_node->low_value) {
				if (FALSE == idset_append_internal(pset_dst,
					prepl_node->replid, prange_node->low_value)) {
					return FALSE;	
				}
			} else {
				if (!append_range(prepl_node->replid,
				    prange_node->low_value, prange_node->high_value))
					return FALSE;	
			}
		}
	}
	return TRUE;
}

BOOL idset::hint(uint64_t eid)
{
	auto pset = this;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (!pset->b_serialize && pset->repl_type == REPL_TYPE_GUID)
		return FALSE;	
	auto replid = rop_util_get_replid(eid);
	auto value = rop_util_get_gc_value(eid);
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		if (replid == prepl_node->replid) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	for (pnode=double_list_get_head(&prepl_node->range_list); NULL!=pnode;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		auto prange_node = static_cast<RANGE_NODE *>(pnode->pdata);
		if (value >= prange_node->low_value &&
			value <= prange_node->high_value) {
			return TRUE;
		}
	}
	return FALSE;
}

static BINARY* idset_init_binary()
{
	auto pbin = static_cast<BINARY *>(malloc(sizeof(BINARY)));
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = 0;
	pbin->pv = malloc(4096);
	if (pbin->pv == nullptr) {
		free(pbin);
		return NULL;
	}
	return pbin;
}

static BOOL idset_write_to_binary(BINARY *pbin, const void *pb, uint8_t len)
{
	uint32_t alloc_len = strange_roundup(pbin->cb, 4096);
	if (pbin->cb + len >= alloc_len) {
		alloc_len = strange_roundup(pbin->cb + len, 4096);
		auto pdata = realloc(pbin->pb, alloc_len);
		if (NULL == pdata) {
			return FALSE;
		}
		pbin->pv = pdata;
	}
	memcpy(pbin->pb + pbin->cb, pb, len);
	pbin->cb += len;
	return TRUE;
}

static BOOL idset_encoding_push_command(BINARY *pbin,
    uint8_t length, const uint8_t *pcommon_bytes)
{
	if (length > 6) {
		return FALSE;
	}
	if (FALSE == idset_write_to_binary(pbin, &length, sizeof(uint8_t))) {
		return FALSE;
	}
	return idset_write_to_binary(pbin, pcommon_bytes, length);
}

static BOOL idset_encoding_pop_command(BINARY *pbin)
{
	uint8_t command = 0x50;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t));
}


static BOOL idset_encode_range_command(BINARY *pbin, uint8_t length,
    const uint8_t *plow_bytes, const uint8_t *phigh_bytes)
{
	if (length > 6 || 0 == length) {
		return FALSE;
	}
	uint8_t command = 0x52;
	if (FALSE == idset_write_to_binary(pbin, &command, sizeof(uint8_t))) {
		return FALSE;
	}
	if (FALSE == idset_write_to_binary(pbin, plow_bytes, length)) {
		return FALSE;
	}
	return idset_write_to_binary(pbin, phigh_bytes, length);
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

static BOOL idset_encoding_globset(BINARY *pbin, const DOUBLE_LIST *pglobset)
{
	if (1 == double_list_get_nodes_num(pglobset)) {
		auto pnode = double_list_get_head(pglobset);
		auto prange_node = static_cast<const RANGE_NODE *>(pnode->pdata);
		auto common_bytes = rop_util_value_to_gc(prange_node->low_value);
		if (prange_node->high_value == prange_node->low_value) {
			if (!idset_encoding_push_command(pbin, 6, common_bytes.ab))
				return FALSE;
		} else {
			auto common_bytes1 = rop_util_value_to_gc(prange_node->high_value);
			if (!idset_encode_range_command(pbin, 6,
			    common_bytes.ab, common_bytes1.ab))
				return FALSE;
		}
		return idset_encode_end_command(pbin);
	}
	auto pnode = double_list_get_head(pglobset);
	auto low_value = reinterpret_cast<const RANGE_NODE *>(pnode)->low_value;
	pnode = double_list_get_tail(pglobset);
	auto high_value = reinterpret_cast<const RANGE_NODE *>(pnode)->high_value;
	auto common_bytes = rop_util_value_to_gc(low_value);
	auto common_bytes1 = rop_util_value_to_gc(high_value);
	uint8_t stack_length;
	for (stack_length=0; stack_length<6; stack_length++) {
		if (common_bytes.ab[stack_length] != common_bytes1.ab[stack_length])
			break;
	}
	if (stack_length != 0 &&
	    !idset_encoding_push_command(pbin, stack_length, common_bytes.ab))
		return FALSE;
	for (pnode=double_list_get_head(pglobset); NULL!=pnode;
		pnode=double_list_get_after(pglobset, pnode)) {
		auto prange_node = static_cast<const RANGE_NODE *>(pnode->pdata);
		common_bytes = rop_util_value_to_gc(prange_node->low_value);
		if (prange_node->high_value == prange_node->low_value) {
			if (!idset_encoding_push_command(pbin,
			    6 - stack_length, &common_bytes.ab[stack_length]))
				return FALSE;
			continue;
		}
		common_bytes1 = rop_util_value_to_gc(prange_node->high_value);
		int i;
		for (i=stack_length; i<6; i++) {
			if (common_bytes.ab[i] != common_bytes1.ab[i])
				break;
		}
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
	if (FALSE == idset_write_uint32(pbin, pguid->time_low)) {
		return FALSE;
	}
	if (FALSE == idset_write_uint16(pbin, pguid->time_mid)) {
		return FALSE;
	}
	if (FALSE == idset_write_uint16(pbin, pguid->time_hi_and_version)) {
		return FALSE;
	}
	if (FALSE == idset_write_to_binary(pbin, pguid->clock_seq, 2)) {
		return FALSE;
	}
	if (FALSE == idset_write_to_binary(pbin, pguid->node, 6)) {
		return FALSE;
	}
	return TRUE;
}

BINARY *idset::serialize_replid() const
{
	auto pset = this;
	
	if (!pset->b_serialize)
		return NULL;
	auto pbin = idset_init_binary();
	if (NULL == pbin) {
		return NULL;
	}
	for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		auto prepl_node = static_cast<const REPLID_NODE *>(pnode->pdata);
		if (0 == double_list_get_nodes_num(&prepl_node->range_list)) {
			continue;
		}
		if (FALSE == idset_write_uint16(pbin, prepl_node->replid)) {
			rop_util_free_binary(pbin);
			return NULL;
		}
		if (FALSE == idset_encoding_globset(pbin, &prepl_node->range_list)) {
			rop_util_free_binary(pbin);
			return NULL;
		}
	}
	return pbin;
}

BINARY *idset::serialize_replguid() const
{
	auto pset = this;
	GUID tmp_guid;
	
	if (!pset->b_serialize)
		return NULL;
	if (NULL == pset->mapping) {
		return NULL;
	}
	auto pbin = idset_init_binary();
	if (NULL == pbin) {
		return NULL;
	}
	for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		auto prepl_node = static_cast<REPLID_NODE *>(pnode->pdata);
		if (0 == double_list_get_nodes_num(&prepl_node->range_list)) {
			continue;
		}
		if (FALSE == pset->mapping(TRUE, pset->pparam,
			&prepl_node->replid, &tmp_guid)) {
			rop_util_free_binary(pbin);
			return NULL;
		}
		if (FALSE == idset_write_guid(pbin, &tmp_guid)) {
			rop_util_free_binary(pbin);
			return NULL;
		}
		if (FALSE == idset_encoding_globset(pbin, &prepl_node->range_list)) {
			rop_util_free_binary(pbin);
			return NULL;
		}
	}
	return pbin;
}

BINARY *idset::serialize() const
{
	return repl_type == REPL_TYPE_ID ? serialize_replid() : serialize_replguid();
}

static uint32_t idset_decoding_globset(const BINARY *pbin,
    DOUBLE_LIST *pglobset) try
{
	uint32_t offset = 0;
	byte_stack bytes_stack;
	bytes_stack.reserve(6);
	
	while (offset < pbin->cb) {
		uint8_t command = pbin->pb[offset];
		offset ++;
		switch (command) {
		case 0x0: /* end */
			return offset;
		case 0x1:
		case 0x2:
		case 0x3:
		case 0x4:
		case 0x5:
		case 0x6: { /* push */
			GLOBCNT common_bytes;
			memcpy(common_bytes.ab, &pbin->pb[offset], command);
			offset += command;
			bytes_stack.emplace_back(common_bytes.ab, command);
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (stack_length > 6) {
				debug_info("[idset]: length of common bytes in"
					" stack is too long when deserializing");
				return 0;
			}
			if (stack_length != 6)
				break;
			auto prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node) {
				return 0;
			}
			prange_node->node.pdata = prange_node;
			prange_node->low_value = rop_util_gc_to_value(common_bytes);
			prange_node->high_value = prange_node->low_value;
			double_list_append_as_tail(pglobset, &prange_node->node);
			/* MS-OXCFXICS 3.1.5.4.3.1.1 */
			/* pop the stack without pop command */
			if (bytes_stack.size() > 0)
				bytes_stack.pop_back();
			break;
		}
		case 0x42: { /* bitmask */
			GLOBCNT common_bytes;
			uint8_t start_value = pbin->pb[offset++];
			uint8_t bitmask = pbin->pb[offset++];
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (5 != stack_length) {
				debug_info("[idset]: bitmask command error when "
					"deserializing, length of common bytes in "
					"stack should be 5");
				return 0;
			}
			auto prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node) {
				return 0;
			}
			prange_node->node.pdata = prange_node;
			common_bytes.ab[5] = start_value;
			auto low_value = rop_util_gc_to_value(common_bytes);
			prange_node->low_value = low_value;
			prange_node->high_value = low_value;
			for (int i = 0; i < 8; ++i) {
				if (!(bitmask & (1U << i))) {
					if (NULL != prange_node) {
						double_list_append_as_tail(
							pglobset, &prange_node->node);
						prange_node = NULL;
					}
				} else if (prange_node == nullptr) {
					prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
					if (NULL == prange_node) {
						return 0;
					}
					prange_node->node.pdata = prange_node;
					prange_node->low_value = low_value + i + 1;
					prange_node->high_value = prange_node->low_value;
				} else {
					prange_node->high_value ++;
				}
			}
			if (NULL != prange_node) {
				double_list_append_as_tail(pglobset, &prange_node->node);
			}
			break;
		}
		case 0x50: /* pop */
			if (bytes_stack.size() > 0)
				bytes_stack.pop_back();
			break;
		case 0x52: { /* range */
			GLOBCNT common_bytes;
			auto prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node) {
				return 0;
			}
			prange_node->node.pdata = prange_node;
			auto stack_length = idset_stack_get_common_bytes(bytes_stack, common_bytes);
			if (stack_length > 5) {
				debug_info("[idset]: range command error when "
					"deserializing, length of common bytes in "
					"stack should be less than 5");
				return 0;
			}
			memcpy(&common_bytes.ab[stack_length],
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			prange_node->low_value = rop_util_gc_to_value(common_bytes);
			memcpy(&common_bytes.ab[stack_length],
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			prange_node->high_value = rop_util_gc_to_value(common_bytes);
			double_list_append_as_tail(pglobset, &prange_node->node);
			break;
		}
		}
	}
	return 0;
} catch (const std::bad_alloc &) {
	fprintf(stderr, "E-1618: ENOMEM\n");
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

BOOL idset::deserialize(const BINARY *pbin)
{
	auto pset = this;
	uint32_t offset = 0;
	
	if (pset->b_serialize)
		return FALSE;
	while (offset < pbin->cb) {
		DOUBLE_LIST *plist;
		DOUBLE_LIST_NODE *pnode;

		if (REPL_TYPE_ID == pset->repl_type) {
			auto preplid_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
			if (NULL == preplid_node) {
				return FALSE;
			}
			preplid_node->node.pdata = preplid_node;
			preplid_node->replid = le16p_to_cpu(&pbin->pb[offset]);
			offset += sizeof(uint16_t);
			plist = &preplid_node->range_list;
			pnode = &preplid_node->node;
		} else {
			auto preplguid_node = static_cast<REPLGUID_NODE *>(malloc(sizeof(REPLGUID_NODE)));
			if (NULL == preplguid_node) {
				return FALSE;
			}
			preplguid_node->node.pdata = preplguid_node;
			idset_read_guid(pbin->pb, offset, &preplguid_node->replguid);
			offset += 16;
			plist = &preplguid_node->range_list;
			pnode = &preplguid_node->node;
		}
		if (offset >= pbin->cb) {
			free(pnode->pdata);
			return FALSE;
		}
		BINARY bin1;
		bin1.pb = pbin->pb + offset;
		bin1.cb = pbin->cb - offset;
		double_list_init(plist);
		uint32_t length = idset_decoding_globset(&bin1, plist);
		double_list_append_as_tail(&pset->repl_list, pnode);
		if (0 == length) {
			return FALSE;
		}
		offset += length;
	}
	return TRUE;
}

BOOL idset::convert()
{
	auto pset = this;
	DOUBLE_LIST temp_list;
	
	if (pset->b_serialize)
		return FALSE;
	if (REPL_TYPE_GUID == pset->repl_type) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		double_list_init(&temp_list);
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto preplguid_node  = static_cast<REPLGUID_NODE *>(pnode->pdata);
			uint16_t replid;
			if (FALSE == pset->mapping(FALSE, pset->pparam,
				&replid, &preplguid_node->replguid)) {
				goto CLEAN_TEMP_LIST;
			}
			auto prepl_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
			if (NULL == prepl_node) {
				goto CLEAN_TEMP_LIST;
			}
			prepl_node->node.pdata = prepl_node;
			prepl_node->replid = replid;
			prepl_node->range_list = preplguid_node->range_list;
			double_list_append_as_tail(&temp_list, &prepl_node->node);
		}
		DOUBLE_LIST_NODE *pnode;
		while ((pnode = double_list_pop_front(&pset->repl_list)) != nullptr)
			free(pnode->pdata);
		double_list_free(&pset->repl_list);
		pset->repl_list = temp_list;
	}
	pset->b_serialize = true;
	return TRUE;
	
 CLEAN_TEMP_LIST:
	DOUBLE_LIST_NODE *pnode;
	while ((pnode = double_list_pop_front(&temp_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&temp_list);
	return FALSE;
}

BOOL idset::get_repl_first_max(uint16_t replid, uint64_t *peid)
{
	auto pset = this;
	DOUBLE_LIST *prange_list = nullptr;
	
	if (!pset->b_serialize && pset->repl_type == REPL_TYPE_GUID) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto preplguid_node = static_cast<REPLGUID_NODE *>(pnode->pdata);
			uint16_t tmp_replid;
			if (FALSE == pset->mapping(FALSE, pset->pparam,
				&tmp_replid, &preplguid_node->replguid)) {
				return FALSE;
			}
			if (tmp_replid == replid) {
				prange_list = &preplguid_node->range_list;
				break;
			}
		}
	} else {
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto prepl_node = static_cast<REPLID_NODE *>(pnode->pdata);
			if (replid == prepl_node->replid) {
				prange_list = &prepl_node->range_list;
				break;
			}
		}
	}
	if (NULL == prange_list) {
		*peid = rop_util_make_eid_ex(replid, 0);
		return TRUE;
	}
	auto pnode = double_list_get_head(prange_list);
	if (NULL == pnode) {
		*peid = rop_util_make_eid_ex(replid, 0);
	} else {
		*peid = rop_util_make_eid_ex(replid,
			((RANGE_NODE*)pnode->pdata)->high_value);
	}
	return TRUE;
}

BOOL idset::enum_replist(void *pparam, REPLIST_ENUM replist_enum)
{
	auto pset = this;
	
	if (pset->b_serialize || pset->repl_type != REPL_TYPE_GUID) {
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto prepl_node = static_cast<REPLID_NODE *>(pnode->pdata);
			replist_enum(pparam, prepl_node->replid);
		}
		return TRUE;
	}
	if (NULL == pset->mapping) {
		return FALSE;
	}
	for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		auto preplguid_node = static_cast<REPLGUID_NODE *>(pnode->pdata);
		uint16_t tmp_replid;
		if (FALSE == pset->mapping(FALSE, pset->pparam,
		    &tmp_replid, &preplguid_node->replguid)) {
			return FALSE;
		}
		replist_enum(pparam, tmp_replid);
	}
	return TRUE;
}

BOOL idset::enum_repl(uint16_t replid, void *pparam, REPLICA_ENUM repl_enum)
{
	auto pset = this;
	DOUBLE_LIST *prange_list = nullptr;
	
	if (!pset->b_serialize && pset->repl_type == REPL_TYPE_GUID) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto preplguid_node = static_cast<REPLGUID_NODE *>(pnode->pdata);
			uint16_t tmp_replid;
			if (FALSE == pset->mapping(FALSE, pset->pparam,
				&tmp_replid, &preplguid_node->replguid)) {
				return FALSE;
			}
			if (tmp_replid == replid) {
				prange_list = &preplguid_node->range_list;
				break;
			}
		}
	} else {
		for (auto pnode = double_list_get_head(&pset->repl_list); pnode != nullptr;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			auto prepl_node = static_cast<REPLID_NODE *>(pnode->pdata);
			if (replid == prepl_node->replid) {
				prange_list = &prepl_node->range_list;
				break;
			}
		}
	}
	if (NULL == prange_list) {
		return TRUE;
	}
	for (auto pnode = double_list_get_head(prange_list); pnode != nullptr;
		pnode=double_list_get_after(prange_list, pnode)) {
		auto prange_node = static_cast<RANGE_NODE *>(pnode->pdata);
		for (auto ival = prange_node->low_value;
			ival<=prange_node->high_value; ival++) {
			auto tmp_eid = rop_util_make_eid_ex(replid, ival);
			repl_enum(pparam, tmp_eid);
		}
	}
	return TRUE;
}

// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/util.hpp>
#include <gromox/idset.hpp>
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
	DOUBLE_LIST_NODE node;
	uint8_t common_length;
	uint8_t *pcommon_bytes;
};
}

IDSET* idset_init(BOOL b_serialize, uint8_t repl_type)
{
	auto pset = static_cast<IDSET *>(malloc(sizeof(IDSET)));
	if (NULL == pset) {
		return NULL;
	}
	pset->pparam = NULL;
	pset->mapping = NULL;
	pset->b_serialize = b_serialize;
	pset->repl_type = repl_type;
	double_list_init(&pset->repl_list);
	return pset;
}

BOOL idset_register_mapping(IDSET *pset,
	BINARY *pparam, REPLICA_MAPPING mapping)
{
	if (NULL != pset->pparam ||
		NULL != pset->mapping) {
		return FALSE;
	}
	if (NULL == pparam) {
		pset->pparam = NULL;
	} else {
		if (0 == pparam->cb) {
			pset->pparam = NULL;
		} else {
			pset->pparam = malloc(pparam->cb);
			if (NULL == pset->pparam) {
				return FALSE;
			}
			memcpy(pset->pparam, pparam->pb, pparam->cb);
		}
	}
	pset->mapping = mapping;
	return TRUE;
}

void idset_clear(IDSET *pset)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	while ((pnode = double_list_pop_front(&pset->repl_list)) != nullptr) {
		if (FALSE == pset->b_serialize &&
			REPL_TYPE_GUID == pset->repl_type) {
			plist = &((REPLGUID_NODE*)pnode->pdata)->range_list;
		} else {
			plist = &((REPLID_NODE*)pnode->pdata)->range_list;
		}
		while ((pnode1 = double_list_pop_front(plist)) != nullptr)
			free(pnode1->pdata);
		double_list_free(plist);
		free(pnode->pdata);
	}
}

void idset_free(IDSET *pset)
{
	idset_clear(pset);
	double_list_free(&pset->repl_list);
	if (NULL != pset->pparam) {
		free(pset->pparam);
	}
	free(pset);
}

BOOL idset_check_empty(IDSET *pset)
{
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
	RANGE_NODE *prange_node;
	RANGE_NODE *prange_node1;
	
	if (FALSE == pset->b_serialize) {
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
	for (pnode=double_list_get_head(&prepl_node->range_list); NULL!=pnode;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		prange_node = (RANGE_NODE*)pnode->pdata;
		if (value >= prange_node->low_value &&
			value <= prange_node->high_value) {
			return TRUE;
		} else if (value == prange_node->low_value - 1) {
			prange_node->low_value = value;
			pnode = double_list_get_before(&prepl_node->range_list, pnode);
			if (NULL != pnode) {
				prange_node1 = (RANGE_NODE*)pnode->pdata;
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
				prange_node1 = (RANGE_NODE*)pnode->pdata;
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
	prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
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

BOOL idset_append(IDSET *pset, uint64_t eid)
{
	uint64_t value;
	uint16_t replid;
	
	replid = rop_util_get_replid(eid);
	value = rop_util_get_gc_value(eid);
	return idset_append_internal(pset, replid, value);
}

BOOL idset_append_range(IDSET *pset, uint16_t replid,
	uint64_t low_value, uint64_t high_value)
{
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	RANGE_NODE *prange_node;
	DOUBLE_LIST_NODE *pnode1;
	RANGE_NODE *prange_node1;
	
	if (FALSE == pset->b_serialize) {
		return FALSE;
	}
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
	prange_node1 = NULL;
	for (pnode=double_list_get_head(&prepl_node->range_list); NULL!=pnode;
		pnode=double_list_get_after(&prepl_node->range_list, pnode)) {
		pnode1 = double_list_get_after(&prepl_node->range_list, pnode);
		prange_node = (RANGE_NODE*)pnode->pdata;
		if (NULL == prange_node1) {
			if (low_value == prange_node->high_value) {
				prange_node1 = prange_node;
				prange_node1->high_value = high_value;
			} else if (low_value > prange_node->high_value && (NULL == pnode1
				|| high_value <= ((RANGE_NODE*)pnode1->pdata)->low_value)) {
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
		} else {
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
	}
	if (NULL != prange_node1) {
		return TRUE;
	}
	prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
	if (NULL == prange_node) {
		return FALSE;
	}
	prange_node->node.pdata = prange_node;
	prange_node->low_value = low_value;
	prange_node->high_value = high_value;
	double_list_append_as_tail(&prepl_node->range_list, &prange_node->node);
	return TRUE;
}

void idset_remove(IDSET *pset, uint64_t eid)
{
	uint64_t value;
	uint16_t replid;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	RANGE_NODE *prange_node;
	RANGE_NODE *prange_node1;
	
	if (FALSE == pset->b_serialize) {
		return;
	}
	replid = rop_util_get_replid(eid);
	value = rop_util_get_gc_value(eid);
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
		prange_node = (RANGE_NODE*)pnode->pdata;
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
			prange_node1 = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
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

BOOL idset_concatenate(IDSET *pset_dst, const IDSET *pset_src)
{
	DOUBLE_LIST *prepl_list;
	REPLID_NODE *prepl_node;
	RANGE_NODE *prange_node;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	if (FALSE == pset_dst->b_serialize ||
		FALSE == pset_src->b_serialize) {
		return FALSE;
	}
	prepl_list = (DOUBLE_LIST*)&pset_src->repl_list;
	for (pnode=double_list_get_head(prepl_list); NULL!=pnode;
		pnode=double_list_get_after(prepl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
		for (pnode1=double_list_get_head(&prepl_node->range_list); NULL!=pnode1;
			pnode1=double_list_get_after(&prepl_node->range_list, pnode1)) {
			prange_node = (RANGE_NODE*)pnode1->pdata;
			if (prange_node->high_value == prange_node->low_value) {
				if (FALSE == idset_append_internal(pset_dst,
					prepl_node->replid, prange_node->low_value)) {
					return FALSE;	
				}
			} else {
				if (FALSE == idset_append_range(pset_dst,
					prepl_node->replid, prange_node->low_value,
					prange_node->high_value)) {
					return FALSE;	
				}
			}
		}
	}
	return TRUE;
}

BOOL idset_hint(IDSET *pset, uint64_t eid)
{
	uint64_t value;
	uint16_t replid;
	RANGE_NODE *prange_node;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == pset->b_serialize &&
		REPL_TYPE_GUID == pset->repl_type) {
		return FALSE;	
	}
	replid = rop_util_get_replid(eid);
	value = rop_util_get_gc_value(eid);
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
		prange_node = (RANGE_NODE*)pnode->pdata;
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
	void *pdata;
	uint32_t alloc_len;
	
	alloc_len = (pbin->cb / 4096 + 1) * 4096;
	if (pbin->cb + len >= alloc_len) {
		alloc_len = ((pbin->cb + len) / 4096 + 1) * 4096;
		pdata = realloc(pbin->pb, alloc_len);
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
	uint8_t length, uint8_t *pcommon_bytes)
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
	uint8_t command;
	
	command = 0x50;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t));
}


static BOOL idset_encode_range_command(BINARY *pbin,
	uint8_t length, uint8_t *plow_bytes, uint8_t *phigh_bytes)
{
	uint8_t command;
	
	if (length > 6 || 0 == length) {
		return FALSE;
	}
	command = 0x52;
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
	uint8_t command;
	
	command = 0;
	return idset_write_to_binary(pbin, &command, sizeof(uint8_t));
}

static void idset_statck_init(DOUBLE_LIST *pstack)
{
	double_list_init(pstack);
}

static void idset_statck_free(DOUBLE_LIST *pstack)
{
	STACK_NODE *pstack_node;
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(pstack)) != nullptr) {
		pstack_node = (STACK_NODE*)pnode->pdata;
		free(pstack_node->pcommon_bytes);
		free(pstack_node);
	}
	double_list_free(pstack);
}

static BOOL idset_statck_push(DOUBLE_LIST *pstack,
	uint8_t common_length, uint8_t *pcommon_bytes)
{
	auto pstack_node = static_cast<STACK_NODE *>(malloc(sizeof(STACK_NODE)));
	if (NULL == pstack_node) {
		return FALSE;
	}
	pstack_node->node.pdata = pstack_node;
	pstack_node->common_length = common_length;
	pstack_node->pcommon_bytes = static_cast<uint8_t *>(malloc(common_length));
	if (NULL == pstack_node->pcommon_bytes) {
		free(pstack_node);
		return FALSE;
	}
	memcpy(pstack_node->pcommon_bytes, pcommon_bytes, common_length);
	double_list_append_as_tail(pstack, &pstack_node->node);
	return TRUE;
}	

static void idset_statck_pop(DOUBLE_LIST *pstack)
{
	auto pnode = double_list_pop_back(pstack);
	if (NULL == pnode) {
		return;
	}
	free(((STACK_NODE*)pnode->pdata)->pcommon_bytes);
	free(pnode->pdata);
}

static uint8_t idset_statck_get_common_bytes(
	DOUBLE_LIST *pstack, uint8_t common_bytes[6])
{
	uint8_t common_length;
	DOUBLE_LIST_NODE *pnode;
	STACK_NODE *pstack_node;
	
	common_length = 0;
	for (pnode=double_list_get_head(pstack); NULL!=pnode;
		pnode=double_list_get_after(pstack, pnode)) {
		pstack_node = (STACK_NODE*)pnode->pdata;
		memcpy(common_bytes + common_length,
			pstack_node->pcommon_bytes, pstack_node->common_length);
		common_length += pstack_node->common_length;
	}
	return common_length;
}

static BOOL idset_encoding_globset(BINARY *pbin, DOUBLE_LIST *pglobset)
{
	int i;
	uint64_t low_value;
	uint64_t high_value;
	uint8_t stack_length;
	RANGE_NODE *prange_node;
	DOUBLE_LIST_NODE *pnode;
	uint8_t common_bytes[6];
	uint8_t common_bytes1[6];
	
	if (1 == double_list_get_nodes_num(pglobset)) {
		pnode = double_list_get_head(pglobset);
		prange_node = (RANGE_NODE*)pnode->pdata;
		rop_util_value_to_gc(prange_node->low_value, common_bytes);
		if (prange_node->high_value == prange_node->low_value) {
			if (FALSE == idset_encoding_push_command(
				pbin, 6, common_bytes)) {
				return FALSE;
			}
		} else {
			rop_util_value_to_gc(prange_node->high_value, common_bytes1);
			if (FALSE == idset_encode_range_command(
				pbin, 6, common_bytes, common_bytes1)) {
				return FALSE;
			}
		}
		return idset_encode_end_command(pbin);
	} else {
		pnode = double_list_get_head(pglobset);
		low_value = ((RANGE_NODE*)pnode)->low_value;
		pnode = double_list_get_tail(pglobset);
		high_value = ((RANGE_NODE*)pnode)->high_value;
		rop_util_value_to_gc(low_value, common_bytes);
		rop_util_value_to_gc(high_value, common_bytes1);
		for (stack_length=0; stack_length<6; stack_length++) {
			if (common_bytes[stack_length] != common_bytes1[stack_length]) {
				break;
			}
		}
		if (0 != stack_length) {
			if (FALSE == idset_encoding_push_command(
				pbin, stack_length, common_bytes)) {
				return FALSE;
			}
		}
	}
	for (pnode=double_list_get_head(pglobset); NULL!=pnode;
		pnode=double_list_get_after(pglobset, pnode)) {
		prange_node = (RANGE_NODE*)pnode->pdata;
		rop_util_value_to_gc(prange_node->low_value, common_bytes);
		if (prange_node->high_value == prange_node->low_value) {
			if (FALSE == idset_encoding_push_command(pbin,
				6 - stack_length, common_bytes + stack_length)) {
				return FALSE;
			}
		} else {
			rop_util_value_to_gc(prange_node->high_value, common_bytes1);
			for (i=stack_length; i<6; i++) {
				if (common_bytes[i] != common_bytes1[i]) {
					break;
				}
			}
			if (stack_length != i) {
				if (FALSE == idset_encoding_push_command(pbin,
					i - stack_length, common_bytes + stack_length)) {
					return FALSE;
				}
			}
			if (FALSE == idset_encode_range_command(pbin, 6 - i,
				common_bytes + i, common_bytes1 + i)) {
				return FALSE;
			}
			if (stack_length != i) {
				if (FALSE == idset_encoding_pop_command(pbin)) {
					return FALSE;
				}
			}
		}
	}
	if (0 != stack_length) {
		if (FALSE == idset_encoding_pop_command(pbin)) {
			return FALSE;
		}
	}
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

BINARY* idset_serialize_replid(IDSET *pset)
{
	BINARY *pbin;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == pset->b_serialize) {
		return NULL;
	}
	pbin = idset_init_binary();
	if (NULL == pbin) {
		return NULL;
	}
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
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

BINARY* idset_serialize_replguid(IDSET *pset)
{
	BINARY *pbin;
	GUID tmp_guid;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (FALSE == pset->b_serialize) {
		return NULL;
	}
	if (NULL == pset->mapping) {
		return NULL;
	}
	pbin = idset_init_binary();
	if (NULL == pbin) {
		return NULL;
	}
	for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
		pnode=double_list_get_after(&pset->repl_list, pnode)) {
		prepl_node = (REPLID_NODE*)pnode->pdata;
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

BINARY* idset_serialize(IDSET *pset)
{
	if (REPL_TYPE_ID == pset->repl_type) {
		return idset_serialize_replid(pset);
	} else {
		return idset_serialize_replguid(pset);
	}
}

static uint32_t idset_decoding_globset(
	const BINARY *pbin, DOUBLE_LIST *pglobset)
{
	int i;
	uint8_t bitmask;
	uint32_t offset;
	uint8_t command;
	uint64_t low_value;
	uint8_t start_value;
	uint8_t stack_length;
	RANGE_NODE *prange_node;
	uint8_t common_bytes[6];
	DOUBLE_LIST bytes_statck;
	
	offset = 0;
	idset_statck_init(&bytes_statck);
	while (offset < pbin->cb) {
		command = pbin->pb[offset];
		offset ++;
		switch (command) {
		case 0x0: /* end */
			idset_statck_free(&bytes_statck);
			return offset;
		case 0x1:
		case 0x2:
		case 0x3:
		case 0x4:
		case 0x5:
		case 0x6: /* push */
			memcpy(common_bytes, pbin->pb + offset, command);
			offset += command;
			idset_statck_push(&bytes_statck, command, common_bytes);
			stack_length = idset_statck_get_common_bytes(
							&bytes_statck, common_bytes);
			if (6 == stack_length) {
				prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
				if (NULL == prange_node) {
					idset_statck_free(&bytes_statck);
					return 0;
				}
				prange_node->node.pdata = prange_node;
				prange_node->low_value = rop_util_gc_to_value(common_bytes);
				prange_node->high_value = prange_node->low_value;
				double_list_append_as_tail(pglobset, &prange_node->node);
				/* MS-OXCFXICS 3.1.5.4.3.1.1 */
				/* pop the stack without pop command */
				idset_statck_pop(&bytes_statck);
			} else if (stack_length > 6) {
				debug_info("[idset]: length of common bytes in"
					" stack is too long when deserializing");
				idset_statck_free(&bytes_statck);
				return 0;
			}
			break;
		case 0x42: /* bitmask */
			start_value = pbin->pb[offset];
			offset ++;
			bitmask = pbin->pb[offset];
			offset ++;
			stack_length = idset_statck_get_common_bytes(
							&bytes_statck, common_bytes);
			if (5 != stack_length) {
				debug_info("[idset]: bitmask command error when "
					"deserializing, length of common bytes in "
					"stack should be 5");
				idset_statck_free(&bytes_statck);
				return 0;
			}
			prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node) {
				idset_statck_free(&bytes_statck);
				return 0;
			}
			prange_node->node.pdata = prange_node;
			common_bytes[5] = start_value;
			low_value = rop_util_gc_to_value(common_bytes);
			prange_node->low_value = low_value;
			prange_node->high_value = low_value;
			for (i=0; i<8; i++) {
				if (bitmask & (1<<i)) {
					if (NULL == prange_node) {
						prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
						if (NULL == prange_node) {
							idset_statck_free(&bytes_statck);
							return 0;
						}
						prange_node->node.pdata = prange_node;
						prange_node->low_value = low_value + i + 1;
						prange_node->high_value = prange_node->low_value;
					} else {
						prange_node->high_value ++;
					}
				} else {
					if (NULL != prange_node) {
						double_list_append_as_tail(
							pglobset, &prange_node->node);
						prange_node = NULL;
					}
				}
			}
			if (NULL != prange_node) {
				double_list_append_as_tail(pglobset, &prange_node->node);
			}
			break;
		case 0x50: /* pop */
			idset_statck_pop(&bytes_statck);
			break;
		case 0x52: /* range */
			prange_node = static_cast<RANGE_NODE *>(malloc(sizeof(RANGE_NODE)));
			if (NULL == prange_node) {
				idset_statck_free(&bytes_statck);
				return 0;
			}
			prange_node->node.pdata = prange_node;
			stack_length = idset_statck_get_common_bytes(
							&bytes_statck, common_bytes);
			if (stack_length > 5) {
				debug_info("[idset]: range command error when "
					"deserializing, length of common bytes in "
					"stack should be less than 5");
				idset_statck_free(&bytes_statck);
				return 0;
			}
			memcpy(common_bytes + stack_length,
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			prange_node->low_value = rop_util_gc_to_value(common_bytes);
			memcpy(common_bytes + stack_length,
				pbin->pb + offset, 6 - stack_length);
			offset += 6 - stack_length;
			prange_node->high_value = rop_util_gc_to_value(common_bytes);
			double_list_append_as_tail(pglobset, &prange_node->node);
			break;
		}
	}
	idset_statck_free(&bytes_statck);
	return 0;
}

static void idset_read_guid(const void *pv, uint32_t offset, GUID *pguid)
{
	auto pb = static_cast<const uint8_t *>(pv);
	memcpy(&pguid->time_low, &pb[offset], sizeof(uint32_t));
	pguid->time_low = le32_to_cpu(pguid->time_low);
	offset += sizeof(uint32_t);
	memcpy(&pguid->time_mid, &pb[offset], sizeof(uint16_t));
	pguid->time_mid = le16_to_cpu(pguid->time_mid);
	offset += sizeof(uint16_t);
	memcpy(&pguid->time_hi_and_version, &pb[offset], sizeof(uint16_t));
	pguid->time_hi_and_version = le16_to_cpu(pguid->time_hi_and_version);
	offset += sizeof(uint16_t);
	memcpy(pguid->clock_seq, pb + offset, 2);
	offset += 2;
	memcpy(pguid->node, pb + offset, 6);
}

BOOL idset_deserialize(IDSET *pset, const BINARY *pbin)
{
	BINARY bin1;
	uint32_t offset;
	uint32_t length;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *preplid_node;
	REPLGUID_NODE *preplguid_node;
	
	if (TRUE == pset->b_serialize) {
		return FALSE;
	}
	offset = 0;
	while (offset < pbin->cb) {
		if (REPL_TYPE_ID == pset->repl_type) {
			preplid_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
			if (NULL == preplid_node) {
				return FALSE;
			}
			preplid_node->node.pdata = preplid_node;
			uint16_t enc2;
			memcpy(&enc2, &pbin->pb[offset], sizeof(enc2));
			preplid_node->replid = le16_to_cpu(enc2);
			offset += sizeof(uint16_t);
			plist = &preplid_node->range_list;
			pnode = &preplid_node->node;
		} else {
			preplguid_node = static_cast<REPLGUID_NODE *>(malloc(sizeof(REPLGUID_NODE)));
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
		bin1.pb = pbin->pb + offset;
		bin1.cb = pbin->cb - offset;
		double_list_init(plist);
		length = idset_decoding_globset(&bin1, plist);
		double_list_append_as_tail(&pset->repl_list, pnode);
		if (0 == length) {
			return FALSE;
		}
		offset += length;
	}
	return TRUE;
}

BOOL idset_convert(IDSET *pset)
{
	uint16_t replid;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *prepl_node;
	REPLGUID_NODE *preplguid_node;
	
	if (TRUE == pset->b_serialize) {
		return FALSE;
	}
	if (REPL_TYPE_GUID == pset->repl_type) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		double_list_init(&temp_list);
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			preplguid_node = (REPLGUID_NODE*)pnode->pdata;
			if (FALSE == pset->mapping(FALSE, pset->pparam,
				&replid, &preplguid_node->replguid)) {
				goto CLEAN_TEMP_LIST;
			}
			prepl_node = static_cast<REPLID_NODE *>(malloc(sizeof(REPLID_NODE)));
			if (NULL == prepl_node) {
				goto CLEAN_TEMP_LIST;
			}
			prepl_node->node.pdata = prepl_node;
			prepl_node->replid = replid;
			prepl_node->range_list = preplguid_node->range_list;
			double_list_append_as_tail(&temp_list, &prepl_node->node);
		}
		while ((pnode = double_list_pop_front(&pset->repl_list)) != nullptr)
			free(pnode->pdata);
		double_list_free(&pset->repl_list);
		pset->repl_list = temp_list;
	}
	pset->b_serialize = TRUE;
	return TRUE;
	
 CLEAN_TEMP_LIST:
	while ((pnode = double_list_pop_front(&temp_list)) != nullptr)
		free(pnode->pdata);
	double_list_free(&temp_list);
	return FALSE;
}

BOOL idset_get_repl_first_max(IDSET *pset,
	uint16_t replid, uint64_t *peid)
{
	uint16_t tmp_replid;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST *prange_list;
	REPLGUID_NODE *preplguid_node;
	
	prange_list = NULL;
	if (FALSE == pset->b_serialize &&
		REPL_TYPE_GUID == pset->repl_type) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			preplguid_node = (REPLGUID_NODE*)pnode->pdata;
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
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			prepl_node = (REPLID_NODE*)pnode->pdata;
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
	pnode = double_list_get_head(prange_list);
	if (NULL == pnode) {
		*peid = rop_util_make_eid_ex(replid, 0);
	} else {
		*peid = rop_util_make_eid_ex(replid,
			((RANGE_NODE*)pnode->pdata)->high_value);
	}
	return TRUE;
}

BOOL idset_enum_replist(IDSET *pset, void *pparam,
	REPLIST_ENUM replist_enum)
{
	uint16_t tmp_replid;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *prepl_node;
	REPLGUID_NODE *preplguid_node;
	
	if (FALSE == pset->b_serialize &&
		REPL_TYPE_GUID == pset->repl_type) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			preplguid_node = (REPLGUID_NODE*)pnode->pdata;
			if (FALSE == pset->mapping(FALSE, pset->pparam,
				&tmp_replid, &preplguid_node->replguid)) {
				return FALSE;
			}
			replist_enum(pparam, tmp_replid);
		}
	} else {
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			prepl_node = (REPLID_NODE*)pnode->pdata;
			replist_enum(pparam, prepl_node->replid);
		}
	}
	return TRUE;
}

BOOL idset_enum_repl(IDSET *pset, uint16_t replid,
	void *pparam, REPLICA_ENUM repl_enum)
{
	uint64_t ival;
	uint64_t tmp_eid;
	uint16_t tmp_replid;
	RANGE_NODE *prange_node;
	DOUBLE_LIST_NODE *pnode;
	REPLID_NODE *prepl_node;
	DOUBLE_LIST *prange_list;
	REPLGUID_NODE *preplguid_node;
	
	prange_list = NULL;
	if (FALSE == pset->b_serialize &&
		REPL_TYPE_GUID == pset->repl_type) {
		if (NULL == pset->mapping) {
			return FALSE;
		}
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			preplguid_node = (REPLGUID_NODE*)pnode->pdata;
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
		for (pnode=double_list_get_head(&pset->repl_list); NULL!=pnode;
			pnode=double_list_get_after(&pset->repl_list, pnode)) {
			prepl_node = (REPLID_NODE*)pnode->pdata;
			if (replid == prepl_node->replid) {
				prange_list = &prepl_node->range_list;
				break;
			}
		}
	}
	if (NULL == prange_list) {
		return TRUE;
	}
	for (pnode=double_list_get_head(prange_list); NULL!=pnode;
		pnode=double_list_get_after(prange_list, pnode)) {
		prange_node = (RANGE_NODE*)pnode->pdata;
		for (ival=prange_node->low_value;
			ival<=prange_node->high_value; ival++) {
			tmp_eid = rop_util_make_eid_ex(replid, ival);
			repl_enum(pparam, tmp_eid);
		}
	}
	return TRUE;
}

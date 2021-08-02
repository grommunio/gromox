// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/eid_array.hpp>
#include <cassert>
#include <cstdlib>
#include <cstring>

EID_ARRAY* eid_array_init()
{
	auto parray = static_cast<EID_ARRAY *>(malloc(sizeof(EID_ARRAY)));
	if (NULL == parray) {
		return NULL;
	}
	parray->count = 0;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	parray->pids = static_cast<uint64_t *>(malloc(count * sizeof(uint64_t)));
	if (NULL == parray->pids) {
		free(parray);
		return NULL;
	}
	return parray;
}

void eid_array_free(EID_ARRAY *parray)
{
	if (NULL != parray->pids) {
		free(parray->pids);
	}
	free(parray);
}

bool eid_array_append(EID_ARRAY *parray, uint64_t id)
{
	uint64_t *pids;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	if (parray->count + 1 >= count) {
		count += SR_GROW_EID_ARRAY;
		pids = static_cast<uint64_t *>(realloc(parray->pids, count * sizeof(uint64_t)));
		if (NULL == pids) {
			return false;
		}
		parray->pids = pids;
	}
	parray->pids[parray->count] = id;
	parray->count ++;
	return true;
}

bool eid_array_batch_append(EID_ARRAY *parray, uint32_t id_count, uint64_t *pids)
{
	uint64_t *ptmp_ids;
	
	if (0 == id_count) {
		return true;
	}
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	if (parray->count + id_count >= count) {
		count = strange_roundup(parray->count + id_count, SR_GROW_EID_ARRAY);
		ptmp_ids = static_cast<uint64_t *>(realloc(parray->pids, count * sizeof(uint64_t)));
		if (NULL == ptmp_ids) {
			return false;
		}
		parray->pids = ptmp_ids;
	}
	memcpy(parray->pids + parray->count, pids, id_count*sizeof(uint64_t));
	parray->count += id_count;
	return true;
}

EID_ARRAY* eid_array_dup(const EID_ARRAY *parray)
{
	auto parray1 = static_cast<EID_ARRAY *>(malloc(sizeof(EID_ARRAY)));
	if (NULL == parray1) {
		return NULL;
	}
	parray1->count = parray->count;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	parray1->pids = static_cast<uint64_t *>(malloc(count * sizeof(uint64_t)));
	if (NULL == parray1->pids) {
		free(parray1);
		return NULL;
	}
	assert(parray->pids != nullptr || parray->count == 0);
	if (parray->pids != nullptr)
		memcpy(parray1->pids, parray->pids, parray->count * sizeof(uint64_t));
	return parray1;
}

bool eid_array_check(const EID_ARRAY *parray, uint64_t eid)
{
	for (size_t i = 0; i < parray->count; ++i)
		if (eid == parray->pids[i]) {
			return true;
		}
	return false;
}

void eid_array_remove(EID_ARRAY *parray, uint64_t eid)
{
	for (size_t i = 0; i < parray->count; ) {
		if (parray->pids[i] == eid) {
			parray->count --;
			if (i != parray->count) {
				memmove(parray->pids + i, parray->pids + i + 1,
						sizeof(uint64_t)*(parray->count - i));
			}
			continue;
		}
		i ++;
	}
}


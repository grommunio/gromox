// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <gromox/eid_array.hpp>

using namespace gromox;

EID_ARRAY* eid_array_init()
{
	auto parray = me_alloc<EID_ARRAY>();
	if (parray == nullptr)
		return NULL;
	parray->count = 0;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	parray->pids = me_alloc<eid_t>(count);
	if (NULL == parray->pids) {
		free(parray);
		return NULL;
	}
	return parray;
}

/**
 * The caller should test for parray!=nullptr before calling this.
 */
void eid_array_free(EID_ARRAY *parray)
{
	free(parray->pids);
	free(parray);
}

bool eid_array_append(EID_ARRAY *parray, eid_t id)
{
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	if (parray->count + 1 >= count) {
		count += SR_GROW_EID_ARRAY;
		auto pids = re_alloc<eid_t>(parray->pids, count);
		if (pids == nullptr)
			return false;
		parray->pids = pids;
	}
	parray->pids[parray->count++] = id;
	return true;
}

bool eid_array_batch_append(EID_ARRAY *parray, uint32_t id_count, eid_t *pids)
{
	if (id_count == 0)
		return true;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	if (parray->count + id_count >= count) {
		count = strange_roundup(parray->count + id_count, SR_GROW_EID_ARRAY);
		auto ptmp_ids = re_alloc<eid_t>(parray->pids, count);
		if (ptmp_ids == nullptr)
			return false;
		parray->pids = ptmp_ids;
	}
	memcpy(&parray->pids[parray->count], pids, id_count * sizeof(eid_t));
	parray->count += id_count;
	return true;
}

EID_ARRAY* eid_array_dup(const EID_ARRAY *parray)
{
	auto parray1 = me_alloc<EID_ARRAY>();
	if (parray1 == nullptr)
		return NULL;
	parray1->count = parray->count;
	auto count = strange_roundup(parray->count, SR_GROW_EID_ARRAY);
	parray1->pids = me_alloc<eid_t>(count);
	if (NULL == parray1->pids) {
		free(parray1);
		return NULL;
	}
	assert(parray->pids != nullptr || parray->count == 0);
	if (parray->pids != nullptr)
		memcpy(parray1->pids, parray->pids, parray->count * sizeof(eid_t));
	return parray1;
}

bool eid_array_check(const EID_ARRAY *parray, eid_t eid)
{
	for (auto elem : *parray)
		if (eid == elem)
			return true;
	return false;
}

void eid_array_remove(EID_ARRAY *parray, eid_t eid)
{
	for (size_t i = 0; i < parray->count; ) {
		if (parray->pids[i] == eid) {
			parray->count --;
			if (i != parray->count)
				memmove(parray->pids + i, parray->pids + i + 1,
					sizeof(eid_t) * (parray->count - i));
			continue;
		}
		i ++;
	}
}

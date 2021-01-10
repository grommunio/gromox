// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/eid_array.hpp>
#include <cstdlib>
#include <cstring>

EID_ARRAY* eid_array_init()
{
	auto parray = static_cast<EID_ARRAY *>(malloc(sizeof(EID_ARRAY)));
	if (NULL == parray) {
		return NULL;
	}
	parray->count = 0;
	parray->pids = static_cast<uint64_t *>(malloc(100 * sizeof(uint64_t)));
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

BOOL eid_array_append(EID_ARRAY *parray, uint64_t id)
{
	uint64_t *pids;
	uint32_t count;
	
	count = (parray->count / 100 + 1) * 100;
	if (parray->count + 1 >= count) {
		count += 100;
		pids = static_cast<uint64_t *>(realloc(parray->pids, count * sizeof(uint64_t)));
		if (NULL == pids) {
			return FALSE;
		}
		parray->pids = pids;
	}
	parray->pids[parray->count] = id;
	parray->count ++;
	return TRUE;
}

BOOL eid_array_batch_append(EID_ARRAY *parray,
	uint32_t id_count, uint64_t *pids)
{
	uint32_t count;
	uint64_t *ptmp_ids;
	
	if (0 == id_count) {
		return TRUE;
	}
	count = (parray->count / 100 + 1) * 100;
	if (parray->count + id_count >= count) {
		for (; count<=parray->count+id_count; count+=100);
		ptmp_ids = static_cast<uint64_t *>(realloc(parray->pids, count * sizeof(uint64_t)));
		if (NULL == ptmp_ids) {
			return FALSE;
		}
		parray->pids = ptmp_ids;
	}
	memcpy(parray->pids + parray->count, pids, id_count*sizeof(uint64_t));
	parray->count += id_count;
	return TRUE;
}

EID_ARRAY* eid_array_dup(const EID_ARRAY *parray)
{
	uint32_t count;
	auto parray1 = static_cast<EID_ARRAY *>(malloc(sizeof(EID_ARRAY)));
	if (NULL == parray1) {
		return NULL;
	}
	parray1->count = parray->count;
	count = (parray->count / 100 + 1) * 100;
	parray1->pids = static_cast<uint64_t *>(malloc(count * sizeof(uint64_t)));
	if (NULL == parray1->pids) {
		free(parray1);
		return NULL;
	}
	memcpy(parray1->pids, parray->pids,
		parray->count*sizeof(uint64_t));
	return parray1;
}

BOOL eid_array_check(const EID_ARRAY *parray, uint64_t eid)
{
	int i;
	
	for (i=0; i<parray->count; i++) {
		if (eid == parray->pids[i]) {
			return TRUE;
		}
	}
	return FALSE;
}

void eid_array_remove(EID_ARRAY *parray, uint64_t eid)
{
	int i;
	
	i = 0;
	while (i < parray->count) {
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


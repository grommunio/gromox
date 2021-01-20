// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <cstdlib>
#include <cstring>

struct XID_NODE {
	DOUBLE_LIST_NODE node;
	SIZED_XID xid;
};

static void pcl_pull_xid(const BINARY *pbin,
	uint16_t offset, uint8_t size, XID *pxid)
{
	BINARY tmp_bin;
	
	tmp_bin.cb = pbin->cb - offset;
	tmp_bin.pb = pbin->pb + offset;
	pxid->guid = rop_util_binary_to_guid(&tmp_bin);
	memcpy(pxid->local_id, pbin->pb + offset + 16, size - 16);
}

static void pcl_push_xid(BINARY *pbin, uint8_t size, const XID *pxid)
{
	rop_util_guid_to_binary(pxid->guid, pbin);
	memcpy(pbin->pb + pbin->cb, pxid->local_id, size - 16);
	pbin->cb += size - 16;
}

static uint8_t pcl_pull_sized_xid(const BINARY *pbin,
	uint16_t offset, SIZED_XID *pxid)
{	
	if (pbin->cb <= offset) {
		return 0;
	}
	pxid->size = pbin->pb[offset];
	if (pxid->size < 17 || pxid->size > 24 ||
		offset + 1 + pxid->size > pbin->cb) {
		return 0;
	}
	pcl_pull_xid(pbin, offset + 1, pxid->size, &pxid->xid);
	return pxid->size + 1;
}

static void pcl_push_sized_xid(BINARY *pbin, const SIZED_XID *pxid)
{
	pbin->pb[pbin->cb] = pxid->size;
	pbin->cb ++;
	pcl_push_xid(pbin, pxid->size, &pxid->xid);
}

PCL* pcl_init()
{
	auto ppcl = static_cast<PCL *>(malloc(sizeof(PCL)));
	if (NULL == ppcl) {
		return NULL;
	}
	double_list_init(ppcl);
	return ppcl;
}

void pcl_free(PCL *ppcl)
{
	DOUBLE_LIST_NODE *pnode;
	
	while ((pnode = double_list_pop_front(ppcl)) != nullptr)
		free(pnode->pdata);
	double_list_free(ppcl);
	free(ppcl);
}

static uint64_t pcl_convert_local_id(const SIZED_XID *pxid)
{
	uint8_t i;
	uint64_t ret_val;
	
	ret_val = 0;
	for (i=0; i<pxid->size - 16; i++) {
		ret_val |= (uint64_t)pxid->xid.local_id[i] << 
					(pxid->size - 16 - 1 - i) * 8;
	}
	return ret_val;
}

BOOL pcl_append(PCL *ppcl, const SIZED_XID *pxid)
{
	int cmp_ret;
	XID_NODE *pxnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(ppcl); NULL!=pnode;
		pnode=double_list_get_after(ppcl, pnode)) {
		pxnode = (XID_NODE*)pnode->pdata;
		cmp_ret = memcmp(&pxnode->xid.xid.guid, &pxid->xid.guid, sizeof(GUID));
		if (cmp_ret < 0) {
			continue;
		} else if (0 == cmp_ret) {
			if (pxid->size != pxnode->xid.size) {
				return FALSE;
			}
			if (pcl_convert_local_id(pxid) >
				pcl_convert_local_id(&pxnode->xid)) {
				memcpy(pxnode->xid.xid.local_id,
					pxid->xid.local_id, pxid->size - sizeof(GUID));
			}
			return TRUE;
		}
		pxnode = static_cast<XID_NODE *>(malloc(sizeof(XID_NODE)));
		if (NULL == pxnode) {
			return FALSE;
		}
		pxnode->node.pdata = pxnode;
		memcpy(&pxnode->xid, pxid, sizeof(SIZED_XID));
		double_list_insert_before(ppcl, pnode, &pxnode->node);
		return TRUE;
	}
	pxnode = static_cast<XID_NODE *>(malloc(sizeof(XID_NODE)));
	if (NULL == pxnode) {
		return FALSE;
	}
	pxnode->node.pdata = pxnode;
	memcpy(&pxnode->xid, pxid, sizeof(SIZED_XID));
	double_list_append_as_tail(ppcl, &pxnode->node);
	return TRUE;
}

BOOL pcl_merge(PCL *ppcl1, const PCL *ppcl2)
{
	XID_NODE *pxnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head((DOUBLE_LIST*)ppcl2); NULL!=pnode;
		pnode=double_list_get_after((DOUBLE_LIST*)ppcl2, pnode)) {
		pxnode = (XID_NODE*)pnode->pdata;
		if (FALSE == pcl_append(ppcl1, &pxnode->xid)) {
			return FALSE;
		}
	}
	return TRUE;
}

BINARY* pcl_serialize(PCL *ppcl)
{
	BINARY tmp_bin;
	SIZED_XID *pxid;
	uint8_t buff[0x8000];
	DOUBLE_LIST_NODE *pnode;
	
	tmp_bin.cb = 0;
	tmp_bin.pb = buff;
	for (pnode=double_list_get_head(ppcl); NULL!=pnode;
		pnode=double_list_get_after(ppcl, pnode)) {
		pxid = &((XID_NODE*)pnode->pdata)->xid;
		if (pxid->size < 17 || pxid->size > 24 ||
			sizeof(buff) < tmp_bin.cb + pxid->size) {
			return NULL;
		}
		pcl_push_sized_xid(&tmp_bin, pxid);
	}
	auto pbin = static_cast<BINARY *>(malloc(sizeof(BINARY)));
	if (NULL == pbin) {
		return NULL;
	}
	pbin->cb = tmp_bin.cb;
	if (0 == tmp_bin.cb) {
		pbin->pb = NULL;
	} else {
		pbin->pv = malloc(pbin->cb);
		if (pbin->pv == nullptr) {
			free(pbin);
			return NULL;
		}
		memcpy(pbin->pv, buff, pbin->cb);
	}
	return pbin;
}

BOOL pcl_deserialize(PCL *ppcl, const BINARY *pbin)
{
	SIZED_XID xid;
	uint16_t offset;
	uint16_t offset1;
	
	offset = 0;
	while ((offset1 = pcl_pull_sized_xid(pbin, offset, &xid)) != 0) {
		if (FALSE == pcl_append(ppcl, &xid)) {
			return FALSE;
		}
		offset += offset1;
		if (pbin->cb == offset) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL pcl_check_included(const PCL *ppcl, SIZED_XID *pxid)
{
	int cmp_ret;
	XID_NODE *pxnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head((DOUBLE_LIST*)ppcl); NULL!=pnode;
		pnode=double_list_get_after((DOUBLE_LIST*)ppcl, pnode)) {
		pxnode = (XID_NODE*)pnode->pdata;
		cmp_ret = memcmp(&pxnode->xid.xid.guid, &pxid->xid.guid, sizeof(GUID));
		if (cmp_ret < 0) {
			continue;
		} else if (cmp_ret > 0) {
			return FALSE;
		}
		if (pxid->size != pxnode->xid.size) {
			return FALSE;
		}
		if (pcl_convert_local_id(&pxnode->xid) >=
			pcl_convert_local_id(pxid)) {
			return TRUE;
		}
	}
	return FALSE;
}

uint32_t pcl_compare(const PCL *ppcl1, const PCL *ppcl2)
{
	int ret_val;
	DOUBLE_LIST_NODE *pnode;
	
	ret_val = PCL_CONFLICT;
	for (pnode=double_list_get_head((DOUBLE_LIST*)ppcl1); NULL!=pnode;
		pnode=double_list_get_after((DOUBLE_LIST*)ppcl1, pnode)) {
		if (FALSE == pcl_check_included(ppcl2,
			&((XID_NODE*)pnode->pdata)->xid)) {
			break;
		}
	}
	if (NULL == pnode) {
		ret_val |= PCL_INCLUDED;
	}
	for (pnode=double_list_get_head((DOUBLE_LIST*)ppcl2); NULL!=pnode;
		pnode=double_list_get_after((DOUBLE_LIST*)ppcl2, pnode)) {
		if (FALSE == pcl_check_included(ppcl1,
			&((XID_NODE*)pnode->pdata)->xid)) {
			return ret_val;
		}
	}
	return ret_val | PCL_INCLUDE;
}

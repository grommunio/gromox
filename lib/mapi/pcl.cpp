// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <gromox/pcl.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

using namespace gromox;

static void pcl_pull_xid(const BINARY *pbin,
	uint16_t offset, uint8_t size, XID *pxid)
{
	BINARY tmp_bin;
	
	tmp_bin.cb = pbin->cb - offset;
	tmp_bin.pb = pbin->pb + offset;
	pxid->guid = rop_util_binary_to_guid(&tmp_bin);
	memcpy(pxid->local_id, pbin->pb + offset + 16, size - 16);
}

static void pcl_push_xid(BINARY &bin, uint8_t size, const XID &xid)
{
	rop_util_guid_to_binary(xid.guid, &bin);
	memcpy(bin.pb + bin.cb, xid.local_id, size - 16);
	bin.cb += size - 16;
}

static uint8_t pcl_pull_sized_xid(const BINARY *pbin, uint16_t offset, XID *pxid)
{	
	if (pbin->cb <= offset) {
		return 0;
	}
	pxid->size = pbin->pb[offset];
	if (pxid->size < 17 || pxid->size > 24 ||
	    offset + 1U + pxid->size > pbin->cb)
		return 0;
	pcl_pull_xid(pbin, offset + 1, pxid->size, pxid);
	return pxid->size + 1;
}

static void pcl_push_sized_xid(BINARY &bin, const XID &xid)
{
	bin.pb[bin.cb++] = xid.size;
	pcl_push_xid(bin, xid.size, xid);
}

static uint64_t pcl_convert_local_id(const XID &xid)
{
	uint64_t ret_val = 0;
	for (uint8_t i = 0; i < xid.size - 16; ++i)
		ret_val |= static_cast<uint64_t>(xid.local_id[i]) <<
		           (xid.size - 16 - 1 - i) * 8;
	return ret_val;
}

bool PCL::append(const XID &zxid) try
{
	for (auto node = begin(); node != end(); ++node) {
		auto cmp_ret = memcmp(&node->guid, &zxid.guid, sizeof(GUID));
		if (cmp_ret < 0) {
			continue;
		} else if (0 == cmp_ret) {
			if (node->size != zxid.size)
				return false;
			if (pcl_convert_local_id(zxid) > pcl_convert_local_id(*node))
				memcpy(node->local_id, zxid.local_id,
				       zxid.size - sizeof(GUID));
			return true;
		}
		emplace(node, zxid);
		return true;
	}
	emplace_back(zxid);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1535: ENOMEM");
	return false;
}

bool PCL::merge(PCL &&their_list) try
{
	splice(end(), std::move(their_list));
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1536: ENOMEM");
	return false;
}

BINARY *PCL::serialize() const
{
	BINARY tmp_bin;
	uint8_t buff[0x8000];
	
	tmp_bin.cb = 0;
	tmp_bin.pb = buff;
	for (const auto &xid : *this) {
		if (xid.size < 17 || xid.size > 24 ||
		    std::size(buff) < tmp_bin.cb + xid.size)
			return NULL;
		pcl_push_sized_xid(tmp_bin, xid);
	}
	auto pbin = gromox::me_alloc<BINARY>();
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

bool PCL::deserialize(const BINARY *pbin)
{
	auto ppcl = this;
	XID xid;
	uint16_t offset;
	uint16_t offset1;
	
	offset = 0;
	while ((offset1 = pcl_pull_sized_xid(pbin, offset, &xid)) != 0) {
		if (!ppcl->append(xid))
			return false;
		offset += offset1;
		if (pbin->cb == offset) {
			return true;
		}
	}
	return false;
}

static bool pcl_check_included(const PCL &pcl, const XID &xid)
{
	for (const auto &node : pcl) {
		auto cmp_ret = memcmp(&node.guid, &xid.guid, sizeof(GUID));
		if (cmp_ret < 0) {
			continue;
		} else if (cmp_ret > 0) {
			return false;
		}
		if (node.size != xid.size)
			return false;
		if (pcl_convert_local_id(node) >= pcl_convert_local_id(xid))
			return true;
	}
	return false;
}

uint32_t PCL::compare(const PCL &their_list) const
{
	int ret_val = PCL_CONFLICT;

	if (std::all_of(cbegin(), cend(),
	    [&](const XID &our_node) { return pcl_check_included(their_list, our_node); }))
		ret_val |= PCL_INCLUDED;
	if (std::all_of(their_list.cbegin(), their_list.cend(),
	    [&](const XID &their_node) { return pcl_check_included(*this, their_node); }))
		ret_val |= PCL_INCLUDE;
	return ret_val;
}

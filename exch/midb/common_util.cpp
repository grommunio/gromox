// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <pthread.h>
#include <utility>
#include <arpa/inet.h>
#include <libHX/string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <gromox/defs.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/pcl.hpp>
#include <gromox/process.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"

using namespace gromox;

namespace {
struct cmd_context {
	alloc_context alloc_ctx;
	std::optional<alloc_context> ptmp_ctx;
	char maildir[256]{};
};
using COMMAND_CONTEXT = cmd_context;
}

static thread_local std::unique_ptr<cmd_context> g_ctx_key;
static thread_local unsigned int g_ctx_refcount;

BOOL cu_build_environment(const char *maildir) try
{
	/*
	 * cu_build_env is already called by midb, and then it _may_ occur
	 * another time during exmdb_client_connect_exmdb, but the latter only
	 * cares about exrpc_alloc succeeding, not the maildir.
	 */
	if (++g_ctx_refcount > 1) {
		if (*maildir != '\0' && strcmp(g_ctx_key->maildir, maildir) != 0)
			mlog(LV_WARN, "W-1901: T%lu: g_ctx_key->maildir mismatch %s vs %s",
			        gx_gettid(), g_ctx_key->maildir, maildir);
		return TRUE;
	}
	auto pctx = std::make_unique<cmd_context>();
	gx_strlcpy(pctx->maildir, maildir, std::size(pctx->maildir));
	g_ctx_key = std::move(pctx);
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1976: ENOMEM");
	return false;
}

void cu_free_environment()
{
	if (--g_ctx_refcount > 0)
		return;
	if (g_ctx_key == nullptr) {
		mlog(LV_WARN, "W-1902: T%lu: g_ctx_key already unset", gx_gettid());
		return;
	}
	g_ctx_key.reset();
}

void *cu_alloc_bytes(size_t size)
{
	auto pctx = g_ctx_key.get();
	if (NULL == pctx) {
		mlog(LV_ERR, "E-1903: T%lu: g_ctx_key is unset, allocator is unset", gx_gettid());
		return NULL;
	}
	return pctx->ptmp_ctx.has_value() ? pctx->ptmp_ctx->alloc(size) :
	       pctx->alloc_ctx.alloc(size);
}

BOOL cu_switch_allocator()
{
	auto pctx = g_ctx_key.get();
	if (NULL == pctx) {
		mlog(LV_ERR, "E-1904: T%lu: g_ctx_key is unset, allocator is unset", gx_gettid());
		return FALSE;
	}
	if (pctx->ptmp_ctx.has_value())
		pctx->ptmp_ctx.reset();
	else
		pctx->ptmp_ctx.emplace();
	return TRUE;
}

void cu_set_maildir(const char *maildir)
{
	auto pctx = g_ctx_key.get();
	if (pctx == nullptr)
		mlog(LV_ERR, "E-1905: T%lu: g_ctx_key is unset, cannot set maildir", gx_gettid());
	else
		gx_strlcpy(pctx->maildir, maildir, std::size(pctx->maildir));
}

const char *cu_get_maildir()
{
	auto pctx = g_ctx_key.get();
	if (pctx != nullptr)
		return pctx->maildir;
	mlog(LV_ERR, "E-1906: T%lu: g_ctx_key is unset, maildir is unset", gx_gettid());
	return NULL;
}

char *cu_dup(const char *pstr)
{
	int len;

	len = strlen(pstr) + 1;
	auto pstr1 = static_cast<char *>(cu_alloc_bytes(len));
	if (pstr1 == nullptr)
		return NULL;
	memcpy(pstr1, pstr, len);
	return pstr1;
}

BINARY *cu_xid_to_bin(const XID &xid)
{
	EXT_PUSH ext_push;

	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	pbin->pv = cu_alloc_bytes(24);
	if (pbin->pv == nullptr || !ext_push.init(pbin->pv, 24, 0) ||
	    ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		return NULL;
	pbin->cb = ext_push.m_offset;
	return pbin;
}

static BOOL cu_binary_to_xid(const BINARY *pbin, XID *pxid)
{
	EXT_PULL ext_pull;

	if (pbin->cb < 17 || pbin->cb > 24)
		return FALSE;
	ext_pull.init(pbin->pb, pbin->cb, cu_alloc_bytes, 0);
	return ext_pull.g_xid(pbin->cb, pxid) == EXT_ERR_SUCCESS ? TRUE : false;
}

BINARY *cu_pcl_append(const BINARY *pbin_pcl, const BINARY *pchange_key)
{
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return NULL;
	PCL ppcl;
	if (pbin_pcl != nullptr && !ppcl.deserialize(pbin_pcl))
		return nullptr;
	XID xid;
	xid.size = pchange_key->cb;
	if (!cu_binary_to_xid(pchange_key, &xid))
		return NULL;
	if (!ppcl.append(xid))
		return NULL;
	auto ptmp_bin = ppcl.serialize();
	ppcl.clear();
	if (ptmp_bin == nullptr)
		return NULL;
	pbin->cb = ptmp_bin->cb;
	pbin->pv = cu_alloc_bytes(ptmp_bin->cb);
	if (pbin->pv == nullptr) {
		rop_util_free_binary(ptmp_bin);
		return NULL;
	}
	memcpy(pbin->pv, ptmp_bin->pb, pbin->cb);
	rop_util_free_binary(ptmp_bin);
	return pbin;
}

BOOL cu_create_folder(const char *dir, int user_id,
	uint64_t parent_id, const char *folder_name, uint64_t *pfolder_id)
{
	BINARY *pbin;
	BINARY tmp_bin;
	EXT_PUSH ext_push;
	uint64_t last_time;
	char tmp_buff[128];
	uint64_t change_num;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[9];
	
	if (!exmdb_client->allocate_cn(dir, &change_num))
		return FALSE;
	uint32_t tmp_type = FOLDER_GENERIC;
	last_time = rop_util_unix_to_nttime(time(NULL));
	tmp_propvals.count = 9;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PidTagParentFolderId;
	propval_buff[0].pvalue = &parent_id;
	propval_buff[1].proptag = PR_FOLDER_TYPE;
	propval_buff[1].pvalue = &tmp_type;
	propval_buff[2].proptag = PR_DISPLAY_NAME;
	propval_buff[2].pvalue = deconst(folder_name);
	propval_buff[3].proptag = PR_CONTAINER_CLASS;
	propval_buff[3].pvalue  = deconst("IPF.Note");
	propval_buff[4].proptag = PR_CREATION_TIME;
	propval_buff[4].pvalue = &last_time;
	propval_buff[5].proptag = PR_LAST_MODIFICATION_TIME;
	propval_buff[5].pvalue = &last_time;
	propval_buff[6].proptag = PidTagChangeNumber;
	propval_buff[6].pvalue = &change_num;
	XID xid{rop_util_make_user_guid(user_id), change_num};
	if (!ext_push.init(tmp_buff, sizeof(tmp_buff), 0) ||
	    ext_push.p_xid(xid) != EXT_ERR_SUCCESS)
		return false;
	tmp_bin.pv = tmp_buff;
	tmp_bin.cb = ext_push.m_offset;
	propval_buff[7].proptag = PR_CHANGE_KEY;
	propval_buff[7].pvalue = &tmp_bin;
	PCL ppcl;
	if (!ppcl.append(xid))
		return FALSE;
	pbin = ppcl.serialize();
	if (pbin == nullptr)
		return FALSE;
	ppcl.clear();
	propval_buff[8].proptag = PR_PREDECESSOR_CHANGE_LIST;
	propval_buff[8].pvalue = pbin;
	ec_error_t err = ecSuccess;
	if (!exmdb_client->create_folder(dir, CP_ACP, &tmp_propvals,
	    pfolder_id, &err) || err != ecSuccess) {
		rop_util_free_binary(pbin);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	return *pfolder_id != 0 ? TRUE : false;
}

BOOL cu_get_propids(const PROPNAME_ARRAY *ppropnames, PROPID_ARRAY *ppropids)
{
	return exmdb_client->get_named_propids(cu_get_maildir(), false,
		ppropnames, ppropids);
}

BOOL cu_get_propids_create(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client->get_named_propids(cu_get_maildir(),
	       TRUE, names, ids);
}

BOOL cu_get_propname(propid_t propid, PROPERTY_NAME **pppropname) try
{
	PROPNAME_ARRAY propnames;
	
	if (!exmdb_client->get_named_propnames(cu_get_maildir(),
	    {propid}, &propnames) || propnames.size() != 1)
		return FALSE;	
	*pppropname = propnames.ppropname;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2228: ENOMEM");
	return false;
}

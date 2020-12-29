// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <libHX/defs.h>
#include <libHX/string.h>
#include "alloc_context.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "rop_util.h"
#include "pcl.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <cstring>
#include <cstdlib>

struct COMMAND_CONTEXT {
	ALLOC_CONTEXT alloc_ctx;
	ALLOC_CONTEXT *ptmp_ctx;
	char maildir[256];
};

static pthread_key_t g_ctx_key;

void common_util_init()
{
	pthread_key_create(&g_ctx_key, NULL);
}

int common_util_run()
{
	return 0;
}

int common_util_stop()
{
	return 0;
}

void common_util_free()
{
	pthread_key_delete(g_ctx_key);
}

BOOL common_util_build_environment(const char *maildir)
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(malloc(sizeof(COMMAND_CONTEXT)));
	if (NULL == pctx) {
		return FALSE;
	}
	alloc_context_init(&pctx->alloc_ctx);
	pctx->ptmp_ctx = NULL;
	strncpy(pctx->maildir, maildir, 256);
	pthread_setspecific(g_ctx_key, pctx);
	return TRUE;
}

void common_util_free_environment()
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(pthread_getspecific(g_ctx_key));
	if (NULL == pctx) {
		return;
	}
	alloc_context_free(&pctx->alloc_ctx);
	if (NULL != pctx->ptmp_ctx) {
		alloc_context_free(pctx->ptmp_ctx);
		free(pctx->ptmp_ctx);
		pctx->ptmp_ctx = NULL;
	}
	free(pctx);
	pthread_setspecific(g_ctx_key, NULL);
}

void* common_util_alloc(size_t size)
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(pthread_getspecific(g_ctx_key));
	if (NULL == pctx) {
		return NULL;
	}
	if (NULL != pctx->ptmp_ctx) {
		return alloc_context_alloc(pctx->ptmp_ctx, size);
	}
	return alloc_context_alloc(&pctx->alloc_ctx, size);
}

BOOL common_util_switch_allocator()
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(pthread_getspecific(g_ctx_key));
	if (NULL == pctx) {
		return FALSE;
	}
	if (NULL != pctx->ptmp_ctx) {
		alloc_context_free(pctx->ptmp_ctx);
		free(pctx->ptmp_ctx);
		pctx->ptmp_ctx = NULL;
	} else {
		pctx->ptmp_ctx = static_cast<ALLOC_CONTEXT *>(malloc(sizeof(ALLOC_CONTEXT)));
		if (NULL == pctx->ptmp_ctx) {
			return FALSE;
		}
		alloc_context_init(pctx->ptmp_ctx);
	}
	return TRUE;
}

void common_util_set_maildir(const char *maildir)
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(pthread_getspecific(g_ctx_key));
	if (NULL != pctx) {
		strcpy(pctx->maildir, maildir);
	}
}

const char* common_util_get_maildir()
{
	auto pctx = static_cast<COMMAND_CONTEXT *>(pthread_getspecific(g_ctx_key));
	if (NULL == pctx) {
		return NULL;
	}
	return pctx->maildir;
}

char* common_util_dup(const char *pstr)
{
	int len;

	len = strlen(pstr) + 1;
	auto pstr1 = static_cast<char *>(common_util_alloc(len));
	if (NULL == pstr1) {
		return NULL;
	}
	memcpy(pstr1, pstr, len);
	return pstr1;
}

void* common_util_get_propvals(const TPROPVAL_ARRAY *parray, uint32_t proptag)
{
	int i;

	for (i=0; i<parray->count; i++) {
		if (proptag == parray->ppropval[i].proptag) {
			return (void*)parray->ppropval[i].pvalue;
		}
	}
	return NULL;
}

BINARY* common_util_xid_to_binary(uint8_t size, const XID *pxid)
{
	EXT_PUSH ext_push;

	auto pbin = static_cast<BINARY *>(common_util_alloc(sizeof(BINARY)));
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(24);
	if (pbin->pv == nullptr)
		return NULL;
	ext_buffer_push_init(&ext_push, pbin->pv, 24, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_push_xid(
		&ext_push, size, pxid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL common_util_binary_to_xid(const BINARY *pbin, XID *pxid)
{
	EXT_PULL ext_pull;

	if (pbin->cb < 17 || pbin->cb > 24) {
		return FALSE;
	}
	ext_buffer_pull_init(&ext_pull, pbin->pb,
			pbin->cb, common_util_alloc, 0);
	if (EXT_ERR_SUCCESS != ext_buffer_pull_xid(
		&ext_pull, pbin->cb, pxid)) {
		return FALSE;
	}
	return TRUE;
}

BINARY* common_util_pcl_append(const BINARY *pbin_pcl,
	const BINARY *pchange_key)
{
	PCL *ppcl;
	SIZED_XID xid;
	BINARY *ptmp_bin;

	auto pbin = static_cast<BINARY *>(common_util_alloc(sizeof(BINARY)));
	if (NULL == pbin) {
		return NULL;
	}
	ppcl = pcl_init();
	if (NULL == ppcl) {
			return NULL;
	}
	if (NULL != pbin_pcl) {
		if (FALSE == pcl_deserialize(ppcl, pbin_pcl)) {
			pcl_free(ppcl);
			return NULL;
		}
	}
	xid.size = pchange_key->cb;
	if (FALSE == common_util_binary_to_xid(pchange_key, &xid.xid)) {
		pcl_free(ppcl);
		return NULL;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		return NULL;
	}
	ptmp_bin = pcl_serialize(ppcl);
	pcl_free(ppcl);
	if (NULL == ptmp_bin) {
		return NULL;
	}
	pbin->cb = ptmp_bin->cb;
	pbin->pv = common_util_alloc(ptmp_bin->cb);
	if (pbin->pv == nullptr) {
		rop_util_free_binary(ptmp_bin);
		return NULL;
	}
	memcpy(pbin->pv, ptmp_bin->pb, pbin->cb);
	rop_util_free_binary(ptmp_bin);
	return pbin;
}

BOOL common_util_create_folder(const char *dir, int user_id,
	uint64_t parent_id, const char *folder_name, uint64_t *pfolder_id)
{
	PCL *ppcl;
	BINARY *pbin;
	SIZED_XID xid;
	BINARY tmp_bin;
	uint32_t tmp_type;
	EXT_PUSH ext_push;
	uint64_t last_time;
	char tmp_buff[128];
	uint64_t change_num;
	TPROPVAL_ARRAY tmp_propvals;
	TAGGED_PROPVAL propval_buff[9];
	
	if (FALSE == exmdb_client_allocate_cn(dir, &change_num)) {
		return FALSE;
	}
	tmp_type = FOLDER_TYPE_GENERIC;
	last_time = rop_util_unix_to_nttime(time(NULL));
	tmp_propvals.count = 9;
	tmp_propvals.ppropval = propval_buff;
	propval_buff[0].proptag = PROP_TAG_PARENTFOLDERID;
	propval_buff[0].pvalue = &parent_id;
	propval_buff[1].proptag = PROP_TAG_FOLDERTYPE;
	propval_buff[1].pvalue = &tmp_type;
	propval_buff[2].proptag = PROP_TAG_DISPLAYNAME;
	propval_buff[2].pvalue = (void*)folder_name;
	propval_buff[3].proptag = PROP_TAG_CONTAINERCLASS;
	propval_buff[3].pvalue  = deconst("IPF.Note");
	propval_buff[4].proptag = PROP_TAG_CREATIONTIME;
	propval_buff[4].pvalue = &last_time;
	propval_buff[5].proptag = PROP_TAG_LASTMODIFICATIONTIME;
	propval_buff[5].pvalue = &last_time;
	propval_buff[6].proptag = PROP_TAG_CHANGENUMBER;
	propval_buff[6].pvalue = &change_num;
	xid.size = 22;
	xid.xid.guid = rop_util_make_user_guid(user_id);
	rop_util_value_to_gc(change_num, xid.xid.local_id);
	ext_buffer_push_init(&ext_push, tmp_buff, sizeof(tmp_buff), 0);
	ext_buffer_push_xid(&ext_push, 22, &xid.xid);
	tmp_bin.pv = tmp_buff;
	tmp_bin.cb = ext_push.offset;
	propval_buff[7].proptag = PROP_TAG_CHANGEKEY;
	propval_buff[7].pvalue = &tmp_bin;
	ppcl = pcl_init();
	if (NULL == ppcl) {
		return FALSE;
	}
	if (FALSE == pcl_append(ppcl, &xid)) {
		pcl_free(ppcl);
		return FALSE;
	}
	pbin = pcl_serialize(ppcl);
	if (NULL == pbin) {
		pcl_free(ppcl);
		return FALSE;
	}
	pcl_free(ppcl);
	propval_buff[8].proptag = PROP_TAG_PREDECESSORCHANGELIST;
	propval_buff[8].pvalue = pbin;
	if (FALSE == exmdb_client_create_folder_by_properties(
		dir, 0, &tmp_propvals, pfolder_id)) {
		rop_util_free_binary(pbin);
		return FALSE;
	}
	rop_util_free_binary(pbin);
	if (0 == *pfolder_id) {
		return FALSE;
	}
	return TRUE;
}

BOOL common_util_get_propids(const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids)
{
	return exmdb_client_get_named_propids(
		common_util_get_maildir(), FALSE,
		ppropnames, ppropids);
}

BOOL common_util_get_propids_create(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	return exmdb_client_get_named_propids(common_util_get_maildir(),
	       TRUE, names, ids);
}

BOOL common_util_get_propname(
	uint16_t propid, PROPERTY_NAME **pppropname)
{
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	
	propids.count = 1;
	propids.ppropid = &propid;
	if (FALSE == exmdb_client_get_named_propnames(
		common_util_get_maildir(), &propids, &propnames)) {
		return FALSE;	
	}
	if (0 == propnames.count) {
		*pppropname = NULL;
	}
	*pppropname = propnames.ppropname;
	return TRUE;
}

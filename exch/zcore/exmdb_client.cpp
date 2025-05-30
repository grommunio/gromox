// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <string>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/usercvt.hpp>
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "zserver.hpp"

using namespace gromox;

static void buildenv(const remote_svr &s)
{
	common_util_build_environment();
}

int exmdb_client_run_front(const char *dir)
{
	return exmdb_client_run(dir, EXMDB_CLIENT_ASYNC_CONNECT, buildenv,
	       common_util_free_environment, zs_notification_proc);
}

BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	const PROPNAME_ARRAY tmp_propnames = {1, deconst(ppropname)};
	if (!exmdb_client->get_named_propids(dir,
	    b_create, &tmp_propnames, &tmp_propids) || tmp_propids.size() != 1)
		return FALSE;	
	*ppropid = tmp_propids[0];
	return TRUE;
}

BOOL exmdb_client_get_folder_property(const char *dir, cpid_t cpid,
    uint64_t folder_id, proptag_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client->get_folder_properties(
		dir, cpid, folder_id, &tmp_proptags,
	    &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_get_message_property(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, proptag_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client->get_message_properties(dir,
	    username, cpid, message_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_delete_message(const char *dir, int account_id, cpid_t cpid,
    uint64_t folder_id, uint64_t message_id, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	EID_ARRAY message_ids;
	
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (!exmdb_client->delete_messages(dir, cpid, nullptr, folder_id,
	    &message_ids, b_hard, &b_partial))
		return FALSE;	
	*pb_done = !b_partial ? TRUE : false;
	return TRUE;
}

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	proptag_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client->get_instance_properties(dir,
	    0, instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!exmdb_client->set_instance_properties(dir,
	    instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_instance_property(const char *dir,
    uint32_t instance_id, proptag_t proptag, uint32_t *presult)
{
	PROPTAG_ARRAY tmp_proptags;
	PROBLEM_ARRAY tmp_problems;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client->remove_instance_properties(
	    dir, instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_message_property(const char *dir,
    cpid_t cpid, uint64_t message_id, proptag_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client->remove_message_properties(
	    dir, cpid, message_id, &tmp_proptags))
		return FALSE;	
	return TRUE;
}

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	EMSAB_ENTRYID ab_entryid;
	
	if (!exmdb_client_get_message_property(dir, nullptr, CP_ACP, message_id,
	    PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
		return FALSE;
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&ab_entryid) != pack_result::ok) {
		*pb_owner = false;
		return TRUE;
	}
	std::string es_result;
	auto ret = cvt_essdn_to_username(ab_entryid.px500dn, g_org_name, mysql_adaptor_userid_to_name, es_result);
	if (ret != ecSuccess) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, es_result.c_str()) == 0 ? TRUE : false;
	return TRUE;
}

// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/proc_common.h>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "emsmdb_interface.hpp"
#include "exmdb_client.hpp"

using namespace gromox;

std::optional<exmdb_client_shm> exmdb_client{std::in_place_t{}};

int exmdb_client_shm::run()
{
	void (*register_proc)(void*);
	void (*pass_service)(const char *, void *); // cross-plugin symbol exchange
	
#define EXMIDL(n, p) do { \
	query_service2("exmdb_client_" #n, n); \
	if ((n) == nullptr) { \
		mlog(LV_ERR, "emsmdb: failed to get the \"%s\" service", "exmdb_client_" #n); \
		return -1; \
	} \
} while (false);
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

#define E(f, s) do { \
	query_service2(s, f); \
	if ((f) == nullptr) { \
		mlog(LV_ERR, "emsmdb: failed to get the \"%s\" service", (s)); \
		return -1; \
	} \
} while (false)

	E(register_proc, "exmdb_client_register_proc");
	register_proc(reinterpret_cast<void *>(emsmdb_interface_event_proc));

	E(pass_service, "pass_service");
#undef E
	/* pass the service functions to exmdb_provider */
#define E(s) reinterpret_cast<void *>(s)
	pass_service("ems_send_mail", E(ems_send_mail));
	pass_service("ems_send_vmail", E(ems_send_vmail));
	pass_service("get_handle", E(emsmdb_interface_get_handle));
#undef E
	return 0;
}

BOOL exmdb_client_shm::get_named_propid(const char *dir, BOOL b_create,
    const PROPERTY_NAME *ppropname, uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	const PROPNAME_ARRAY tmp_propnames = {1, deconst(ppropname)};
	if (!exmdb_client->get_named_propids(dir, b_create,
	    &tmp_propnames, &tmp_propids) || tmp_propids.size() != 1)
		return FALSE;	
	*ppropid = tmp_propids[0];
	return TRUE;
}

BOOL exmdb_client_shm::get_named_propname(const char *dir, propid_t propid,
    PROPERTY_NAME *ppropname) try
{
	PROPNAME_ARRAY tmp_propnames;
	
	if (!exmdb_client->get_named_propnames(dir, {propid}, &tmp_propnames) ||
	    tmp_propnames.size() != 1)
		return FALSE;	
	*ppropname = *tmp_propnames.ppropname;
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

BOOL exmdb_client_shm::get_store_property(const char *dir, cpid_t cpid,
    proptag_t proptag, void **ppval)
{
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_store_properties(dir, cpid,
	    {&proptag, 1}, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_shm::get_folder_property(const char *dir, cpid_t cpid,
    uint64_t folder_id, proptag_t proptag, void **ppval)
{
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_folder_properties(dir, cpid, folder_id,
	    {&proptag, 1}, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_shm::delete_message(const char *dir, int account_id, cpid_t cpid,
    uint64_t folder_id, uint64_t message_idn, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	eid_t message_id = message_idn;
	const EID_ARRAY message_ids = {1, &message_id};
	if (!exmdb_client->delete_messages(dir, cpid, nullptr, folder_id,
	    &message_ids, b_hard, &b_partial))
		return FALSE;	
	*pb_done = !b_partial;
	return TRUE;
}

BOOL exmdb_client_shm::get_instance_property(const char *dir, uint32_t instance_id,
    proptag_t proptag, void **ppval)
{
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_instance_properties(dir, 0, instance_id,
	    {&proptag, 1}, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_shm::set_instance_property(const char *dir, uint32_t instance_id,
    const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!exmdb_client->set_instance_properties(dir, instance_id,
	    &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_shm::remove_instance_property(const char *dir, uint32_t instance_id,
    proptag_t proptag, uint32_t *presult)
{
	const PROPTAG_ARRAY tmp_proptags = {1, &proptag};
	PROBLEM_ARRAY tmp_problems;
	if (!exmdb_client->remove_instance_properties(dir, instance_id,
	    &tmp_proptags, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_shm::get_message_property(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, proptag_t proptag, void **ppval)
{
	const PROPTAG_ARRAY tmp_proptags = {1, &proptag};
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_message_properties(dir, username, cpid,
	    message_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_shm::set_message_property(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, TAGGED_PROPVAL *ppropval,
    uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!exmdb_client->set_message_properties(dir, username, cpid,
	    message_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_shm::remove_message_property(const char *dir, cpid_t cpid,
    uint64_t message_id, proptag_t proptag)
{
	const PROPTAG_ARRAY tmp_proptags = {1, &proptag};
	return exmdb_client->remove_message_properties(dir, cpid,
	       message_id, &tmp_proptags);
}

BOOL exmdb_client_shm::is_message_owner(const char *dir, uint64_t message_id,
    const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EMSAB_ENTRYID ab_entryid;
	
	if (!exmdb_client->get_message_property(dir, nullptr, CP_ACP,
	    message_id, PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
		return FALSE;
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	EXT_PULL ext_pull;
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&ab_entryid)  != pack_result::ok) {
		*pb_owner = false;
		return TRUE;
	}
	std::string es_result;
	if (cvt_essdn_to_username(ab_entryid.x500dn.c_str(), g_emsmdb_org_name,
	    mysql_adaptor_userid_to_name, es_result) != ecSuccess) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, es_result.c_str()) == 0 ? TRUE : false;
	return TRUE;
}

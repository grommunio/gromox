// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/proc_common.h>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"

using namespace gromox;

namespace exmdb_client_ems {

#define EXMIDL(n, p) decltype(n) n;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

int run()
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
	pass_service("get_handle", E(emsmdb_interface_get_handle));
#undef E
	return 0;
}

BOOL get_named_propid(const char *dir, BOOL b_create,
    const PROPERTY_NAME *ppropname, uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	const PROPNAME_ARRAY tmp_propnames = {1, deconst(ppropname)};
	if (!exmdb_client::get_named_propids(dir, b_create,
	    &tmp_propnames, &tmp_propids))
		return FALSE;	
	*ppropid = *tmp_propids.ppropid;
	return TRUE;
}

BOOL get_named_propname(const char *dir, uint16_t propid,
    PROPERTY_NAME *ppropname)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propids.count = 1;
	tmp_propids.ppropid = &propid;
	if (!exmdb_client::get_named_propnames(dir, &tmp_propids, &tmp_propnames))
		return FALSE;	
	*ppropname = *tmp_propnames.ppropname;
	return TRUE;
}

BOOL get_store_property(const char *dir, cpid_t cpid,
    uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_store_properties(dir, cpid,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL get_folder_property(const char *dir, cpid_t cpid, uint64_t folder_id,
    uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_folder_properties(dir, cpid, folder_id,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL delete_message(const char *dir, int account_id, cpid_t cpid,
    uint64_t folder_id, uint64_t message_id, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	EID_ARRAY message_ids;
	
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (!exmdb_client::delete_messages(dir, account_id, cpid, nullptr,
	    folder_id, &message_ids, b_hard, &b_partial))
		return FALSE;	
	*pb_done = !b_partial;
	return TRUE;
}

BOOL get_instance_property(const char *dir, uint32_t instance_id,
    uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_instance_properties(dir, 0, instance_id,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL set_instance_property(const char *dir, uint32_t instance_id,
    const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!exmdb_client::set_instance_properties(dir, instance_id,
	    &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL remove_instance_property(const char *dir, uint32_t instance_id,
    uint32_t proptag, uint32_t *presult)
{
	PROPTAG_ARRAY tmp_proptags;
	PROBLEM_ARRAY tmp_problems;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::remove_instance_properties(dir, instance_id,
	    &tmp_proptags, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL get_message_property(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client::get_message_properties(dir, username, cpid,
	    message_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL set_message_property(const char *dir, const char *username,
    cpid_t cpid, uint64_t message_id, TAGGED_PROPVAL *ppropval,
    uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	const TPROPVAL_ARRAY tmp_propvals = {1, deconst(ppropval)};
	if (!exmdb_client::set_message_properties(dir, username, cpid,
	    message_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL remove_message_property(const char *dir, cpid_t cpid,
    uint64_t message_id, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	return exmdb_client::remove_message_properties(dir, cpid,
	       message_id, &tmp_proptags);
}

BOOL check_message_owner(const char *dir, uint64_t message_id,
    const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[UADDR_SIZE];
	EMSAB_ENTRYID ab_entryid;
	
	if (!exmdb_client::get_message_property(dir, nullptr, CP_ACP,
	    message_id, PR_CREATOR_ENTRYID, reinterpret_cast<void **>(&pbin)))
		return FALSE;
	if (NULL == pbin) {
		*pb_owner = FALSE;
		return TRUE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_abk_eid(&ab_entryid)  != EXT_ERR_SUCCESS) {
		*pb_owner = false;
		return TRUE;
	}
	std::string es_result;
	if (cvt_essdn_to_username(ab_entryid.px500dn, g_emsmdb_org_name,
	    cu_id2user, es_result) != ecSuccess) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(es_result.c_str(), tmp_name) == 0 ? TRUE : false;
	return TRUE;
}

}

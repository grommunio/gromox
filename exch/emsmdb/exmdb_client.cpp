// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <gromox/ext_buffer.hpp>
#include <gromox/proc_common.h>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#define SERVICE_ID_LANG_TO_CHARSET							1
#define SERVICE_ID_CPID_TO_CHARSET							2
#define SERVICE_ID_GET_USER_DISPLAYNAME						3
#define SERVICE_ID_CHECK_MLIST_INCLUDE						4
#define SERVICE_ID_GET_USER_LANG							5
#define SERVICE_ID_GET_TIMEZONE								6
#define SERVICE_ID_GET_MAILDIR								7
#define SERVICE_ID_GET_ID_FFROM_USERNAME					8
#define SERVICE_ID_GET_USERNAME_FROM_ID						9
#define SERVICE_ID_GET_USER_IDS								10
#define SERVICE_ID_GET_DOMAIN_IDS							11
#define SERVICE_ID_GET_ID_FROM_MAILDIR						12
#define SERVICE_ID_GET_ID_FROM_HOMEDIR						13
#define SERVICE_ID_SEND_MAIL								14
#define SERVICE_ID_GET_MIME_POOL							15
#define SERVICE_ID_LOG_INFO									16
#define SERVICE_ID_GET_HANDLE								17

#define E(s) decltype(exmdb_client_ ## s) exmdb_client_ ## s;
E(get_named_propid)
E(get_named_propname)
E(get_store_property)
E(get_folder_property)
E(delete_message)
E(check_message_owner)
E(get_instance_property)
E(set_instance_property)
E(remove_instance_property)
E(get_message_property)
E(set_message_property)
E(remove_message_property)
#undef E
#define EXMIDL(n, p) decltype(exmdb_client_ ## n) exmdb_client_ ## n;
#define IDLOUT
#include <gromox/exmdb_idef.hpp>
#undef EXMIDL
#undef IDLOUT

int exmdb_client_run()
{
	void (*register_proc)(void*);
	void (*pass_service)(int, void*);
	
#define EXMIDL(n, p) do { \
	query_service2("exmdb_client_" #n, exmdb_client_ ## n); \
	if ((exmdb_client_ ## n) == nullptr) { \
		printf("[%s]: failed to get the \"%s\" service\n", "exchange_emsmdb", "exmdb_client_" #n); \
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
		printf("[%s]: failed to get the \"%s\" service\n", "exchange_emsmdb", (s)); \
		return -1; \
	} \
} while (false)

	E(register_proc, "exmdb_client_register_proc");
	register_proc(reinterpret_cast<void *>(emsmdb_interface_event_proc));

	E(pass_service, "pass_service");
#undef E
	/* pass the service functions to exmdb_provider */
#define E(s) reinterpret_cast<void *>(s)
	pass_service(SERVICE_ID_LANG_TO_CHARSET, E(common_util_lang_to_charset));
	pass_service(SERVICE_ID_CPID_TO_CHARSET, E(common_util_cpid_to_charset));
	pass_service(SERVICE_ID_GET_USER_DISPLAYNAME, E(common_util_get_user_displayname));
	pass_service(SERVICE_ID_CHECK_MLIST_INCLUDE, E(common_util_check_mlist_include));
	pass_service(SERVICE_ID_GET_USER_LANG, E(common_util_get_user_lang));
	pass_service(SERVICE_ID_GET_TIMEZONE, E(common_util_get_timezone));
	pass_service(SERVICE_ID_GET_MAILDIR, E(common_util_get_maildir));
	pass_service(SERVICE_ID_GET_ID_FFROM_USERNAME, E(common_util_get_id_from_username));
	pass_service(SERVICE_ID_GET_USERNAME_FROM_ID, E(common_util_get_username_from_id));
	pass_service(SERVICE_ID_GET_USER_IDS, E(common_util_get_user_ids));
	pass_service(SERVICE_ID_GET_DOMAIN_IDS, E(common_util_get_domain_ids));
	pass_service(SERVICE_ID_GET_ID_FROM_MAILDIR, E(common_util_get_id_from_maildir));
	pass_service(SERVICE_ID_GET_ID_FROM_HOMEDIR, E(common_util_get_id_from_homedir));
	pass_service(SERVICE_ID_SEND_MAIL, E(cu_send_mail));
	pass_service(SERVICE_ID_GET_MIME_POOL, E(common_util_get_mime_pool));
	pass_service(SERVICE_ID_LOG_INFO, E(log_info));
	pass_service(SERVICE_ID_GET_HANDLE, E(emsmdb_interface_get_handle));
#undef E
	return 0;
}

BOOL exmdb_client_get_named_propid(const char *dir,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propnames.count = 1;
	tmp_propnames.ppropname = (PROPERTY_NAME*)ppropname;
	if (!exmdb_client_get_named_propids(dir, b_create,
	    &tmp_propnames, &tmp_propids))
		return FALSE;	
	*ppropid = *tmp_propids.ppropid;
	return TRUE;
}

BOOL exmdb_client_get_named_propname(const char *dir,
	uint16_t propid, PROPERTY_NAME *ppropname)
{
	PROPID_ARRAY tmp_propids;
	PROPNAME_ARRAY tmp_propnames;
	
	tmp_propids.count = 1;
	tmp_propids.ppropid = &propid;
	if (!exmdb_client_get_named_propnames(dir, &tmp_propids, &tmp_propnames))
		return FALSE;	
	*ppropname = *tmp_propnames.ppropname;
	return TRUE;
}

BOOL exmdb_client_get_store_property(const char *dir,
	uint32_t cpid, uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client_get_store_properties(dir, cpid,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_get_folder_property(const char *dir,
	uint32_t cpid, uint64_t folder_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client_get_folder_properties(dir, cpid, folder_id,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_delete_message(const char *dir,
	int account_id, uint32_t cpid, uint64_t folder_id,
	uint64_t message_id, BOOL b_hard, BOOL *pb_done)
{
	BOOL b_partial;
	EID_ARRAY message_ids;
	
	message_ids.count = 1;
	message_ids.pids = &message_id;
	if (!exmdb_client_delete_messages(dir, account_id, cpid, nullptr,
	    folder_id, &message_ids, b_hard, &b_partial))
		return FALSE;	
	*pb_done = !b_partial;
	return TRUE;
}

BOOL exmdb_client_get_instance_property(
	const char *dir, uint32_t instance_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client_get_instance_properties(dir, 0, instance_id,
	    &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_instance_property(
	const char *dir, uint32_t instance_id,
	const TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (!exmdb_client_set_instance_properties(dir, instance_id,
	    &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_instance_property(const char *dir,
	uint32_t instance_id, uint32_t proptag, uint32_t *presult)
{
	PROPTAG_ARRAY tmp_proptags;
	PROBLEM_ARRAY tmp_problems;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client_remove_instance_properties(dir, instance_id,
	    &tmp_proptags, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_get_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	uint32_t proptag, void **ppval)
{
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	if (!exmdb_client_get_message_properties(dir, username, cpid,
	    message_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	*ppval = tmp_propvals.count == 0 ? nullptr : tmp_propvals.ppropval->pvalue;
	return TRUE;
}

BOOL exmdb_client_set_message_property(const char *dir,
	const char *username, uint32_t cpid, uint64_t message_id,
	TAGGED_PROPVAL *ppropval, uint32_t *presult)
{
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = (TAGGED_PROPVAL*)ppropval;
	if (!exmdb_client_set_message_properties(dir, username, cpid,
	    message_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	*presult = tmp_problems.count == 0 ? 0 : tmp_problems.pproblem->err;
	return TRUE;
}

BOOL exmdb_client_remove_message_property(const char *dir,
	uint32_t cpid, uint64_t message_id, uint32_t proptag)
{
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 1;
	tmp_proptags.pproptag = &proptag;
	return exmdb_client_remove_message_properties(dir, cpid,
	       message_id, &tmp_proptags);
}

BOOL exmdb_client_check_message_owner(const char *dir,
	uint64_t message_id, const char *username, BOOL *pb_owner)
{
	BINARY *pbin;
	EXT_PULL ext_pull;
	char tmp_name[UADDR_SIZE];
	EMSAB_ENTRYID ab_entryid;
	
	if (!exmdb_client_get_message_property(dir, nullptr, 0,
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
	if (!common_util_essdn_to_username(ab_entryid.px500dn,
	    tmp_name, gromox::arsizeof(tmp_name))) {
		*pb_owner = false;
		return TRUE;
	}
	*pb_owner = strcasecmp(username, tmp_name) == 0 ? TRUE : false;
	return TRUE;
}

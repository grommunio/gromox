#ifndef _H_LOGON_OBJECT_
#define _H_LOGON_OBJECT_
#include "element_data.h"
#include "mapi_types.h"
#include "str_hash.h"
#include "int_hash.h"

#define LOGON_MODE_OWNER				0
#define LOGON_MODE_DELEGATE				1
#define LOGON_MODE_GUEST				2

typedef struct _LOGON_OBJECT {
	uint8_t logon_flags;
	uint32_t open_flags;
	int logon_mode;
	int account_id;
	char account[256];
	char dir[256];
	GUID mailbox_guid;
	PROPERTY_GROUPINFO *pgpinfo;
	INT_HASH_TABLE *ppropid_hash;
	STR_HASH_TABLE *ppropname_hash;
	DOUBLE_LIST group_list;
} LOGON_OBJECT;


LOGON_OBJECT* logon_object_create(uint8_t logon_flags,
	uint32_t open_flags, int logon_mode, int account_id,
	const char *account, const char *dir, GUID mailbox_guid);

void logon_object_free(LOGON_OBJECT *plogon);

BOOL logon_object_check_private(LOGON_OBJECT *plogon);

int logon_object_get_mode(LOGON_OBJECT *plogon);

int logon_object_get_account_id(LOGON_OBJECT *plogon);

const char* logon_object_get_account(LOGON_OBJECT *plogon);

const char* logon_object_get_dir(LOGON_OBJECT *plogon);

GUID logon_object_get_mailbox_guid(LOGON_OBJECT *plogon);

BOOL logon_object_get_named_propname(LOGON_OBJECT *plogon,
	uint16_t propid, PROPERTY_NAME *ppropname);

BOOL logon_object_get_named_propnames(LOGON_OBJECT *plogon,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

BOOL logon_object_get_named_propid(LOGON_OBJECT *plogon,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid);

BOOL logon_object_get_named_propids(LOGON_OBJECT *plogon,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);

/* used for message partial change information when saving 
	message, the return value is maintained by logon object,
	do not free it outside */
PROPERTY_GROUPINFO* logon_object_get_last_property_groupinfo(
	LOGON_OBJECT *plogon);

/* same as logon_object_get_last_property_groupinfo,
	do not free it outside */
PROPERTY_GROUPINFO* logon_object_get_property_groupinfo(
	LOGON_OBJECT *plogon, uint32_t group_id);

BOOL logon_object_get_all_proptags(LOGON_OBJECT *plogon,
	PROPTAG_ARRAY *pproptags);

BOOL logon_object_get_properties(LOGON_OBJECT *plogon,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL logon_object_set_properties(LOGON_OBJECT *plogon,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems);

BOOL logon_object_remove_properties(LOGON_OBJECT *plogon,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems);

#endif /* _H_LOGON_OBJECT_ */

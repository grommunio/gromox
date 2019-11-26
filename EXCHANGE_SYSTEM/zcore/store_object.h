#ifndef _H_STORE_OBJECT_
#define _H_STORE_OBJECT_
#include "element_data.h"
#include "mapi_types.h"
#include "str_hash.h"
#include "int_hash.h"

typedef struct _STORE_OBJECT {
	BOOL b_private;
	int account_id;
	char account[256];
	char dir[256];
	GUID mailbox_guid;
	PROPERTY_GROUPINFO *pgpinfo;
	INT_HASH_TABLE *ppropid_hash;
	STR_HASH_TABLE *ppropname_hash;
	DOUBLE_LIST group_list;
} STORE_OBJECT;


struct _PERMISSION_SET;

STORE_OBJECT* store_object_create(BOOL b_private,
	int account_id, const char *account, const char *dir);

void store_object_free(STORE_OBJECT *pstore);

BOOL store_object_check_private(STORE_OBJECT *pstore);

BOOL store_object_check_owner_mode(STORE_OBJECT *pstore);

int store_object_get_account_id(STORE_OBJECT *pstore);

const char* store_object_get_account(STORE_OBJECT *pstore);

const char* store_object_get_dir(STORE_OBJECT *pstore);

GUID store_object_get_mailbox_guid(STORE_OBJECT *pstore);

BOOL store_object_get_named_propname(STORE_OBJECT *pstore,
	uint16_t propid, PROPERTY_NAME *ppropname);

BOOL store_object_get_named_propnames(STORE_OBJECT *pstore,
	const PROPID_ARRAY *ppropids, PROPNAME_ARRAY *ppropnames);

BOOL store_object_get_named_propid(STORE_OBJECT *pstore,
	BOOL b_create, const PROPERTY_NAME *ppropname,
	uint16_t *ppropid);

BOOL store_object_get_named_propids(STORE_OBJECT *pstore,
	BOOL b_create, const PROPNAME_ARRAY *ppropnames,
	PROPID_ARRAY *ppropids);

/* used for message partial change information when saving 
	message, the return value is maintained by logon object,
	do not free it outside */
PROPERTY_GROUPINFO* store_object_get_last_property_groupinfo(
	STORE_OBJECT *pstore);

/* same as store_object_get_last_property_groupinfo,
	do not free it outside */
PROPERTY_GROUPINFO* store_object_get_property_groupinfo(
	STORE_OBJECT *pstore, uint32_t group_id);

BOOL store_object_get_all_proptags(STORE_OBJECT *pstore,
	PROPTAG_ARRAY *pproptags);

BOOL store_object_get_properties(STORE_OBJECT *pstore,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals);

BOOL store_object_set_properties(STORE_OBJECT *pstore,
	const TPROPVAL_ARRAY *ppropvals);

BOOL store_object_remove_properties(STORE_OBJECT *pstore,
	const PROPTAG_ARRAY *pproptags);
	
BOOL store_object_get_permissions(STORE_OBJECT *pstore,
	struct _PERMISSION_SET *pperm_set);

#endif /* _H_STORE_OBJECT_ */

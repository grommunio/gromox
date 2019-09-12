#include "container_object.h"
#include "zarafa_server.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "tarray_set.h"
#include "mail_func.h"
#include "rop_util.h"
#include "ab_tree.h"
#include <stdio.h>

CONTAINER_OBJECT* container_object_create(
	uint8_t type, CONTAINER_ID id)
{
	CONTAINER_OBJECT *pcontainer;
	
	pcontainer = malloc(sizeof(CONTAINER_OBJECT));
	if (NULL == pcontainer) {
		return NULL;
	}
	memset(pcontainer, 0, sizeof(CONTAINER_OBJECT));
	pcontainer->type = type;
	pcontainer->id = id;
	return pcontainer;
}

void container_object_clear(
	CONTAINER_OBJECT *pcontainer)
{
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL == pcontainer->contents.pminid_array) {
			return;
		}
		if (NULL != pcontainer->contents.pminid_array->pl) {
			free(pcontainer->contents.pminid_array->pl);
		}
		free(pcontainer->contents.pminid_array);
		pcontainer->contents.pminid_array = NULL;
	} else {
		if (NULL != pcontainer->contents.prow_set) {
			tarray_set_free(pcontainer->contents.prow_set);
			pcontainer->contents.prow_set = NULL;
		}
	}
}

void container_object_free(CONTAINER_OBJECT *pcontainer)
{
	container_object_clear(pcontainer);
	free(pcontainer);
}

static BOOL container_object_match_contact_message(
	const TPROPVAL_ARRAY *ppropvals, const RESTRICTION *pfilter)
{
	int i, len;
	void *pvalue;
	
	switch (pfilter->rt) {
	case RESTRICTION_TYPE_AND:
		for (i=0; i<((RESTRICTION_AND_OR*)pfilter->pres)->count; i++) {
			if (FALSE == container_object_match_contact_message(ppropvals,
				&((RESTRICTION_AND_OR*)pfilter->pres)->pres[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case RESTRICTION_TYPE_OR:
		for (i=0; i<((RESTRICTION_AND_OR*)pfilter->pres)->count; i++) {
			if (TRUE == container_object_match_contact_message(ppropvals,
				&((RESTRICTION_AND_OR*)pfilter->pres)->pres[i])) {
				return TRUE;
			}
		}
		return FALSE;
	case RESTRICTION_TYPE_NOT:
		if (TRUE == container_object_match_contact_message(
			ppropvals, &((RESTRICTION_NOT*)pfilter->pres)->res)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_CONTENT:
		if (PROPVAL_TYPE_WSTRING != (((RESTRICTION_CONTENT*)
			pfilter->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if ((((RESTRICTION_CONTENT*)pfilter->pres)->proptag & 0xFFFF)
			!= (((RESTRICTION_CONTENT*)pfilter->pres)->propval.proptag
			& 0xFFFF)) {
			return FALSE;
		}
		pvalue = common_util_get_propvals(ppropvals,
			((RESTRICTION_CONTENT*)pfilter->pres)->proptag);
		if (NULL == pvalue) {
			return FALSE;	
		}
		switch (((RESTRICTION_CONTENT*)
			pfilter->pres)->fuzzy_level & 0xFFFF) {
		case FUZZY_LEVEL_FULLSTRING:
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strcasecmp(((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
			} else {
				if (0 == strcmp(((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		case FUZZY_LEVEL_SUBSTRING:
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			} else {
				if (NULL != strstr(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		case FUZZY_LEVEL_PREFIX:
			len = strlen(((RESTRICTION_CONTENT*)
				pfilter->pres)->propval.pvalue);
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE | FUZZY_LEVEL_LOOSE)) {
				if (0 == strncasecmp(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, len)) {
					return TRUE;
				}
			} else {
				if (0 == strncmp(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, len)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		return FALSE;
	case RESTRICTION_TYPE_PROPERTY:
		if (PROP_TAG_ANR == ((RESTRICTION_PROPERTY*)pfilter->pres)->proptag) {
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_SMTPADDRESS);
			if (NULL != pvalue) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_DISPLAYNAME);
			if (NULL != pvalue) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		pvalue = common_util_get_propvals(ppropvals,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		return propval_compare_relop(
			((RESTRICTION_PROPERTY*)pfilter->pres)->relop,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag&0xFFFF,
			pvalue, ((RESTRICTION_PROPERTY*)pfilter->pres)->propval.pvalue);
	case RESTRICTION_TYPE_PROPCOMPARE:
		return FALSE;
	case RESTRICTION_TYPE_BITMASK:
		 if (PROPVAL_TYPE_LONG != (((RESTRICTION_BITMASK*)
			pfilter->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		pvalue = common_util_get_propvals(ppropvals,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_BITMASK*)pfilter->pres)->bitmask_relop) {
		case BITMASK_RELOP_EQZ:
			if (0 == (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pfilter->pres)->mask)) {
				return TRUE;
			}
			break;
		case BITMASK_RELOP_NEZ:
			if (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pfilter->pres)->mask) {
				return TRUE;
			}
			break;
		}
		return FALSE;
	case RESTRICTION_TYPE_SIZE:
		return FALSE;
	case RESTRICTION_TYPE_EXIST:
		pvalue = common_util_get_propvals(ppropvals,
			((RESTRICTION_EXIST*)pfilter->pres)->proptag);
		if (NULL != pvalue) {
			return TRUE;	
		}
		return FALSE;
	case RESTRICTION_TYPE_SUBOBJ:
		return FALSE;
	}
}

static BOOL container_object_get_pidlids(PROPTAG_ARRAY *pproptags)
{
	int i;
	uint32_t handle;
	uint32_t lids[9];
	USER_INFO *pinfo;
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[9];
	
	pinfo = zarafa_server_get_info();
	handle = object_tree_get_store_handle(
		pinfo->ptree, TRUE, pinfo->user_id);
	pstore = object_tree_get_object(
		pinfo->ptree, handle, &mapi_type);
	if (NULL == pstore || MAPI_STORE != mapi_type) {
		return FALSE;
	}
	propnames.count = 9;
	propnames.ppropname = propname_buff;
	/* PidLidEmail1DisplayName */
	propname_buff[0].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[0].guid);
	lids[0] = 0x8080;
	propname_buff[0].plid = &lids[0];
	/* PidLidEmail1AddressType */
	propname_buff[1].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[1].guid);
	lids[1] = 0x8082;
	propname_buff[1].plid = &lids[1];
	/* PidLidEmail1EmailAddress */
	propname_buff[2].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[2].guid);
	lids[2] = 0x8083;
	propname_buff[2].plid = &lids[2];
	/* PidLidEmail2DisplayName */
	propname_buff[3].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[3].guid);
	lids[3] = 0x8090;
	propname_buff[3].plid = &lids[3];
	/* PidLidEmail2AddressType */
	propname_buff[4].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[4].guid);
	lids[4] = 0x8092;
	propname_buff[4].plid = &lids[4];
	/* PidLidEmail2EmailAddress */
	propname_buff[5].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[5].guid);
	lids[5] = 0x8093;
	propname_buff[5].plid = &lids[5];
	/* PidLidEmail3DisplayName */
	propname_buff[6].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[6].guid);
	lids[6] = 0x80A0;
	propname_buff[6].plid = &lids[6];
	/* PidLidEmail3AddressType */
	propname_buff[7].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[7].guid);
	lids[7] = 0x80A2;
	propname_buff[7].plid = &lids[7];
	/* PidLidEmail3EmailAddress */
	propname_buff[8].kind = KIND_LID;
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[8].guid);
	lids[8] = 0x80A3;
	propname_buff[8].plid = &lids[8];
	if (FALSE == store_object_get_named_propids(
		pstore, FALSE, &propnames, &propids) ||
		9 != propids.count) {
		return FALSE;
	}
	for (i=0; i<9; i++) {
		pproptags->pproptag[i] = propids.ppropid[i];
		pproptags->pproptag[i] <<= 16;
		pproptags->pproptag[i] |= PROPVAL_TYPE_WSTRING;
	}
	pproptags->count = 9;
	return TRUE;
}

static BINARY* container_object_folder_to_addressbook_entryid(
	BOOL b_private, int db_id, uint64_t folder_id)
{
	uint8_t type;
	BINARY *pbin;
	char x500dn[128];
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	
	if (TRUE == b_private) {
		type = LOC_TYPE_PRIVATE_FOLDER;
	} else {
		type = LOC_TYPE_PUBLIC_FOLDER;
	}
	memcpy(x500dn, "/exmdb=", 7);
	common_util_exmdb_locinfo_to_string(
		type, db_id, folder_id, x500dn + 7);
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
								tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
	tmp_entryid.px500dn = x500dn;
	pbin = common_util_alloc(sizeof(BINARY));
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pb = common_util_alloc(256);
	if (NULL == pbin->pb) {
		return NULL;
	}
	ext_buffer_push_init(&ext_push, pbin->pb, 256, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

static BINARY* container_object_message_to_addressbook_entryid(
	BOOL b_private, int db_id, uint64_t message_id, int num)
{
	int len;
	uint8_t type;
	BINARY *pbin;
	char x500dn[128];
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	
	if (TRUE == b_private) {
		type = LOC_TYPE_PRIVATE_MESSAGE;
	} else {
		type = LOC_TYPE_PUBLIC_MESSAGE;
	}
	memcpy(x500dn, "/exmdb=", 7);
	common_util_exmdb_locinfo_to_string(
		type, db_id, message_id, x500dn + 7);
	len = strlen(x500dn);
	sprintf(x500dn + len, ":%d", num);
	tmp_entryid.flags = 0;
	memcpy(tmp_entryid.provider_uid,
		common_util_get_muidzcsab(), 16);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_REMOTE_USER;
	tmp_entryid.px500dn = x500dn;
	pbin = common_util_alloc(sizeof(BINARY));
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pb = common_util_alloc(256);
	if (NULL == pbin->pb) {
		return NULL;
	}
	ext_buffer_push_init(&ext_push, pbin->pb, 256, EXT_FLAG_UTF16);
	if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
		&ext_push, &tmp_entryid)) {
		return NULL;
	}
	pbin->cb = ext_push.offset;
	return pbin;
}

BOOL container_object_load_user_table(
	CONTAINER_OBJECT *pcontainer,
	const RESTRICTION *prestriction)
{
	int i, j, k;
	void *pvalue;
	char *paddress;
	AB_BASE *pbase;
	BINARY tmp_bin;
	uint32_t handle;
	uint32_t tmp_int;
	uint32_t row_num;
	USER_INFO *pinfo;
	uint32_t table_id;
	uint8_t mapi_type;
	char username[256];
	TARRAY_SET tmp_set;
	char *pdisplayname;
	char *paddress_type;
	STORE_OBJECT *pstore;
	TAGGED_PROPVAL propval;
	PROPTAG_ARRAY proptags;
	LONG_ARRAY minid_array;
	BINARY *pparent_entryid;
	LONG_ARRAY *pminid_array;
	TPROPVAL_ARRAY *ppropvals;
	uint32_t proptag_buff[25];
	static uint32_t tmp_proptags[] = {
			PROP_TAG_NICKNAME,
			PROP_TAG_SURNAME,
			PROP_TAG_GIVENNAME,
			PROP_TAG_MIDDLENAME,
			PROP_TAG_TITLE,
			PROP_TAG_PRIMARYTELEPHONENUMBER,
			PROP_TAG_MOBILETELEPHONENUMBER,
			PROP_TAG_HOMEADDRESSSTREET,
			PROP_TAG_COMMENT,
			PROP_TAG_COMPANYNAME,
			PROP_TAG_DEPARTMENTNAME,
			PROP_TAG_OFFICELOCATION,
			PROP_TAG_CREATIONTIME
	};
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL == prestriction ||
			NULL != pcontainer->contents.pminid_array) {
			return TRUE;
		}
		pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		pinfo = zarafa_server_get_info();
		if (FALSE == ab_tree_match_minids(
			pbase, pcontainer->id.abtree_id.minid,
			pinfo->cpid, prestriction, &minid_array)) {
			ab_tree_put_base(pbase);
			return FALSE;	
		}
		ab_tree_put_base(pbase);
		pminid_array = malloc(sizeof(LONG_ARRAY));
		if (NULL == pminid_array) {
			return FALSE;
		}
		pcontainer->contents.pminid_array = pminid_array;
		pminid_array->count = minid_array.count;
		if (0 == minid_array.count) {
			pminid_array->pl = NULL;
			return TRUE;
		}
		pminid_array->pl = malloc(sizeof(uint32_t)*minid_array.count);
		if (NULL == pminid_array->pl) {
			free(pcontainer->contents.pminid_array);
			pcontainer->contents.pminid_array = NULL;
			return FALSE;
		}
		memcpy(pminid_array->pl, minid_array.pl,
			sizeof(uint32_t)*minid_array.count);
		return TRUE;
	}
	if (NULL != pcontainer->contents.prow_set) {
		return TRUE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == exmdb_client_load_content_table(pinfo->maildir,
		pinfo->cpid, pcontainer->id.exmdb_id.folder_id, NULL, 0,
		NULL, NULL, &table_id, &row_num)) {
		return FALSE;
	}
	if (row_num > 0) {
		proptags.pproptag = proptag_buff;
		if (FALSE == container_object_get_pidlids(&proptags)) {
			return FALSE;
		}
		proptags.pproptag[proptags.count] =
						PROP_TAG_DISPLAYNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_NICKNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
							PROP_TAG_TITLE;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_SURNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_GIVENNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_MIDDLENAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
			PROP_TAG_PRIMARYTELEPHONENUMBER;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
			PROP_TAG_MOBILETELEPHONENUMBER;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
				PROP_TAG_HOMEADDRESSSTREET;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_COMMENT;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
						PROP_TAG_COMPANYNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
					PROP_TAG_DEPARTMENTNAME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
					PROP_TAG_OFFICELOCATION;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
					PROP_TAG_CREATIONTIME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
							PROP_TAG_MID;
		proptags.count ++;
		if (FALSE == exmdb_client_query_table(
			pinfo->maildir, NULL, pinfo->cpid,
			table_id, &proptags, 0, row_num,
			&tmp_set)) {
			return FALSE;
		}
		pparent_entryid = container_object_folder_to_addressbook_entryid(
				TRUE, pinfo->user_id, pcontainer->id.exmdb_id.folder_id);
		if (NULL == pparent_entryid) {
			return FALSE;
		}
		handle = object_tree_get_store_handle(
			pinfo->ptree, TRUE, pinfo->user_id);
		pstore = object_tree_get_object(
			pinfo->ptree, handle, &mapi_type);
		if (NULL == pstore || MAPI_STORE != mapi_type) {
			return FALSE;
		}
	} else {
		tmp_set.count = 0;
	}
	exmdb_client_unload_table(pinfo->maildir, table_id);
	pcontainer->contents.prow_set = tarray_set_init();
	if (NULL == pcontainer->contents.prow_set) {
		return FALSE;
	}
	for (i=0; i<tmp_set.count; i++) {
		for (j=0; j<3; j++) {
			pdisplayname = common_util_get_propvals(
				tmp_set.pparray[i], proptags.pproptag[3*j]);
			if (NULL == pdisplayname) {
				pdisplayname = common_util_get_propvals(
					tmp_set.pparray[i], PROP_TAG_DISPLAYNAME);
			}
			paddress_type = common_util_get_propvals(
				tmp_set.pparray[i], proptags.pproptag[3*j+1]);
			paddress = common_util_get_propvals(
				tmp_set.pparray[i], proptags.pproptag[3*j+2]);
			if (NULL == paddress || NULL == paddress_type) {
				continue;
			}
			if (0 == strcasecmp(paddress_type, "EX")) {
				if (FALSE == common_util_essdn_to_username(
					paddress, username)) {
					continue;
				}
			} else if (0 == strcasecmp(paddress_type, "SMTP")) {
				strncpy(username, paddress, sizeof(username));
			} else {
				continue;
			}
			ppropvals = tpropval_array_init();
			if (NULL == ppropvals) {
				return FALSE;
			}
			propval.proptag = PROP_TAG_SMTPADDRESS;
			propval.pvalue = username;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ACCOUNT;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ADDRESSTYPE;
			propval.pvalue = "SMTP";
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_EMAILADDRESS;
			propval.pvalue = username;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (NULL != pdisplayname) {
				propval.proptag = PROP_TAG_DISPLAYNAME;
				propval.pvalue = pdisplayname;
				if (FALSE == tpropval_array_set_propval(
					ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
				propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
				if (FALSE == tpropval_array_set_propval(
					ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
				propval.proptag = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
				if (FALSE == tpropval_array_set_propval(
					ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
			}
			for (k=0; k<sizeof(tmp_proptags)/sizeof(uint32_t); k++) {
				propval.proptag = tmp_proptags[k];
				propval.pvalue = common_util_get_propvals(
					tmp_set.pparray[i], propval.proptag);
				if (NULL != propval.pvalue) {
					if (FALSE == tpropval_array_set_propval(
						ppropvals, &propval)) {
						tpropval_array_free(ppropvals);
						return FALSE;
					}
				}
			}
			propval.proptag = PROP_TAG_PARENTENTRYID;
			propval.pvalue = pparent_entryid;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			pvalue = common_util_get_propvals(
				tmp_set.pparray[i], PROP_TAG_MID);
			if (NULL == pvalue) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ENTRYID;
			propval.pvalue = container_object_message_to_addressbook_entryid(
								TRUE, pinfo->user_id, *(uint64_t*)pvalue, j);
			if (NULL == propval.pvalue) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_RECORDKEY;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_TEMPLATEID;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ORIGINALENTRYID;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ABPROVIDERID;
			propval.pvalue = &tmp_bin;
			tmp_bin.cb = 16;
			tmp_bin.pb = common_util_get_muidzcsab();
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_OBJECTTYPE;
			propval.pvalue = &tmp_int;
			tmp_int = OBJECT_USER;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_DISPLAYTYPE;
			propval.pvalue = &tmp_int;
			tmp_int = DISPLAY_TYPE_MAILUSER;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_DISPLAYTYPEEX;
			if (FALSE == tpropval_array_set_propval(
				ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (NULL != prestriction && FALSE ==
				container_object_match_contact_message(
				ppropvals, prestriction)) {
				tpropval_array_free(ppropvals);
				continue;
			}
			if (FALSE == tarray_set_append_internal(
				pcontainer->contents.prow_set, ppropvals)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
		}
	}
	return TRUE;
}

BOOL container_object_fetch_special_property(
	uint8_t special_type, uint32_t proptag, void **ppvalue)
{
	void *pvalue;
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	switch (proptag) {
	case PROP_TAG_ABPROVIDERID:
		*ppvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY*)*ppvalue)->cb = 16;
		((BINARY*)*ppvalue)->pb = common_util_get_muidecsab();
		return TRUE;
	case PROP_TAG_ENTRYID:
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		ab_entryid.flags = 0;
		rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
									ab_entryid.provider_uid);
		ab_entryid.version = 1;
		ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
		if (SPECIAL_CONTAINER_GAL == special_type) {
			ab_entryid.px500dn = "";
		} else {
			ab_entryid.px500dn = "/";
		}
		((BINARY*)pvalue)->pb = common_util_alloc(128);
		if (NULL == ((BINARY*)pvalue)->pb) {
			return FALSE;
		}
		ext_buffer_push_init(&ext_push, ((BINARY*)pvalue)->pb, 128, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
			&ext_push, &ab_entryid)) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = ext_push.offset;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_CONTAINERFLAGS:
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = AB_RECIPIENTS |
			AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPTH:
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DISPLAYNAME:
		if (SPECIAL_CONTAINER_GAL == special_type) {
			*ppvalue = "Global Address List";
		} else {
			*ppvalue = "Steep Contact Folders";
		}
		return TRUE;
	case PROP_TAG_ADDRESSBOOKISMASTER:
		pvalue = common_util_alloc(sizeof(uint8_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	}
	*ppvalue = NULL;
	return TRUE;
}

static BOOL container_object_fetch_special_properties(
	uint8_t special_type, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	
	ppropvals->ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (FALSE == container_object_fetch_special_property(
			special_type, pproptags->pproptag[i], &pvalue)) {
			return FALSE;	
		}
		if (NULL == pvalue) {
			continue;
		}
		ppropvals->ppropval[ppropvals->count].proptag =
									pproptags->pproptag[i];
		ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
		ppropvals->count ++;
	}
	return TRUE;
}

static BOOL container_object_fetch_folder_properties(
	const TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *pout_propvals)
{
	int i;
	int count;
	BOOL b_sub;
	void *pvalue;
	USER_INFO *pinfo;
	uint64_t folder_id;
	
	pvalue = common_util_get_propvals(ppropvals, PROP_TAG_FOLDERID);
	if (NULL == pvalue) {
		return FALSE;
	}
	folder_id = *(uint64_t*)pvalue;
	pout_propvals->count = 0;
	pout_propvals->ppropval = common_util_alloc(
		pproptags->count*sizeof(TAGGED_PROPVAL));
	if (NULL == pout_propvals->ppropval) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		pout_propvals->ppropval[pout_propvals->count].proptag =
										pproptags->pproptag[i];
		switch (pproptags->pproptag[i]) {
		case PROP_TAG_ABPROVIDERID:
			pvalue = common_util_alloc(sizeof(BINARY));
			if (NULL == pvalue) {
				return FALSE;
			}
			((BINARY*)pvalue)->cb = 16;
			((BINARY*)pvalue)->pb = common_util_get_muidzcsab();
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_ENTRYID:
		case PROP_TAG_PARENTENTRYID:
			pinfo = zarafa_server_get_info();
			if (PROP_TAG_PARENTENTRYID == pproptags->pproptag[i]) {
				if (folder_id == rop_util_make_eid_ex(
					1, PRIVATE_FID_CONTACTS)) {
					if (FALSE == container_object_fetch_special_property(
						SPECIAL_CONTAINER_PROVIDER, PROP_TAG_ENTRYID,
						&pvalue)) {
						return FALSE;	
					}
				} else {
					pvalue = common_util_get_propvals(
						ppropvals, PROP_TAG_PARENTFOLDERID);
					if (NULL == pvalue) {
						return FALSE;
					}
					pvalue = container_object_folder_to_addressbook_entryid(
									TRUE, pinfo->user_id, *(uint64_t*)pvalue);
				}
			} else {
				pvalue = container_object_folder_to_addressbook_entryid(
										TRUE, pinfo->user_id, folder_id);
			}
			if (NULL == pvalue) {
				return FALSE;
			}
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_CONTAINERFLAGS:
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_SUBFOLDERS);
			if (NULL == pvalue || 0 == *(uint32_t*)pvalue) {
				b_sub = FALSE;
			} else {
				b_sub = TRUE;
			}
			pvalue = common_util_alloc(sizeof(uint32_t));
			if (NULL == pvalue) {
				return FALSE;
			}
			if (TRUE == b_sub) {
				*(uint32_t*)pvalue = AB_RECIPIENTS | AB_UNMODIFIABLE;
			} else {
				*(uint32_t*)pvalue = AB_RECIPIENTS |
					AB_SUBCONTAINERS | AB_UNMODIFIABLE;
			}
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_DEPTH:
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_FOLDERPATHNAME);
			if (NULL == pvalue) {
				return FALSE;
			}
			count = 0;
			for (; '\0'!=*(char*)pvalue; pvalue++) {
				if ('\\' == *(char*)pvalue) {
					count ++;
				}
			}
			if (count < 3) {
				return FALSE;
			}
			count -= 2;
			pvalue = common_util_alloc(sizeof(uint32_t));
			if (NULL == pvalue) {
				return FALSE;
			}
			*(uint32_t*)pvalue = count;
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_DISPLAYNAME:
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_DISPLAYNAME);
			if (NULL == pvalue) {
				return FALSE;
			}
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_ADDRESSBOOKISMASTER:
			pvalue = common_util_alloc(sizeof(uint8_t));
			if (NULL == pvalue) {
				return FALSE;
			}
			*(uint8_t*)pvalue = 0;
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		}
	}
	return TRUE;
}

static const PROPTAG_ARRAY* container_object_get_folder_proptags()
{
	static PROPTAG_ARRAY proptags;
	static uint32_t proptag_buff[] = {
					PROP_TAG_FOLDERID,
					PROP_TAG_SUBFOLDERS,
					PROP_TAG_DISPLAYNAME,
					PROP_TAG_CONTAINERCLASS,
					PROP_TAG_FOLDERPATHNAME,
					PROP_TAG_PARENTFOLDERID,
					PROP_TAG_ATTRIBUTEHIDDEN};
	
	if (0 == proptags.count) {
		proptags.count = 7;
		proptags.pproptag = proptag_buff;
	}
	return &proptags;
}

BOOL container_object_get_properties(CONTAINER_OBJECT *pcontainer,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	AB_BASE *pbase;
	USER_INFO *pinfo;
	SIMPLE_TREE_NODE *pnode;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (0 == pcontainer->id.abtree_id.minid) {
			return container_object_fetch_special_properties(
				SPECIAL_CONTAINER_PROVIDER, pproptags, ppropvals);
		}
		pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		pnode = ab_tree_minid_to_node(pbase,
			pcontainer->id.abtree_id.minid);
		if (NULL == pnode) {
			ppropvals->count = 0;
			ab_tree_put_base(pbase);
			return TRUE;
		}
		if (FALSE == ab_tree_fetch_node_properties(
			pnode, pproptags, ppropvals)) {
			ab_tree_put_base(pbase);
			return FALSE;
		}
		ab_tree_put_base(pbase);
		return TRUE;
	} else {
		pinfo = zarafa_server_get_info();
		if (FALSE == exmdb_client_get_folder_properties(
			pinfo->maildir, pinfo->cpid,
			pcontainer->id.exmdb_id.folder_id,
			container_object_get_folder_proptags(),
			&tmp_propvals)) {
			return FALSE;
		}
		return container_object_fetch_folder_properties(
					&tmp_propvals, pproptags, ppropvals);
	}
}

BOOL container_object_get_container_table_num(
	CONTAINER_OBJECT *pcontainer, BOOL b_depth,
	uint32_t *pnum)
{
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	
	proptags.count = 0;
	proptags.pproptag = NULL;
	if (FALSE == container_object_query_container_table(
		pcontainer, &proptags, b_depth, 0, 0x7FFFFFFF,
		&tmp_set)) {
		return FALSE;	
	}
	*pnum = tmp_set.count;
	return TRUE;
}

void container_object_get_container_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static uint32_t proptag_buff[] = {
		PROP_TAG_ENTRYID,
		PROP_TAG_CONTAINERFLAGS,
		PROP_TAG_DEPTH,
		PROP_TAG_INSTANCEKEY,
		PROP_TAG_ADDRESSBOOKCONTAINERID,
		PROP_TAG_DISPLAYNAME,
		PROP_TAG_ADDRESSBOOKISMASTER,
		PROP_TAG_ADDRESSBOOKPARENTENTRYID,
		PROP_TAG_ABPROVIDERID
	};
	
	pproptags->count = 7;
	pproptags->pproptag = proptag_buff;
}

static BOOL container_object_get_specialtables_from_node(
	SIMPLE_TREE_NODE *pnode, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, TARRAY_SET *pset)
{
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
	TPROPVAL_ARRAY *ppropvals;
	
	count = (pset->count / 100 + 1) * 100;
	if (pset->count + 1 >= count) {
		count += 100;
		pparray = common_util_alloc(count*sizeof(TPROPVAL_ARRAY*));
		if (NULL == pparray) {
			return FALSE;
		}
		memcpy(pparray, pset->pparray,
			pset->count*sizeof(TPROPVAL_ARRAY*));
		pset->pparray = pparray;
	}
	pset->pparray[pset->count] =
		common_util_alloc(sizeof(TPROPVAL_ARRAY));
	if (NULL == pset->pparray[pset->count]) {
		return FALSE;
	}
	if (FALSE == ab_tree_fetch_node_properties(
		pnode, pproptags, pset->pparray[pset->count])) {
		return FALSE;	
	}
	pset->count ++;
	if (TRUE == b_depth && TRUE == ab_tree_has_child(pnode)) {
		pnode = simple_tree_node_get_child(pnode);
		do {
			if (ab_tree_get_node_type(pnode) < 0x80) {
				continue;
			}
			if (FALSE == container_object_get_specialtables_from_node(
				pnode, pproptags, TRUE, pset)) {
				return FALSE;	
			}
		} while (pnode=simple_tree_node_get_slibling(pnode));
	}
	return TRUE;
}

static BOOL container_object_query_folder_hierarchy(
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, TARRAY_SET *pset)
{
	int i;
	void *pvalue;
	uint32_t count;
	uint32_t row_num;
	USER_INFO *pinfo;
	uint32_t table_id;
	TARRAY_SET tmp_set;
	TPROPVAL_ARRAY **pparray;
	
	pinfo = zarafa_server_get_info();
	if (FALSE == exmdb_client_load_hierarchy_table(
		pinfo->maildir, folder_id, NULL, TABLE_FLAG_DEPTH,
		NULL, &table_id, &row_num)) {
		return FALSE;
	}
	if (0 == row_num) {
		tmp_set.count = 0;
	} else {
		if (FALSE == exmdb_client_query_table(
			pinfo->maildir, NULL, pinfo->cpid, table_id,
			container_object_get_folder_proptags(), 0,
			row_num, &tmp_set)) {
			return FALSE;
		}
	}
	exmdb_client_unload_table(pinfo->maildir, table_id);
	for (i=0; i<tmp_set.count; i++) {
		pvalue = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_ATTRIBUTEHIDDEN);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_CONTAINERCLASS);
		if (NULL == pvalue || 0 != strcasecmp(
			pvalue, "IPF.Contact")) {
			continue;
		}
		count = (pset->count / 100 + 1) * 100;
		if (pset->count + 1 >= count) {
			count += 100;
			pparray = common_util_alloc(count*sizeof(TPROPVAL_ARRAY*));
			if (NULL == pparray) {
				return FALSE;
			}
			memcpy(pparray, pset->pparray,
				pset->count*sizeof(TPROPVAL_ARRAY*));
			pset->pparray = pparray;
		}
		pset->pparray[pset->count] =
			common_util_alloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == pset->pparray[pset->count]) {
			return FALSE;
		}
		if (FALSE == container_object_fetch_folder_properties(
			tmp_set.pparray[i], pproptags, pset->pparray[pset->count])) {
			return FALSE;	
		}
		pset->count ++;
	}
	return TRUE;
}

BOOL container_object_query_container_table(
	CONTAINER_OBJECT *pcontainer, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, uint32_t start_pos, int32_t row_needed,
	TARRAY_SET *pset)
{
	int i, end_pos;
	AB_BASE *pbase;
	USER_INFO *pinfo;
	TARRAY_SET tmp_set;
	DOMAIN_NODE *pdnode;
	SINGLE_LIST_NODE *psnode;
	SIMPLE_TREE_NODE *ptnode;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (0 == row_needed) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	tmp_set.count = 0;
	tmp_set.pparray = common_util_alloc(sizeof(TPROPVAL_ARRAY*)*100);
	if (NULL == tmp_set.pparray) {
		return FALSE;
	}
	if (CONTAINER_TYPE_FOLDER == pcontainer->type) {
		if (FALSE == container_object_query_folder_hierarchy(
			pcontainer->id.exmdb_id.folder_id, pproptags,
			b_depth, &tmp_set)) {
			return FALSE;	
		}
	} else {
		pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
			tmp_set.pparray[tmp_set.count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			if (FALSE == container_object_fetch_special_properties(
				SPECIAL_CONTAINER_GAL, pproptags,
				tmp_set.pparray[tmp_set.count])) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			if (FALSE == container_object_fetch_special_properties(
				SPECIAL_CONTAINER_PROVIDER, pproptags,
				tmp_set.pparray[tmp_set.count])) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			pinfo = zarafa_server_get_info();
			if (FALSE == exmdb_client_get_folder_properties(pinfo->maildir,
				pinfo->cpid, rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
				container_object_get_folder_proptags(), &tmp_propvals)) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			if (FALSE == container_object_fetch_folder_properties(
				&tmp_propvals, pproptags, tmp_set.pparray[tmp_set.count])) {
				ab_tree_put_base(pbase);
				return FALSE;
			}
			tmp_set.count ++;
			if (TRUE == b_depth) {
				if (FALSE == container_object_query_folder_hierarchy(
					rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
					pproptags, TRUE, &tmp_set)) {
					ab_tree_put_base(pbase);
					return FALSE;	
				}
			}
			for (psnode=single_list_get_head(&pbase->list); NULL!=psnode;
				psnode=single_list_get_after(&pbase->list, psnode)) {
				pdnode = (DOMAIN_NODE*)psnode->pdata;
				ptnode = simple_tree_get_root(&pdnode->tree);
				if (FALSE == container_object_get_specialtables_from_node(
					ptnode, pproptags, b_depth, &tmp_set)) {
					ab_tree_put_base(pbase);
					return FALSE;
				}
			}
		} else {
			ptnode = ab_tree_minid_to_node(pbase,
				pcontainer->id.abtree_id.minid);
			if (NULL == ptnode) {
				ab_tree_put_base(pbase);
				pset->count = 0;
				pset->pparray = NULL;
				return TRUE;
			}
			if (NULL != (ptnode = simple_tree_node_get_child(ptnode))) {
				do {
					if (ab_tree_get_node_type(ptnode) < 0x80) {
						continue;
					}
					if (FALSE == container_object_get_specialtables_from_node(
						ptnode, pproptags, b_depth, &tmp_set)) {
						ab_tree_put_base(pbase);
						return FALSE;	
					}
				} while (ptnode=simple_tree_node_get_slibling(ptnode));
			}
		}
		ab_tree_put_base(pbase);
	}
	pset->count = 0;
	pset->pparray = common_util_alloc(
		sizeof(TPROPVAL_ARRAY*)*tmp_set.count);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	end_pos = start_pos + row_needed;
	if (row_needed > 0) {
		if (end_pos > tmp_set.count) {
			end_pos = tmp_set.count;
		}
		for (i=start_pos; i<end_pos; i++) {
			pset->pparray[pset->count] = tmp_set.pparray[i];
			pset->count ++;
		}
	} else {
		if (end_pos < -1) {
			end_pos = -1;
		}
		for (i=start_pos; i>end_pos; i--) {
			pset->pparray[pset->count] = tmp_set.pparray[i];
			pset->count ++;
		}
	}
	return TRUE;
}

BOOL container_object_get_user_table_num(
	CONTAINER_OBJECT *pcontainer, uint32_t *pnum)
{
	AB_BASE *pbase;
	SIMPLE_TREE_NODE *pnode;
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL != pcontainer->contents.pminid_array) {
			*pnum = pcontainer->contents.pminid_array->count;
			return TRUE;
		}
		pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		*pnum = 0;
		if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
			*pnum = single_list_get_nodes_num(&pbase->gal_list);
		} else if (0 == pcontainer->id.abtree_id.minid) {
			*pnum = 0;
		} else {
			pnode = ab_tree_minid_to_node(pbase,
				pcontainer->id.abtree_id.minid);
			if (NULL == pnode || NULL == (pnode =
				simple_tree_node_get_child(pnode))) {
				ab_tree_put_base(pbase);
				return TRUE;
			}
			do {
				if (ab_tree_get_node_type(pnode) > 0x80) {
					continue;
				}
				(*pnum) ++;
			} while (pnode=simple_tree_node_get_slibling(pnode));
		}
		ab_tree_put_base(pbase);
	} else {
		if (NULL == pcontainer->contents.prow_set) {
			if (FALSE == container_object_load_user_table(
				pcontainer, NULL)) {
				return FALSE;	
			}
		}
		*pnum = pcontainer->contents.prow_set->count;
	}
	return TRUE;
}

void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static uint32_t proptag_buff[] = {
		PROP_TAG_DISPLAYNAME,
		PROP_TAG_NICKNAME,
		PROP_TAG_SURNAME,
		PROP_TAG_GIVENNAME,
		PROP_TAG_MIDDLENAME,
		PROP_TAG_TITLE,
		PROP_TAG_PRIMARYTELEPHONENUMBER,
		PROP_TAG_MOBILETELEPHONENUMBER,
		PROP_TAG_HOMEADDRESSSTREET,
		PROP_TAG_COMMENT,
		PROP_TAG_COMPANYNAME,
		PROP_TAG_DEPARTMENTNAME,
		PROP_TAG_OFFICELOCATION,
		PROP_TAG_ADDRESSTYPE,
		PROP_TAG_SMTPADDRESS,
		PROP_TAG_EMAILADDRESS,
		PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE,
		PROP_TAG_ACCOUNT,
		PROP_TAG_TRANSMITTABLEDISPLAYNAME,
		PROP_TAG_ADDRESSBOOKPROXYADDRESSES,
		PROP_TAG_OBJECTTYPE,
		PROP_TAG_DISPLAYTYPE,
		PROP_TAG_DISPLAYTYPEEX,
		PROP_TAG_ENTRYID,
		PROP_TAG_RECORDKEY,
		PROP_TAG_ORIGINALENTRYID,
		PROP_TAG_SEARCHKEY,
		PROP_TAG_INSTANCEKEY,
		PROP_TAG_MAPPINGSIGNATURE,
		PROP_TAG_SENDRICHINFO,
		PROP_TAG_TEMPLATEID,
		PROP_TAG_ADDRESSBOOKOBJECTGUID,
		PROP_TAG_CREATIONTIME,
		PROP_TAG_THUMBNAILPHOTO
	};
	pproptags->count = 34;
	pproptags->pproptag = proptag_buff;
}

BOOL container_object_query_user_table(
	CONTAINER_OBJECT *pcontainer, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	int i;
	AB_BASE *pbase;
	BOOL b_forward;
	uint32_t first_pos;
	uint32_t row_count;
	SINGLE_LIST_NODE *psnode;
	SIMPLE_TREE_NODE *ptnode;
	TPROPVAL_ARRAY *ppropvals;
	
	if (0 == row_needed) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	} else if (row_needed > 0) {
		b_forward = TRUE;
		first_pos = start_pos;
		row_count = row_needed;
	} else {
		b_forward = FALSE;
		if (start_pos + 1 + row_needed < 0) {
			first_pos = 0;
			row_count = start_pos + 1;
		} else {
			first_pos = start_pos + 1 + row_needed;
			row_count = (-1)*row_needed;
		}
	}
	pset->count = 0;
	pset->pparray = common_util_alloc(row_count*sizeof(void*));
	if (NULL == pset->pparray) {
		return FALSE;
	}
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL != pcontainer->contents.pminid_array &&
			0 == pcontainer->contents.pminid_array->count) {
			pset->count = 0;
			pset->pparray = NULL;
			return TRUE;
		}
		pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		if (NULL != pcontainer->contents.pminid_array) {
			for (i=first_pos; i<first_pos+row_count&&
				i<pcontainer->contents.pminid_array->count; i++) {
				ptnode = ab_tree_minid_to_node(pbase,
					pcontainer->contents.pminid_array->pl[i]);
				if (NULL == ptnode) {
					continue;
				}
				pset->pparray[pset->count] =
					common_util_alloc(sizeof(TPROPVAL_ARRAY));
				if (NULL == pset->pparray[pset->count]) {
					ab_tree_put_base(pbase);
					return FALSE;
				}
				if (FALSE == ab_tree_fetch_node_properties(
					ptnode, pproptags, pset->pparray[pset->count])) {
					ab_tree_put_base(pbase);
					return FALSE;	
				}
				pset->count ++;
			}
		} else {
			if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
				i = 0;
				for (psnode=single_list_get_head(&pbase->gal_list); NULL!=psnode;
					psnode=single_list_get_after(&pbase->gal_list, psnode)) {
					if (i < first_pos) {
						break;
					}
					i ++;
					pset->pparray[pset->count] =
						common_util_alloc(sizeof(TPROPVAL_ARRAY));
					if (NULL == pset->pparray[pset->count]) {
						ab_tree_put_base(pbase);
						return FALSE;
					}
					if (FALSE == ab_tree_fetch_node_properties(
						psnode->pdata, pproptags, pset->pparray[pset->count])) {
						ab_tree_put_base(pbase);
						return FALSE;	
					}
					pset->count ++;
					if (pset->count == row_count) {
						break;
					}
				}
			} else if (0 == pcontainer->id.abtree_id.minid) {
				ab_tree_put_base(pbase);
				return TRUE;
			} else {
				ptnode = ab_tree_minid_to_node(pbase,
					pcontainer->id.abtree_id.minid);
				if (NULL == ptnode || NULL == (ptnode =
					simple_tree_node_get_child(ptnode))) {
					ab_tree_put_base(pbase);
					return TRUE;
				}
				i = 0;
				do {
					if (ab_tree_get_node_type(ptnode) > 0x80) {
						continue;
					}
					if (i < first_pos) {
						continue;
					}
					i ++;
					pset->pparray[pset->count] =
						common_util_alloc(sizeof(TPROPVAL_ARRAY));
					if (NULL == pset->pparray[pset->count]) {
						ab_tree_put_base(pbase);
						return FALSE;
					}
					if (FALSE == ab_tree_fetch_node_properties(
						ptnode, pproptags, pset->pparray[pset->count])) {
						ab_tree_put_base(pbase);
						return FALSE;	
					}
					pset->count ++;
					if (pset->count == row_count) {
						break;
					}
				} while (ptnode=simple_tree_node_get_slibling(ptnode));
			}
		}
		ab_tree_put_base(pbase);
	} else {
		if (NULL == pcontainer->contents.prow_set) {
			if (FALSE == container_object_load_user_table(
				pcontainer, NULL)) {
				return FALSE;	
			}
		}
		for (i=first_pos; i<pcontainer->contents.prow_set->count
			&& i<first_pos+row_count; i++) {
			pset->pparray[pset->count] =
				pcontainer->contents.prow_set->pparray[i];
			pset->count ++;
		}
	}
	if (FALSE == b_forward) {
		for (i=0; i<pset->count/2; i++) {
			ppropvals = pset->pparray[i];
			pset->pparray[i] = pset->pparray[pset->count - 1 - i];
			pset->pparray[pset->count - 1 - i] = ppropvals;
		}
	}
	return TRUE;
}

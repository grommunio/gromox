#include "container_object.h"
#include "zarafa_server.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "rop_util.h"
#include "ab_tree.h"

CONTAINER_OBJECT* container_object_create(int base_id, uint32_t minid)
{
	CONTAINER_OBJECT *pcontainer;
	
	pcontainer = malloc(sizeof(CONTAINER_OBJECT));
	if (NULL == pcontainer) {
		return NULL;
	}
	pcontainer->base_id = base_id;
	pcontainer->minid = minid;
	pcontainer->pminid_array = NULL;
	return pcontainer;
}

void container_object_free(CONTAINER_OBJECT *pcontainer)
{
	if (NULL != pcontainer->pminid_array) {
		if (NULL != pcontainer->pminid_array->pl) {
			free(pcontainer->pminid_array->pl);
		}
		free(pcontainer->pminid_array);
	}
	free(pcontainer);
}

void container_object_clear_restriction(
	CONTAINER_OBJECT *pcontainer)
{
	if (NULL != pcontainer->pminid_array) {
		if (NULL != pcontainer->pminid_array->pl) {
			free(pcontainer->pminid_array->pl);
		}
		free(pcontainer->pminid_array);
		pcontainer->pminid_array = NULL;
	}
}

BOOL container_object_restrict_user_table(
	CONTAINER_OBJECT *pcontainer,
	const RESTRICTION *prestriction)
{
	AB_BASE *pbase;	
	USER_INFO *pinfo;
	TARRAY_SET user_set;
	LONG_ARRAY minid_array;
	
	if (NULL == prestriction ||
		NULL != pcontainer->pminid_array) {
		return TRUE;
	}
	pbase = ab_tree_get_base(pcontainer->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == ab_tree_match_minids(pbase,
		pcontainer->minid, pinfo->cpid,
		prestriction, &minid_array)) {
		ab_tree_put_base(pbase);
		return FALSE;	
	}
	ab_tree_put_base(pbase);
	pcontainer->pminid_array = malloc(sizeof(LONG_ARRAY));
	if (NULL == pcontainer->pminid_array) {
		return FALSE;
	}
	pcontainer->pminid_array->count = minid_array.count;
	if (0 == minid_array.count) {
		pcontainer->pminid_array->pl = NULL;
		return TRUE;
	}
	pcontainer->pminid_array->pl = malloc(
		sizeof(uint32_t)*minid_array.count);
	if (NULL == pcontainer->pminid_array->pl) {
		free(pcontainer->pminid_array);
		pcontainer->pminid_array = NULL;
		return FALSE;
	}
	memcpy(pcontainer->pminid_array->pl, minid_array.pl,
					sizeof(uint32_t)*minid_array.count);
	return TRUE;
}

BOOL container_object_get_properties(CONTAINER_OBJECT *pcontainer,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	AB_BASE *pbase;	
	SIMPLE_TREE_NODE *pnode;
	
	if (0 == pcontainer->minid) {
		return ab_tree_fetch_node_properties(
				NULL, pproptags, ppropvals);
	}
	pbase = ab_tree_get_base(pcontainer->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	pnode = ab_tree_minid_to_node(pbase, pcontainer->minid);
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
	TARRAY_SET *pset)
{
	int i;
	BOOL b_sub;
	void *pvalue;
	uint32_t count;
	uint32_t handle;
	USER_INFO *pinfo;
	uint8_t mapi_type;
	uint64_t folder_id;
	STORE_OBJECT *pstore;
	TPROPVAL_ARRAY **pparray;
	TPROPVAL_ARRAY *ptmp_propvals;
	
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
	pvalue = common_util_get_propvals(ppropvals, PROP_TAG_FOLDERID);
	if (NULL == pvalue) {
		return FALSE;
	}
	folder_id = *(uint64_t*)pvalue;
	ptmp_propvals = pset->pparray[pset->count];
	pset->count ++;
	ptmp_propvals->count = 0;
	ptmp_propvals->ppropval = common_util_alloc(
		pproptags->count*sizeof(TAGGED_PROPVAL));
	if (NULL == ptmp_propvals->ppropval) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		ptmp_propvals->ppropval[ptmp_propvals->count].proptag =
										pproptags->pproptag[i];
		switch (pproptags->pproptag[i]) {
		case PROP_TAG_ABPROVIDERID:
			pvalue = common_util_alloc(sizeof(BINARY));
			if (NULL == pvalue) {
				return FALSE;
			}
			((BINARY*)pvalue)->cb = 16;
			((BINARY*)pvalue)->pb = common_util_get_muidecsab();
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
			break;
		case PROP_TAG_ENTRYID:
		case PROP_TAG_PARENTENTRYID:
			pinfo = zarafa_server_get_info();
			handle = object_tree_get_store_handle(
				pinfo->ptree, TRUE, pinfo->user_id);
			pstore = object_tree_get_object(
				pinfo->ptree, handle, &mapi_type);
			if (NULL == pstore || MAPI_STORE != mapi_type) {
				return FALSE;
			}
			if (PROP_TAG_PARENTENTRYID == pproptags->pproptag[i]) {
				pvalue = common_util_get_propvals(
					ppropvals, PROP_TAG_PARENTFOLDERID);
				if (NULL == pvalue) {
					return FALSE;
				}
				pvalue = common_util_to_folder_entryid(
							pstore, *(uint64_t*)pvalue);
			} else {
				pvalue = common_util_to_folder_entryid(pstore, folder_id);
			}
			if (NULL == pvalue) {
				return FALSE;
			}
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
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
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
			break;
		case PROP_TAG_DEPTH:
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_DEPTH);
			if (NULL == pvalue) {
				return FALSE;
			}
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
			break;
		case PROP_TAG_DISPLAYNAME:
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_DISPLAYNAME);
			if (NULL == pvalue) {
				return FALSE;
			}
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
			break;
		case PROP_TAG_ADDRESSBOOKISMASTER:
			pvalue = common_util_alloc(sizeof(uint8_t));
			if (NULL == pvalue) {
				return FALSE;
			}
			*(uint8_t*)pvalue = 0;
			ptmp_propvals->ppropval[ptmp_propvals->count].pvalue = pvalue;
			ptmp_propvals->count ++;
			break;
		}
	}
	return TRUE;
}

static BOOL container_object_query_contacts(uint64_t folder_id,
	const PROPTAG_ARRAY *pproptags, BOOL b_depth, TARRAY_SET *pset)
{
	int i;
	void *pvalue;
	uint32_t row_num;
	USER_INFO *pinfo;
	uint32_t table_id;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static uint32_t proptag_buff[] = {
					PROP_TAG_DEPTH,
					PROP_TAG_FOLDERID,
					PROP_TAG_SUBFOLDERS,
					PROP_TAG_DISPLAYNAME,
					PROP_TAG_PARENTFOLDERID,
					PROP_TAG_ATTRIBUTEHIDDEN};
	
	tmp_proptags.count = 5;
	tmp_proptags.pproptag = proptag_buff;
	pinfo = zarafa_server_get_info();
	if (FALSE == exmdb_client_get_folder_properties(
		pinfo->maildir, pinfo->cpid, folder_id,
		&tmp_proptags, &tmp_propvals)) {
		return FALSE;
	}
	if (FALSE == container_object_fetch_folder_properties(
		&tmp_propvals, pproptags, pset)) {
		return FALSE;	
	}
	if (TRUE == b_depth) {
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
				&tmp_proptags, 0, row_num, &tmp_set)) {
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
			if (FALSE == container_object_fetch_folder_properties(
				tmp_set.pparray[i], pproptags, pset)) {
				return FALSE;	
			}
		}
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
	TARRAY_SET tmp_set;
	DOMAIN_NODE *pdnode;
	SINGLE_LIST_NODE *psnode;
	SIMPLE_TREE_NODE *ptnode;
	
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
	pbase = ab_tree_get_base(pcontainer->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	if (0xFFFFFFFF == pcontainer->minid) {
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
		if (FALSE == container_object_query_contacts(
			rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
			pproptags, b_depth, &tmp_set)) {
			ab_tree_put_base(pbase);
			return FALSE;	
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
		ptnode = ab_tree_minid_to_node(pbase, pcontainer->minid);
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
	
	if (NULL != pcontainer->pminid_array) {
		*pnum = pcontainer->pminid_array->count;
		return TRUE;
	}
	pbase = ab_tree_get_base(pcontainer->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	*pnum = 0;
	if (0xFFFFFFFF == pcontainer->minid) {
		*pnum = single_list_get_nodes_num(&pbase->gal_list);
	} else {
		pnode = ab_tree_minid_to_node(pbase, pcontainer->minid);
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
	return TRUE;
}

void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static uint32_t proptag_buff[] = {
		PROP_TAG_DISPLAYNAME,
		PROP_TAG_NICKNAME,
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
	pproptags->count = 31;
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
	
	if (NULL != pcontainer->pminid_array &&
		0 == pcontainer->pminid_array->count) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
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
	pbase = ab_tree_get_base(pcontainer->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	if (NULL != pcontainer->pminid_array) {
		for (i=first_pos; i<first_pos+row_count&&
			i<pcontainer->pminid_array->count; i++) {
			ptnode = ab_tree_minid_to_node(pbase,
				pcontainer->pminid_array->pl[i]);
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
		if (0xFFFFFFFF == pcontainer->minid) {
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
		} else {
			ptnode = ab_tree_minid_to_node(pbase, pcontainer->minid);
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
	if (FALSE == b_forward) {
		for (i=0; i<pset->count/2; i++) {
			ppropvals = pset->pparray[i];
			pset->pparray[i] = pset->pparray[pset->count - 1 - i];
			pset->pparray[pset->count - 1 - i] = ppropvals;
		}
	}
	return TRUE;
}

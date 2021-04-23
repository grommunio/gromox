// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <cstdint>
#include <memory>
#include <libHX/string.h>
#include <gromox/mapidefs.h>
#include "container_object.h"
#include "zarafa_server.h"
#include "common_util.h"
#include <gromox/ext_buffer.hpp>
#include <gromox/tarray_set.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/rop_util.hpp>
#include "ab_tree.h"
#include "exmdb_client.h"
#include <gromox/propval.hpp>
#include <cstdio>

std::unique_ptr<CONTAINER_OBJECT> container_object_create(
	uint8_t type, CONTAINER_ID id)
{
	std::unique_ptr<CONTAINER_OBJECT> pcontainer;
	try {
		pcontainer = std::make_unique<CONTAINER_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
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

CONTAINER_OBJECT::~CONTAINER_OBJECT()
{
	container_object_clear(this);
}

static BOOL container_object_match_contact_message(
	const TPROPVAL_ARRAY *ppropvals, const RESTRICTION *pfilter)
{
	void *pvalue;
	
	switch (pfilter->rt) {
	case RES_AND:
		for (size_t i = 0; i < pfilter->andor->count; ++i)
			if (!container_object_match_contact_message(ppropvals, &pfilter->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (size_t i = 0; i < pfilter->andor->count; ++i)
			if (container_object_match_contact_message(ppropvals, &pfilter->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_NOT:
		if (container_object_match_contact_message(ppropvals, &pfilter->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pfilter->cont;
		if (PROP_TYPE(rcon->proptag) != PT_UNICODE)
			return FALSE;
		if (PROP_TYPE(rcon->proptag) != PROP_TYPE(rcon->propval.proptag))
			return FALSE;
		pvalue = common_util_get_propvals(ppropvals, rcon->proptag);
		if (NULL == pvalue) {
			return FALSE;	
		}
		switch (rcon->fuzzy_level & 0xFFFF) {
		case FL_FULLSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasecmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
			} else {
				if (strcmp(static_cast<char *>(rcon->propval.pvalue),
				    static_cast<char *>(pvalue)) == 0)
					return TRUE;
			}
			return FALSE;
		case FL_SUBSTRING:
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			} else {
				if (strstr(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		case FL_PREFIX: {
			auto len = strlen(static_cast<char *>(rcon->propval.pvalue));
			if (rcon->fuzzy_level & (FL_IGNORECASE | FL_LOOSE)) {
				if (strncasecmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue),
				    len) == 0)
					return TRUE;
			} else {
				if (strncmp(static_cast<char *>(pvalue),
				    static_cast<char *>(rcon->propval.pvalue),
				    len) == 0)
					return TRUE;
			}
			return FALSE;
		}
		}
		return FALSE;
	}
	case RES_PROPERTY: {
		auto rprop = pfilter->prop;
		if (rprop->proptag == PROP_TAG_ANR) {
			pvalue = common_util_get_propvals(ppropvals, PR_SMTP_ADDRESS);
			if (NULL != pvalue) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
					return TRUE;
			}
			pvalue = common_util_get_propvals(ppropvals, PR_DISPLAY_NAME);
			if (NULL != pvalue) {
				if (strcasestr(static_cast<char *>(pvalue),
				    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
					return TRUE;
			}
			return FALSE;
		}
		pvalue = common_util_get_propvals(ppropvals, rprop->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		return propval_compare_relop(rprop->relop,
		       PROP_TYPE(rprop->proptag), pvalue, rprop->propval.pvalue);
	}
	case RES_BITMASK: {
		auto rbm = pfilter->bm;
		if (PROP_TYPE(rbm->proptag) != PT_LONG)
			return FALSE;
		pvalue = common_util_get_propvals(ppropvals, rbm->proptag);
		if (NULL == pvalue) {
			return FALSE;
		}
		switch (rbm->bitmask_relop) {
		case BMR_EQZ:
			if ((*static_cast<uint32_t *>(pvalue) & rbm->mask) == 0)
				return TRUE;
			break;
		case BMR_NEZ:
			if (*static_cast<uint32_t *>(pvalue) & rbm->mask)
				return TRUE;
			break;
		}
		return FALSE;
	}
	case RES_EXIST:
		pvalue = common_util_get_propvals(ppropvals, pfilter->exist->proptag);
		if (NULL != pvalue) {
			return TRUE;	
		}
		return FALSE;
	default:
		return FALSE;
	}
	return false;
}

static BOOL container_object_get_pidlids(PROPTAG_ARRAY *pproptags)
{
	int i;
	uint32_t handle;
	uint32_t lids[9];
	uint8_t mapi_type;
	STORE_OBJECT *pstore;
	PROPID_ARRAY propids;
	PROPNAME_ARRAY propnames;
	PROPERTY_NAME propname_buff[9];
	
	auto pinfo = zarafa_server_get_info();
	handle = object_tree_get_store_handle(
		pinfo->ptree, TRUE, pinfo->user_id);
	pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
	         pinfo->ptree, handle, &mapi_type));
	if (NULL == pstore || MAPI_STORE != mapi_type) {
		return FALSE;
	}
	propnames.count = 9;
	propnames.ppropname = propname_buff;
	/* PidLidEmail1DisplayName */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[0].guid);
	lids[0] = 0x8080;
	propname_buff[0].kind = MNID_ID;
	propname_buff[0].plid = &lids[0];
	/* PidLidEmail1AddressType */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[1].guid);
	lids[1] = 0x8082;
	propname_buff[1].kind = MNID_ID;
	propname_buff[1].plid = &lids[1];
	/* PidLidEmail1EmailAddress */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[2].guid);
	lids[2] = 0x8083;
	propname_buff[2].kind = MNID_ID;
	propname_buff[2].plid = &lids[2];
	/* PidLidEmail2DisplayName */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[3].guid);
	lids[3] = 0x8090;
	propname_buff[3].kind = MNID_ID;
	propname_buff[3].plid = &lids[3];
	/* PidLidEmail2AddressType */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[4].guid);
	lids[4] = 0x8092;
	propname_buff[4].kind = MNID_ID;
	propname_buff[4].plid = &lids[4];
	/* PidLidEmail2EmailAddress */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[5].guid);
	lids[5] = 0x8093;
	propname_buff[5].kind = MNID_ID;
	propname_buff[5].plid = &lids[5];
	/* PidLidEmail3DisplayName */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[6].guid);
	lids[6] = 0x80A0;
	propname_buff[6].kind = MNID_ID;
	propname_buff[6].plid = &lids[6];
	/* PidLidEmail3AddressType */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[7].guid);
	lids[7] = 0x80A2;
	propname_buff[7].kind = MNID_ID;
	propname_buff[7].plid = &lids[7];
	/* PidLidEmail3EmailAddress */
	rop_util_get_common_pset(PSETID_ADDRESS, &propname_buff[8].guid);
	lids[8] = 0x80A3;
	propname_buff[8].kind = MNID_ID;
	propname_buff[8].plid = &lids[8];
	if (FALSE == store_object_get_named_propids(
		pstore, FALSE, &propnames, &propids) ||
		9 != propids.count) {
		return FALSE;
	}
	for (i=0; i<9; i++) {
		pproptags->pproptag[i] = PROP_TAG(PT_UNICODE, propids.ppropid[i]);
	}
	pproptags->count = 9;
	return TRUE;
}

static BINARY* container_object_folder_to_addressbook_entryid(
	BOOL b_private, int db_id, uint64_t folder_id)
{
	BINARY *pbin;
	char x500dn[128];
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	uint8_t type = b_private ? LOC_TYPE_PRIVATE_FOLDER : LOC_TYPE_PUBLIC_FOLDER;
	
	memcpy(x500dn, "/exmdb=", 7);
	common_util_exmdb_locinfo_to_string(
		type, db_id, folder_id, x500dn + 7);
	tmp_entryid.flags = 0;
	rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
								tmp_entryid.provider_uid);
	tmp_entryid.version = 1;
	tmp_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
	tmp_entryid.px500dn = x500dn;
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pb, 256, EXT_FLAG_UTF16))
		return NULL;
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
	BINARY *pbin;
	char x500dn[128];
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID tmp_entryid;
	uint8_t type = b_private ? LOC_TYPE_PRIVATE_MESSAGE : LOC_TYPE_PUBLIC_MESSAGE;
	
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
	pbin = cu_alloc<BINARY>();
	if (NULL == pbin) {
		return NULL;
	}
	pbin->pv = common_util_alloc(256);
	if (pbin->pv == nullptr ||
	    !ext_buffer_push_init(&ext_push, pbin->pb, 256, EXT_FLAG_UTF16))
		return NULL;
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
	void *pvalue;
	char *paddress;
	BINARY tmp_bin;
	uint32_t handle;
	uint32_t tmp_int;
	uint32_t row_num;
	uint32_t table_id;
	uint8_t mapi_type;
	char username[UADDR_SIZE];
	TARRAY_SET tmp_set;
	char *pdisplayname;
	char *paddress_type;
	STORE_OBJECT *pstore;
	TAGGED_PROPVAL propval;
	PROPTAG_ARRAY proptags;
	LONG_ARRAY minid_array;
	BINARY *pparent_entryid = nullptr;
	LONG_ARRAY *pminid_array;
	TPROPVAL_ARRAY *ppropvals;
	uint32_t proptag_buff[25];
	static const uint32_t tmp_proptags[] = {
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
			PR_CREATION_TIME
	};
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL == prestriction ||
			NULL != pcontainer->contents.pminid_array) {
			return TRUE;
		}
		auto pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (pbase == nullptr)
			return FALSE;
		auto pinfo = zarafa_server_get_info();
		if (!ab_tree_match_minids(pbase.get(), pcontainer->id.abtree_id.minid,
			pinfo->cpid, prestriction, &minid_array)) {
			return FALSE;	
		}
		pbase.reset();
		pminid_array = me_alloc<LONG_ARRAY>();
		if (NULL == pminid_array) {
			return FALSE;
		}
		pcontainer->contents.pminid_array = pminid_array;
		pminid_array->count = minid_array.count;
		if (0 == minid_array.count) {
			pminid_array->pl = NULL;
			return TRUE;
		}
		pminid_array->pl = me_alloc<uint32_t>(minid_array.count);
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
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::load_content_table(pinfo->maildir,
		pinfo->cpid, pcontainer->id.exmdb_id.folder_id, NULL, 0,
		NULL, NULL, &table_id, &row_num)) {
		return FALSE;
	}
	if (row_num > 0) {
		proptags.pproptag = proptag_buff;
		if (FALSE == container_object_get_pidlids(&proptags)) {
			return FALSE;
		}
		proptags.pproptag[proptags.count] = PR_DISPLAY_NAME;
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
		proptags.pproptag[proptags.count] = PR_CREATION_TIME;
		proptags.count ++;
		proptags.pproptag[proptags.count] =
							PROP_TAG_MID;
		proptags.count ++;
		if (!exmdb_client::query_table(
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
		pstore = static_cast<STORE_OBJECT *>(object_tree_get_object(
		         pinfo->ptree, handle, &mapi_type));
		if (NULL == pstore || MAPI_STORE != mapi_type) {
			return FALSE;
		}
	} else {
		tmp_set.count = 0;
	}
	exmdb_client::unload_table(pinfo->maildir, table_id);
	pcontainer->contents.prow_set = tarray_set_init();
	if (NULL == pcontainer->contents.prow_set) {
		return FALSE;
	}
	for (size_t i = 0; i < tmp_set.count; ++i) {
		for (unsigned int j = 0; j < 3; ++j) {
			pdisplayname = static_cast<char *>(common_util_get_propvals(
			               tmp_set.pparray[i], proptags.pproptag[3*j]));
			if (NULL == pdisplayname) {
				pdisplayname = static_cast<char *>(common_util_get_propvals(
				               tmp_set.pparray[i], PR_DISPLAY_NAME));
			}
			paddress_type = static_cast<char *>(common_util_get_propvals(
				tmp_set.pparray[i], proptags.pproptag[3*j+1]));
			paddress = static_cast<char *>(common_util_get_propvals(
				tmp_set.pparray[i], proptags.pproptag[3*j+2]));
			if (NULL == paddress || NULL == paddress_type) {
				continue;
			}
			if (0 == strcasecmp(paddress_type, "EX")) {
				if (!common_util_essdn_to_username(paddress,
				    username, GX_ARRAY_SIZE(username)))
					continue;
			} else if (0 == strcasecmp(paddress_type, "SMTP")) {
				gx_strlcpy(username, paddress, GX_ARRAY_SIZE(username));
			} else {
				continue;
			}
			ppropvals = tpropval_array_init();
			if (NULL == ppropvals) {
				return FALSE;
			}
			propval.proptag = PR_SMTP_ADDRESS;
			propval.pvalue = username;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ACCOUNT;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ADDRESSTYPE;
			propval.pvalue  = deconst("SMTP");
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PR_EMAIL_ADDRESS;
			propval.pvalue = username;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (NULL != pdisplayname) {
				propval.proptag = PR_DISPLAY_NAME;
				propval.pvalue = pdisplayname;
				if (!tpropval_array_set_propval(ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
				propval.proptag = PROP_TAG_TRANSMITTABLEDISPLAYNAME;
				if (!tpropval_array_set_propval(ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
				propval.proptag = PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE;
				if (!tpropval_array_set_propval(ppropvals, &propval)) {
					tpropval_array_free(ppropvals);
					return FALSE;
				}
			}
			for (size_t k = 0; k < GX_ARRAY_SIZE(tmp_proptags); ++k) {
				propval.proptag = tmp_proptags[k];
				propval.pvalue = common_util_get_propvals(
					tmp_set.pparray[i], propval.proptag);
				if (NULL != propval.pvalue) {
					if (!tpropval_array_set_propval(ppropvals, &propval)) {
						tpropval_array_free(ppropvals);
						return FALSE;
					}
				}
			}
			propval.proptag = PR_PARENT_ENTRYID;
			propval.pvalue = pparent_entryid;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			pvalue = common_util_get_propvals(
				tmp_set.pparray[i], PROP_TAG_MID);
			if (NULL == pvalue) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PR_ENTRYID;
			propval.pvalue = container_object_message_to_addressbook_entryid(
								TRUE, pinfo->user_id, *(uint64_t*)pvalue, j);
			if (NULL == propval.pvalue) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PR_RECORD_KEY;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_TEMPLATEID;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ORIGINALENTRYID;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_ABPROVIDERID;
			propval.pvalue = &tmp_bin;
			tmp_bin.cb = 16;
			tmp_bin.pb = deconst(common_util_get_muidzcsab());
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PR_OBJECT_TYPE;
			propval.pvalue = &tmp_int;
			tmp_int = OBJECT_USER;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_DISPLAYTYPE;
			propval.pvalue = &tmp_int;
			tmp_int = DISPLAY_TYPE_MAILUSER;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			propval.proptag = PROP_TAG_DISPLAYTYPEEX;
			if (!tpropval_array_set_propval(ppropvals, &propval)) {
				tpropval_array_free(ppropvals);
				return FALSE;
			}
			if (NULL != prestriction && FALSE ==
				container_object_match_contact_message(
				ppropvals, prestriction)) {
				tpropval_array_free(ppropvals);
				continue;
			}
			if (!tarray_set_append_internal(pcontainer->contents.prow_set, ppropvals)) {
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
		*ppvalue = cu_alloc<BINARY>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY*)*ppvalue)->cb = 16;
		static_cast<BINARY *>(*ppvalue)->pb = deconst(common_util_get_muidecsab());
		return TRUE;
	case PR_ENTRYID: {
		pvalue = cu_alloc<BINARY>();
		if (NULL == pvalue) {
			return FALSE;
		}
		auto bv = static_cast<BINARY *>(pvalue);
		ab_entryid.flags = 0;
		rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
									ab_entryid.provider_uid);
		ab_entryid.version = 1;
		ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
		ab_entryid.px500dn = special_type == SPECIAL_CONTAINER_GAL ?
		                     deconst("") : deconst("/");
		bv->pv = common_util_alloc(128);
		if (bv->pv == nullptr ||
		    !ext_buffer_push_init(&ext_push, ((BINARY*)pvalue)->pb, 128, 0))
			return FALSE;
		if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
			&ext_push, &ab_entryid)) {
			return FALSE;
		}
		bv->cb = ext_push.offset;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PROP_TAG_CONTAINERFLAGS:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = AB_RECIPIENTS |
			AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPTH:
		pvalue = cu_alloc<uint32_t>();
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PR_DISPLAY_NAME:
		*ppvalue = special_type == SPECIAL_CONTAINER_GAL ?
		           deconst("Global Address List") :
		           deconst("Gromox Contact Folders");
		return TRUE;
	case PROP_TAG_ADDRESSBOOKISMASTER:
		pvalue = cu_alloc<uint8_t>();
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
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
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
	void *pvalue;
	uint64_t folder_id;
	
	pvalue = common_util_get_propvals(ppropvals, PROP_TAG_FOLDERID);
	if (NULL == pvalue) {
		return FALSE;
	}
	folder_id = *(uint64_t*)pvalue;
	pout_propvals->count = 0;
	pout_propvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == pout_propvals->ppropval) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		pout_propvals->ppropval[pout_propvals->count].proptag =
										pproptags->pproptag[i];
		switch (pproptags->pproptag[i]) {
		case PROP_TAG_ABPROVIDERID:
			pvalue = cu_alloc<BINARY>();
			if (NULL == pvalue) {
				return FALSE;
			}
			((BINARY*)pvalue)->cb = 16;
			static_cast<BINARY *>(pvalue)->pb = deconst(common_util_get_muidzcsab());
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PR_ENTRYID:
		case PR_PARENT_ENTRYID: {
			auto pinfo = zarafa_server_get_info();
			if (pproptags->pproptag[i] == PR_PARENT_ENTRYID) {
				if (folder_id == rop_util_make_eid_ex(
					1, PRIVATE_FID_CONTACTS)) {
					if (!container_object_fetch_special_property(SPECIAL_CONTAINER_PROVIDER,
					    PR_ENTRYID, &pvalue))
						return FALSE;	
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
		}
		case PROP_TAG_CONTAINERFLAGS: {
			pvalue = common_util_get_propvals(
				ppropvals, PROP_TAG_SUBFOLDERS);
			BOOL b_sub = pvalue == nullptr || *static_cast<uint32_t *>(pvalue) == 0 ? false : TRUE;
			pvalue = cu_alloc<uint32_t>();
			if (NULL == pvalue) {
				return FALSE;
			}
			*static_cast<uint32_t *>(pvalue) = b_sub ?
				AB_RECIPIENTS | AB_UNMODIFIABLE :
				AB_RECIPIENTS | AB_SUBCONTAINERS | AB_UNMODIFIABLE;
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		}
		case PROP_TAG_DEPTH: {
			auto pc = static_cast<char *>(common_util_get_propvals(
			          ppropvals, PROP_TAG_FOLDERPATHNAME));
			if (pc == nullptr)
				return FALSE;
			count = 0;
			for (; *pc != '\0'; ++pc)
				if (*pc == '\\')
					count ++;
			if (count < 3) {
				return FALSE;
			}
			count -= 2;
			pvalue = cu_alloc<uint32_t>();
			if (NULL == pvalue) {
				return FALSE;
			}
			*(uint32_t*)pvalue = count;
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		}
		case PR_DISPLAY_NAME:
			pvalue = common_util_get_propvals(ppropvals, PR_DISPLAY_NAME);
			if (NULL == pvalue) {
				return FALSE;
			}
			pout_propvals->ppropval[pout_propvals->count].pvalue = pvalue;
			pout_propvals->count ++;
			break;
		case PROP_TAG_ADDRESSBOOKISMASTER:
			pvalue = cu_alloc<uint8_t>();
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
	static const uint32_t proptag_buff[] = {
					PROP_TAG_FOLDERID,
					PROP_TAG_SUBFOLDERS,
					PR_DISPLAY_NAME,
					PROP_TAG_CONTAINERCLASS,
					PROP_TAG_FOLDERPATHNAME,
					PROP_TAG_PARENTFOLDERID,
					PROP_TAG_ATTRIBUTEHIDDEN};
	static const PROPTAG_ARRAY proptags = {.count = 7, .pproptag = (uint32_t *)proptag_buff};
	return &proptags;
}

BOOL container_object_get_properties(CONTAINER_OBJECT *pcontainer,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	SIMPLE_TREE_NODE *pnode;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (0 == pcontainer->id.abtree_id.minid) {
			return container_object_fetch_special_properties(
				SPECIAL_CONTAINER_PROVIDER, pproptags, ppropvals);
		}
		auto pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (pbase == nullptr)
			return FALSE;
		pnode = ab_tree_minid_to_node(pbase.get(),
			pcontainer->id.abtree_id.minid);
		if (NULL == pnode) {
			ppropvals->count = 0;
			return TRUE;
		}
		if (FALSE == ab_tree_fetch_node_properties(
			pnode, pproptags, ppropvals)) {
			return FALSE;
		}
		return TRUE;
	} else {
		auto pinfo = zarafa_server_get_info();
		if (!exmdb_client::get_folder_properties(
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
	static const uint32_t proptag_buff[] = {
		PR_ENTRYID,
		PROP_TAG_CONTAINERFLAGS,
		PROP_TAG_DEPTH,
		PROP_TAG_INSTANCEKEY,
		PROP_TAG_ADDRESSBOOKCONTAINERID,
		PR_DISPLAY_NAME,
		PROP_TAG_ADDRESSBOOKISMASTER,
		PROP_TAG_ADDRESSBOOKPARENTENTRYID,
		PROP_TAG_ABPROVIDERID
	};
	
	pproptags->count = 7;
	pproptags->pproptag = deconst(proptag_buff);
}

static BOOL container_object_get_specialtables_from_node(
	SIMPLE_TREE_NODE *pnode, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, TARRAY_SET *pset)
{
	uint32_t count;
	TPROPVAL_ARRAY **pparray;
	
	count = (pset->count / 100 + 1) * 100;
	if (pset->count + 1 >= count) {
		count += 100;
		pparray = cu_alloc<TPROPVAL_ARRAY *>(count);
		if (NULL == pparray) {
			return FALSE;
		}
		memcpy(pparray, pset->pparray,
			pset->count*sizeof(TPROPVAL_ARRAY*));
		pset->pparray = pparray;
	}
	pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
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
		} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
	}
	return TRUE;
}

static BOOL container_object_query_folder_hierarchy(
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, TARRAY_SET *pset)
{
	void *pvalue;
	uint32_t count;
	uint32_t row_num;
	uint32_t table_id;
	TARRAY_SET tmp_set;
	TPROPVAL_ARRAY **pparray;
	
	auto pinfo = zarafa_server_get_info();
	if (!exmdb_client::load_hierarchy_table(
		pinfo->maildir, folder_id, NULL, TABLE_FLAG_DEPTH,
		NULL, &table_id, &row_num)) {
		return FALSE;
	}
	if (row_num == 0)
		tmp_set.count = 0;
	else if (!exmdb_client::query_table(pinfo->maildir, nullptr,
	    pinfo->cpid, table_id, container_object_get_folder_proptags(),
	    0, row_num, &tmp_set))
		return FALSE;
	exmdb_client::unload_table(pinfo->maildir, table_id);
	for (size_t i = 0; i < tmp_set.count; ++i) {
		pvalue = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_ATTRIBUTEHIDDEN);
		if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
			continue;
		}
		pvalue = common_util_get_propvals(
			tmp_set.pparray[i], PROP_TAG_CONTAINERCLASS);
		if (pvalue == nullptr || strcasecmp(static_cast<char *>(pvalue), "IPF.Contact") != 0)
			continue;
		count = (pset->count / 100 + 1) * 100;
		if (pset->count + 1 >= count) {
			count += 100;
			pparray = cu_alloc<TPROPVAL_ARRAY *>(count);
			if (NULL == pparray) {
				return FALSE;
			}
			memcpy(pparray, pset->pparray,
				pset->count*sizeof(TPROPVAL_ARRAY*));
			pset->pparray = pparray;
		}
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
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
	tmp_set.pparray = cu_alloc<TPROPVAL_ARRAY *>(100);
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
		auto pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (pbase == nullptr)
			return FALSE;
		if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				return FALSE;
			}
			if (FALSE == container_object_fetch_special_properties(
				SPECIAL_CONTAINER_GAL, pproptags,
				tmp_set.pparray[tmp_set.count])) {
				return FALSE;
			}
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				return FALSE;
			}
			if (FALSE == container_object_fetch_special_properties(
				SPECIAL_CONTAINER_PROVIDER, pproptags,
				tmp_set.pparray[tmp_set.count])) {
				return FALSE;
			}
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (NULL == tmp_set.pparray[tmp_set.count]) {
				return FALSE;
			}
			auto pinfo = zarafa_server_get_info();
			if (!exmdb_client::get_folder_properties(pinfo->maildir,
				pinfo->cpid, rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
				container_object_get_folder_proptags(), &tmp_propvals)) {
				return FALSE;
			}
			if (FALSE == container_object_fetch_folder_properties(
				&tmp_propvals, pproptags, tmp_set.pparray[tmp_set.count])) {
				return FALSE;
			}
			tmp_set.count ++;
			if (b_depth && !container_object_query_folder_hierarchy(
			    rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
			    pproptags, TRUE, &tmp_set))
				return FALSE;
			for (psnode=single_list_get_head(&pbase->list); NULL!=psnode;
				psnode=single_list_get_after(&pbase->list, psnode)) {
				pdnode = (DOMAIN_NODE*)psnode->pdata;
				ptnode = simple_tree_get_root(&pdnode->tree);
				if (FALSE == container_object_get_specialtables_from_node(
					ptnode, pproptags, b_depth, &tmp_set)) {
					return FALSE;
				}
			}
		} else {
			ptnode = ab_tree_minid_to_node(pbase.get(),
				pcontainer->id.abtree_id.minid);
			if (NULL == ptnode) {
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
						return FALSE;	
					}
				} while ((ptnode = simple_tree_node_get_sibling(ptnode)) != nullptr);
			}
		}
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(tmp_set.count);
	if (NULL == pset->pparray) {
		return FALSE;
	}
	ssize_t end_pos = start_pos + row_needed;
	if (row_needed > 0) {
		if (end_pos > tmp_set.count) {
			end_pos = tmp_set.count;
		}
		for (ssize_t i = start_pos; i < end_pos; ++i) {
			pset->pparray[pset->count] = tmp_set.pparray[i];
			pset->count ++;
		}
	} else {
		if (end_pos < -1) {
			end_pos = -1;
		}
		for (ssize_t i = start_pos; i > end_pos; --i) {
			pset->pparray[pset->count] = tmp_set.pparray[i];
			pset->count ++;
		}
	}
	return TRUE;
}

BOOL container_object_get_user_table_num(
	CONTAINER_OBJECT *pcontainer, uint32_t *pnum)
{
	SIMPLE_TREE_NODE *pnode;
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL != pcontainer->contents.pminid_array) {
			*pnum = pcontainer->contents.pminid_array->count;
			return TRUE;
		}
		auto pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (pbase == nullptr)
			return FALSE;
		*pnum = 0;
		if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
			*pnum = single_list_get_nodes_num(&pbase->gal_list);
		} else if (0 == pcontainer->id.abtree_id.minid) {
			*pnum = 0;
		} else {
			pnode = ab_tree_minid_to_node(pbase.get(),
				pcontainer->id.abtree_id.minid);
			if (NULL == pnode || NULL == (pnode =
				simple_tree_node_get_child(pnode))) {
				return TRUE;
			}
			do {
				if (ab_tree_get_node_type(pnode) > 0x80) {
					continue;
				}
				(*pnum) ++;
			} while ((pnode = simple_tree_node_get_sibling(pnode)) != nullptr);
		}
	} else {
		if (NULL == pcontainer->contents.prow_set) {
			if (FALSE == container_object_load_user_table(
				pcontainer, NULL)) {
				return FALSE;	
			}
		}
		*pnum = pcontainer->contents.prow_set != nullptr ?
		        pcontainer->contents.prow_set->count : 0;
	}
	return TRUE;
}

void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static const uint32_t proptag_buff[] = {
		PR_DISPLAY_NAME,
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
		PR_SMTP_ADDRESS,
		PR_EMAIL_ADDRESS,
		PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE,
		PROP_TAG_ACCOUNT,
		PROP_TAG_TRANSMITTABLEDISPLAYNAME,
		PROP_TAG_ADDRESSBOOKPROXYADDRESSES,
		PR_OBJECT_TYPE,
		PROP_TAG_DISPLAYTYPE,
		PROP_TAG_DISPLAYTYPEEX,
		PR_ENTRYID,
		PR_RECORD_KEY,
		PROP_TAG_ORIGINALENTRYID,
		PROP_TAG_SEARCHKEY,
		PROP_TAG_INSTANCEKEY,
		PROP_TAG_MAPPINGSIGNATURE,
		PROP_TAG_SENDRICHINFO,
		PROP_TAG_TEMPLATEID,
		PROP_TAG_ADDRESSBOOKOBJECTGUID,
		PR_CREATION_TIME,
		PROP_TAG_THUMBNAILPHOTO
	};
	pproptags->count = 34;
	pproptags->pproptag = deconst(proptag_buff);
}

BOOL container_object_query_user_table(
	CONTAINER_OBJECT *pcontainer, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
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
		if (static_cast<int64_t>(start_pos) + 1 + row_needed < 0) {
			first_pos = 0;
			row_count = start_pos + 1;
		} else {
			first_pos = start_pos + 1 + row_needed;
			row_count = -row_needed;
		}
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_count);
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
		auto pbase = ab_tree_get_base(pcontainer->id.abtree_id.base_id);
		if (pbase == nullptr)
			return FALSE;
		if (NULL != pcontainer->contents.pminid_array) {
			for (size_t i = first_pos; i < first_pos+row_count &&
			     i < pcontainer->contents.pminid_array->count; ++i) {
				ptnode = ab_tree_minid_to_node(pbase.get(),
					pcontainer->contents.pminid_array->pl[i]);
				if (NULL == ptnode) {
					continue;
				}
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (NULL == pset->pparray[pset->count]) {
					return FALSE;
				}
				if (FALSE == ab_tree_fetch_node_properties(
					ptnode, pproptags, pset->pparray[pset->count])) {
					return FALSE;	
				}
				pset->count ++;
			}
		} else {
			if (0xFFFFFFFF == pcontainer->id.abtree_id.minid) {
				size_t i = 0;
				for (psnode = single_list_get_head(&pbase->gal_list);
				     psnode != nullptr;
				     psnode = single_list_get_after(&pbase->gal_list, psnode), ++i) {
					if (i < first_pos) {
						continue;
					}
					pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
					if (NULL == pset->pparray[pset->count]) {
						return FALSE;
					}
					if (!ab_tree_fetch_node_properties(static_cast<SIMPLE_TREE_NODE *>(psnode->pdata),
					    pproptags, pset->pparray[pset->count])) {
						return FALSE;	
					}
					pset->count ++;
					if (pset->count == row_count) {
						break;
					}
				}
			} else if (0 == pcontainer->id.abtree_id.minid) {
				return TRUE;
			} else {
				ptnode = ab_tree_minid_to_node(pbase.get(),
					pcontainer->id.abtree_id.minid);
				if (NULL == ptnode || NULL == (ptnode =
					simple_tree_node_get_child(ptnode))) {
					return TRUE;
				}
				size_t i = 0;
				do {
					if (ab_tree_get_node_type(ptnode) > 0x80) {
						continue;
					}
					if (i < first_pos) {
						continue;
					}
					i ++;
					pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
					if (NULL == pset->pparray[pset->count]) {
						return FALSE;
					}
					if (FALSE == ab_tree_fetch_node_properties(
						ptnode, pproptags, pset->pparray[pset->count])) {
						return FALSE;	
					}
					pset->count ++;
					if (pset->count == row_count) {
						break;
					}
				} while ((ptnode = simple_tree_node_get_sibling(ptnode)) != nullptr);
			}
		}
	} else {
		if (NULL == pcontainer->contents.prow_set) {
			if (FALSE == container_object_load_user_table(
				pcontainer, NULL)) {
				return FALSE;	
			}
		}
		if (pcontainer->contents.prow_set != nullptr) {
			for (size_t i = first_pos;
			     i < pcontainer->contents.prow_set->count &&
			     i < first_pos+row_count; ++i) {
				pset->pparray[pset->count] =
					pcontainer->contents.prow_set->pparray[i];
				pset->count++;
			}
		}
	}
	if (FALSE == b_forward) {
		for (size_t i = 0; i < pset->count / 2; ++i) {
			ppropvals = pset->pparray[i];
			pset->pparray[i] = pset->pparray[pset->count - 1 - i];
			pset->pparray[pset->count - 1 - i] = ppropvals;
		}
	}
	return TRUE;
}

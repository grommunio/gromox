// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2025 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <libHX/string.h>
#include <gromox/ext_buffer.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/propval.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/safeint.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "ab_tree.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "object_tree.hpp"
#include "objects.hpp"
#include "store_object.hpp"
#include "zserver.hpp"

using namespace gromox;

std::unique_ptr<container_object>
container_object::create(uint8_t type, CONTAINER_ID id)
{
	std::unique_ptr<container_object> pcontainer;
	try {
		pcontainer.reset(new container_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pcontainer->type = type;
	pcontainer->id = id;
	return pcontainer;
}

void container_object::clear()
{
	auto pcontainer = this;
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (pcontainer->contents.pminid_array == nullptr)
			return;
		if (pcontainer->contents.pminid_array->pl != nullptr)
			free(pcontainer->contents.pminid_array->pl);
		free(pcontainer->contents.pminid_array);
		pcontainer->contents.pminid_array = NULL;
	} else {
		if (NULL != pcontainer->contents.prow_set) {
			tarray_set_free(pcontainer->contents.prow_set);
			pcontainer->contents.prow_set = NULL;
		}
	}
}

static BOOL container_object_match_contact_message(
	const TPROPVAL_ARRAY *ppropvals, const RESTRICTION *pfilter)
{
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
		return rcon->comparable() &&
		       rcon->eval(ppropvals->getval(rcon->proptag));
	}
	case RES_PROPERTY: {
		auto rprop = pfilter->prop;
		if (!rprop->comparable())
			return false;
		if (rprop->proptag != PR_ANR)
			return rprop->eval(ppropvals->getval(rprop->proptag));
		auto pvalue = ppropvals->get<char>(PR_SMTP_ADDRESS);
		if (pvalue != nullptr && strcasestr(pvalue,
		    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
			return TRUE;
		pvalue = ppropvals->get<char>(PR_DISPLAY_NAME);
		return pvalue != nullptr && strcasestr(pvalue,
		       static_cast<char *>(rprop->propval.pvalue)) != nullptr ? TRUE : false;
	}
	case RES_BITMASK: {
		auto rbm = pfilter->bm;
		return rbm->comparable() &&
		       rbm->eval(ppropvals->getval(rbm->proptag));
	}
	case RES_EXIST:
		return ppropvals->has(pfilter->exist->proptag) ? TRUE : false;
	default:
		return FALSE;
	}
	return false;
}

static BOOL container_object_get_pidlids(PROPTAG_ARRAY *pproptags)
{
	zs_objtype mapi_type;
	PROPID_ARRAY propids;
	PROPERTY_NAME propname_buff[9];
	PROPNAME_ARRAY propnames;
	
	auto pinfo = zs_get_info();
	auto handle = pinfo->ptree->get_store_handle(TRUE, pinfo->user_id);
	auto pstore = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
	if (pstore == nullptr || mapi_type != zs_objtype::store)
		return FALSE;
	propnames.count = 9;
	propnames.ppropname = propname_buff;
	for (size_t i = 0; i < std::size(propname_buff); ++i) {
		propname_buff[i].guid = PSETID_Address;
		propname_buff[i].kind = MNID_ID;
	}
	propname_buff[0].lid = PidLidEmail1DisplayName;
	propname_buff[1].lid = PidLidEmail1AddressType;
	propname_buff[2].lid = PidLidEmail1EmailAddress;
	propname_buff[3].lid = PidLidEmail2DisplayName;
	propname_buff[4].lid = PidLidEmail2AddressType;
	propname_buff[5].lid = PidLidEmail2EmailAddress;
	propname_buff[6].lid = PidLidEmail3DisplayName;
	propname_buff[7].lid = PidLidEmail3AddressType;
	propname_buff[8].lid = PidLidEmail3EmailAddress;
	if (!pstore->get_named_propids(false, &propnames, &propids) ||
	    propids.size() != propnames.size() || propids.size() != 9)
		return FALSE;
	for (size_t i = 0; i < 9; ++i)
		pproptags->pproptag[i] = PROP_TAG(PT_UNICODE, propids[i]);
	pproptags->count = 9;
	return TRUE;
}

static BINARY *zcsab_prepend(const BINARY *lower_eid,
    mapi_object_type type, uint32_t ofs)
{
	if (lower_eid == nullptr)
		return nullptr;
	EXT_PUSH ep;
	auto new_eid = cu_alloc<BINARY>();
	if (new_eid == nullptr)
		return nullptr;
	new_eid->pb = cu_alloc<uint8_t>(255);
	if (new_eid->pb == nullptr || !ep.init(new_eid->pb, 255, EXT_FLAG_UTF16) ||
	    ep.p_uint32(0) != EXT_ERR_SUCCESS ||
	    ep.p_guid(muidZCSAB) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(static_cast<uint32_t>(type)) != EXT_ERR_SUCCESS ||
	    ep.p_uint32(ofs) != EXT_ERR_SUCCESS ||
	    ep.p_bytes(lower_eid->pb, lower_eid->cb) != EXT_ERR_SUCCESS)
		return nullptr;
	new_eid->cb = ep.m_offset;
	return new_eid;
}

BOOL container_object::load_user_table(const RESTRICTION *prestriction) try
{
	auto pcontainer = this;
	BINARY tmp_bin;
	uint32_t tmp_int;
	uint32_t row_num;
	uint32_t table_id;
	zs_objtype mapi_type;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	LONG_ARRAY minid_array;
	BINARY *pparent_entryid = nullptr;
	LONG_ARRAY *pminid_array;
	proptag_t proptag_buff[25];
	static constexpr uint32_t tmp_proptags[] = {
		PR_NICKNAME, PR_SURNAME, PR_GIVEN_NAME, PR_MIDDLE_NAME,
		PR_TITLE, PR_PRIMARY_TELEPHONE_NUMBER,
		PR_MOBILE_TELEPHONE_NUMBER, PR_HOME_ADDRESS_STREET, PR_COMMENT,
		PR_COMPANY_NAME, PR_DEPARTMENT_NAME, PR_OFFICE_LOCATION,
		PR_CREATION_TIME, PR_MESSAGE_CLASS,
	};
	
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL == prestriction ||
			NULL != pcontainer->contents.pminid_array) {
			return TRUE;
		}
		auto pbase = ab_tree::AB.get(pcontainer->id.abtree_id.base_id);
		if (!pbase)
			return FALSE;
		if (!ab_tree_match_minids(pbase.get(), pcontainer->id.abtree_id.minid,
		     prestriction, &minid_array))
			return FALSE;	
		pbase.reset();
		pminid_array = me_alloc<LONG_ARRAY>();
		if (pminid_array == nullptr)
			return FALSE;
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
	if (pcontainer->contents.prow_set != nullptr)
		return TRUE;
	auto pinfo = zs_get_info();
	if (!exmdb_client->load_content_table(pinfo->get_maildir(),
	    pinfo->cpid, pcontainer->id.exmdb_id.folder_id, nullptr, 0,
	    nullptr, nullptr, &table_id, &row_num))
		return FALSE;
	auto handle = pinfo->ptree->get_store_handle(TRUE, pinfo->user_id);
	auto pstore = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
	if (pstore == nullptr || mapi_type != zs_objtype::store)
		return false;
	if (row_num > 0) {
		proptags.pproptag = proptag_buff;
		if (!container_object_get_pidlids(&proptags))
			return FALSE;
		proptags.pproptag[proptags.count++] = PR_DISPLAY_NAME;
		proptags.pproptag[proptags.count++] = PR_NICKNAME;
		proptags.pproptag[proptags.count++] = PR_TITLE;
		proptags.pproptag[proptags.count++] = PR_SURNAME;
		proptags.pproptag[proptags.count++] = PR_GIVEN_NAME;
		proptags.pproptag[proptags.count++] = PR_MIDDLE_NAME;
		proptags.pproptag[proptags.count++] = PR_PRIMARY_TELEPHONE_NUMBER;
		proptags.pproptag[proptags.count++] = PR_MOBILE_TELEPHONE_NUMBER;
		proptags.pproptag[proptags.count++] = PR_HOME_ADDRESS_STREET;
		proptags.pproptag[proptags.count++] = PR_COMMENT;
		proptags.pproptag[proptags.count++] = PR_COMPANY_NAME;
		proptags.pproptag[proptags.count++] = PR_DEPARTMENT_NAME;
		proptags.pproptag[proptags.count++] = PR_OFFICE_LOCATION;
		proptags.pproptag[proptags.count++] = PR_CREATION_TIME;
		proptags.pproptag[proptags.count++] = PR_MESSAGE_CLASS;
		proptags.pproptag[proptags.count++] = PidTagMid;
		if (!exmdb_client->query_table(pinfo->get_maildir(), nullptr,
		    pinfo->cpid, table_id, &proptags, 0, row_num, &tmp_set))
			return FALSE;
		pparent_entryid = zcsab_prepend(cu_fid_to_entryid(*pstore,
		                  pcontainer->id.exmdb_id.folder_id), MAPI_ABCONT, UINT32_MAX);
		if (pparent_entryid == nullptr)
			return FALSE;
	} else {
		tmp_set.count = 0;
	}
	exmdb_client->unload_table(pinfo->get_maildir(), table_id);
	pcontainer->contents.prow_set = tarray_set_init();
	if (pcontainer->contents.prow_set == nullptr)
		return FALSE;
	for (size_t i = 0; i < tmp_set.count; ++i) {
		for (unsigned int j = 0; j < 3; ++j) {
			auto pdisplayname = tmp_set.pparray[i]->get<char>(proptags.pproptag[3*j]);
			if (pdisplayname == nullptr)
				pdisplayname = tmp_set.pparray[i]->get<char>(PR_DISPLAY_NAME);
			auto paddress_type = tmp_set.pparray[i]->get<char>(proptags.pproptag[3*j+1]);
			auto paddress = tmp_set.pparray[i]->get<char>(proptags.pproptag[3*j+2]);
			mapi_object_type mot = MAPI_MAILUSER;
			display_type dt = DT_MAILUSER;
			auto msg_class = tmp_set.pparray[i]->get<char>(PR_MESSAGE_CLASS);
			if (msg_class != nullptr && strcasecmp(msg_class, "IPM.DistList") == 0)
				mot = MAPI_DISTLIST;
			tpropval_array_ptr ppropvals(tpropval_array_init());
			if (ppropvals == nullptr)
				return FALSE;
			std::string username;
			auto addrtype = "SMTP";
			switch (mot) {
			case MAPI_MAILUSER: {
				if (paddress == nullptr || paddress_type == nullptr)
					continue;
				if (0 == strcasecmp(paddress_type, "EX")) {
					if (cvt_essdn_to_username(paddress, g_org_name,
					    cu_id2user, username) != ecSuccess)
						continue;
				} else if (0 == strcasecmp(paddress_type, "SMTP")) {
					try {
						username = paddress;
					} catch (const std::bad_alloc &) {
						continue;
					}
				} else {
					continue;
				}
				break;
			}
			case MAPI_DISTLIST:
				username = pdisplayname;
				addrtype = "MAPIPDL";
				dt = DT_DISTLIST;
				break;
			default:
				break;
			}
			if (ppropvals->set(PR_SMTP_ADDRESS, username.c_str()) != 0 ||
			    ppropvals->set(PR_ACCOUNT, username.c_str()) != 0 ||
			    ppropvals->set(PR_ADDRTYPE, addrtype) != 0 ||
			    ppropvals->set(PR_EMAIL_ADDRESS, username.c_str()) != 0)
				return FALSE;
			if (NULL != pdisplayname) {
				if (ppropvals->set(PR_DISPLAY_NAME, pdisplayname) != 0 ||
				    ppropvals->set(PR_TRANSMITABLE_DISPLAY_NAME, pdisplayname) != 0 ||
				    ppropvals->set(PR_EMS_AB_DISPLAY_NAME_PRINTABLE, pdisplayname) != 0)
					return FALSE;
			}
			for (size_t k = 0; k < std::size(tmp_proptags); ++k) {
				uint32_t tag = tmp_proptags[k];
				auto newval = tmp_set.pparray[i]->getval(tag);
				if (newval == nullptr)
					continue;
				if (ppropvals->set(tag, newval) != 0)
					return FALSE;
			}
			if (ppropvals->set(PR_PARENT_ENTRYID, pparent_entryid) != 0)
				return FALSE;
			auto msgid = tmp_set.pparray[i]->get<uint64_t>(PidTagMid);
			if (msgid == nullptr)
				return FALSE;
			auto pvalue = zcsab_prepend(cu_mid_to_entryid(*pstore,
			              pcontainer->id.exmdb_id.folder_id, *msgid), mot, 3*i+j);
			if (pvalue == nullptr ||
			    ppropvals->set(PR_ENTRYID, pvalue) != 0 ||
			    ppropvals->set(PR_RECORD_KEY, pvalue) != 0 ||
			    ppropvals->set(PR_TEMPLATEID, pvalue) != 0 ||
			    ppropvals->set(PR_ORIGINAL_ENTRYID, pvalue) != 0)
				return FALSE;
			tmp_bin.cb = sizeof(muidZCSAB);
			tmp_bin.pv = deconst(&muidZCSAB);
			if (ppropvals->set(PR_AB_PROVIDER_ID, &tmp_bin) != 0)
				return FALSE;
			tmp_int = static_cast<uint32_t>(mot);
			if (ppropvals->set(PR_OBJECT_TYPE, &tmp_int) != 0)
				return FALSE;
			tmp_int = static_cast<uint32_t>(dt);
			if (ppropvals->set(PR_DISPLAY_TYPE, &tmp_int) != 0 ||
			    ppropvals->set(PR_DISPLAY_TYPE_EX, &tmp_int) != 0)
				return FALSE;
			if (prestriction != nullptr &&
			    !container_object_match_contact_message(ppropvals.get(), prestriction))
				continue;
			if (pcontainer->contents.prow_set->append_move(std::move(ppropvals)) != 0)
				return FALSE;
			if (mot == MAPI_DISTLIST)
				break;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

BOOL container_object_fetch_special_property(uint8_t special_type,
    proptag_t proptag, void **ppvalue)
{
	void *pvalue;
	EXT_PUSH ext_push;
	EMSAB_ENTRYID ab_entryid;
	
	switch (proptag) {
	case PR_AB_PROVIDER_ID: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = sizeof(muidECSAB);
		bv->pv = deconst(&muidECSAB);
		return TRUE;
	}
	case PR_ENTRYID: {
		pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		ab_entryid.flags = 0;
		ab_entryid.type = DT_CONTAINER;
		ab_entryid.px500dn = special_type == SPECIAL_CONTAINER_GAL ?
		                     deconst("/") : deconst("/exmdb");
		bv->pv = common_util_alloc(128);
		if (bv->pv == nullptr ||
		    !ext_push.init(static_cast<BINARY *>(pvalue)->pb, 128, 0) ||
		    ext_push.p_abk_eid(ab_entryid) != EXT_ERR_SUCCESS)
			return FALSE;
		bv->cb = ext_push.m_offset;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_CONTAINER_FLAGS:
		pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(pvalue) = ab_tree::CF_ALL;
		*ppvalue = pvalue;
		return TRUE;
	case PR_DEPTH:
		pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(pvalue) = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PR_DISPLAY_NAME:
		*ppvalue = special_type == SPECIAL_CONTAINER_GAL ?
		           deconst("Global Address List") :
		           deconst("Gromox Contact Folders");
		return TRUE;
	case PR_EMS_AB_IS_MASTER:
		pvalue = cu_alloc<uint8_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(pvalue) = 0;
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
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!container_object_fetch_special_property(special_type, tag, &pvalue))
			return FALSE;	
		if (pvalue == nullptr)
			continue;
		ppropvals->emplace_back(tag, pvalue);
	}
	return TRUE;
}

static BOOL container_object_fetch_folder_properties(
	const TPROPVAL_ARRAY *ppropvals, const PROPTAG_ARRAY *pproptags,
	TPROPVAL_ARRAY *pout_propvals)
{
	auto pvfid = ppropvals->get<uint64_t>(PidTagFolderId);
	if (pvfid == nullptr)
		return FALSE;
	auto folder_id = *pvfid;
	pout_propvals->count = 0;
	pout_propvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (pout_propvals->ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		switch (tag) {
		case PR_AB_PROVIDER_ID: {
			auto bv = cu_alloc<BINARY>();
			if (bv == nullptr)
				return FALSE;
			pout_propvals->emplace_back(tag, bv);
			bv->cb = sizeof(muidZCSAB);
			bv->pv = deconst(&muidZCSAB);
			break;
		}
		case PR_ENTRYID:
		case PR_PARENT_ENTRYID: {
			zs_objtype mapi_type = zs_objtype::invalid;
			auto pinfo = zs_get_info();
			auto handle = pinfo->ptree->get_store_handle(TRUE, pinfo->user_id);
			auto store = pinfo->ptree->get_object<store_object>(handle, &mapi_type);
			if (store == nullptr || mapi_type != zs_objtype::store)
				return false;
			void *pvalue = nullptr;
			if (tag != PR_PARENT_ENTRYID) {
				pvalue = zcsab_prepend(cu_fid_to_entryid(*store, folder_id),
				         MAPI_ABCONT, UINT32_MAX);
			} else if (folder_id == rop_util_make_eid_ex(
			    1, PRIVATE_FID_CONTACTS)) {
				if (!container_object_fetch_special_property(SPECIAL_CONTAINER_PROVIDER,
				    PR_ENTRYID, &pvalue))
					return FALSE;
			} else {
				auto fid = ppropvals->get<uint64_t>(PidTagParentFolderId);
				if (fid == nullptr)
					return FALSE;
				pvalue = zcsab_prepend(cu_fid_to_entryid(*store, *fid),
				         MAPI_ABCONT, UINT32_MAX);
			}
			if (pvalue == nullptr)
				return FALSE;
			pout_propvals->emplace_back(tag, pvalue);
			break;
		}
		case PR_CONTAINER_FLAGS: {
			auto count = ppropvals->get<uint32_t>(PR_SUBFOLDERS);
			auto b_sub = count != nullptr && *count > 0;
			auto pvalue = cu_alloc<uint32_t>();
			if (pvalue == nullptr)
				return FALSE;
			*pvalue = b_sub ?
				ab_tree::CF_RECIPIENTS | ab_tree::CF_UNMODIFIABLE :
				ab_tree::CF_RECIPIENTS | ab_tree::CF_SUBCONTAINERS | ab_tree::CF_UNMODIFIABLE;
			pout_propvals->emplace_back(tag, pvalue);
			break;
		}
		case PR_DEPTH: {
			auto pc = ppropvals->get<const char>(PR_FOLDER_PATHNAME);
			if (pc == nullptr)
				return FALSE;
			unsigned int count = 0;
			for (; *pc != '\0'; ++pc)
				if (*pc == '\\')
					count ++;
			if (count < 3)
				return FALSE;
			count -= 2;
			auto pvalue = cu_alloc<uint32_t>();
			if (pvalue == nullptr)
				return FALSE;
			*pvalue = count;
			pout_propvals->emplace_back(tag, pvalue);
			break;
		}
		case PR_DISPLAY_NAME: {
			auto pvalue = ppropvals->get<char>(PR_DISPLAY_NAME);
			if (pvalue == nullptr)
				return FALSE;
			pout_propvals->emplace_back(tag, pvalue);
			break;
		}
		case PR_EMS_AB_IS_MASTER: {
			auto pvalue = cu_alloc<uint8_t>();
			if (pvalue == nullptr)
				return FALSE;
			*pvalue = 0;
			pout_propvals->emplace_back(tag, pvalue);
			break;
		}
		}
	}
	return TRUE;
}

static const PROPTAG_ARRAY* container_object_get_folder_proptags()
{
	static constexpr uint32_t p[] = {
		PidTagFolderId, PR_SUBFOLDERS, PR_DISPLAY_NAME,
		PR_CONTAINER_CLASS, PR_FOLDER_PATHNAME,
		PidTagParentFolderId, PR_ATTR_HIDDEN,
	};
	static constexpr PROPTAG_ARRAY proptags = {std::size(p), deconst(p)};
	return &proptags;
}

BOOL container_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto pcontainer = this;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (pcontainer->type != CONTAINER_TYPE_ABTREE) {
		auto pinfo = zs_get_info();
		if (!exmdb_client->get_folder_properties(pinfo->get_maildir(),
		    pinfo->cpid, pcontainer->id.exmdb_id.folder_id,
		    container_object_get_folder_proptags(), &tmp_propvals))
			return FALSE;
		return container_object_fetch_folder_properties(
					&tmp_propvals, pproptags, ppropvals);
	}
	if (pcontainer->id.abtree_id.minid == SPECIAL_CONTAINER_EMPTY)
		return container_object_fetch_special_properties(
			SPECIAL_CONTAINER_PROVIDER, pproptags, ppropvals);
	auto pbase = ab_tree::AB.get(pcontainer->id.abtree_id.base_id);
	if (!pbase)
		return FALSE;
	ab_tree::ab_node node(pbase, pcontainer->id.abtree_id.minid);
	if (!node.exists()) {
		ppropvals->count = 0;
		return TRUE;
	}
	return ab_tree_fetch_node_properties(node, pproptags, ppropvals);
}

BOOL container_object::get_container_table_num(BOOL b_depth, uint32_t *pnum)
{
	auto pcontainer = this;
	TARRAY_SET tmp_set;
	PROPTAG_ARRAY proptags;
	
	proptags.count = 0;
	proptags.pproptag = NULL;
	if (!pcontainer->query_container_table(&proptags, b_depth, 0,
	    INT32_MAX, &tmp_set))
		return FALSE;	
	*pnum = tmp_set.count;
	return TRUE;
}

void container_object_get_container_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static constexpr uint32_t p[] = {
		PR_ENTRYID, PR_CONTAINER_FLAGS, PR_DEPTH, PR_INSTANCE_KEY,
		PR_EMS_AB_CONTAINERID, PR_DISPLAY_NAME, PR_EMS_AB_IS_MASTER,
		PR_EMS_AB_PARENT_ENTRYID, PR_AB_PROVIDER_ID,
	};
	pproptags->count = std::size(p);
	pproptags->pproptag = deconst(p);
}

static BOOL
container_object_get_specialtables_from_node(const ab_tree::ab_node& node,
    const PROPTAG_ARRAY *pproptags, BOOL b_depth, TARRAY_SET *pset)
{
	TPROPVAL_ARRAY **pparray;
	auto count = strange_roundup(pset->count, SR_GROW_TPROPVAL_ARRAY);
	if (pset->count + 1 >= count) {
		count += SR_GROW_TPROPVAL_ARRAY;
		pparray = cu_alloc<TPROPVAL_ARRAY *>(count);
		if (pparray == nullptr)
			return FALSE;
		memcpy(pparray, pset->pparray,
			pset->count*sizeof(TPROPVAL_ARRAY*));
		pset->pparray = pparray;
	}
	pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
	if (pset->pparray[pset->count] == nullptr)
		return FALSE;
	if (!ab_tree_fetch_node_properties(node, pproptags,
	    pset->pparray[pset->count]))
		return FALSE;	
	pset->count ++;
	// NOTE: removed recursion as containers currently cannot contain containers
	return TRUE;
}

static BOOL container_object_query_folder_hierarchy(
	uint64_t folder_id, const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, TARRAY_SET *pset)
{
	uint32_t row_num;
	uint32_t table_id;
	TARRAY_SET tmp_set;
	TPROPVAL_ARRAY **pparray;
	
	auto pinfo = zs_get_info();
	if (!exmdb_client->load_hierarchy_table(pinfo->get_maildir(),
	    folder_id, nullptr, TABLE_FLAG_DEPTH, nullptr, &table_id, &row_num))
		return FALSE;
	if (row_num == 0)
		tmp_set.count = 0;
	else if (!exmdb_client->query_table(pinfo->get_maildir(), nullptr,
	    pinfo->cpid, table_id, container_object_get_folder_proptags(),
	    0, row_num, &tmp_set))
		return FALSE;
	exmdb_client->unload_table(pinfo->get_maildir(), table_id);
	for (size_t i = 0; i < tmp_set.count; ++i) {
		auto pbool = tmp_set.pparray[i]->get<const uint8_t>(PR_ATTR_HIDDEN);
		if (pbool != nullptr && *pbool != 0)
			continue;
		auto cnclass = tmp_set.pparray[i]->get<const char>(PR_CONTAINER_CLASS);
		if (class_match_prefix(cnclass, "IPF.Contact") != 0)
			continue;
		auto count = strange_roundup(pset->count, SR_GROW_TPROPVAL_ARRAY);
		if (pset->count + 1 >= count) {
			count += SR_GROW_TPROPVAL_ARRAY;
			pparray = cu_alloc<TPROPVAL_ARRAY *>(count);
			if (pparray == nullptr)
				return FALSE;
			memcpy(pparray, pset->pparray,
				pset->count*sizeof(TPROPVAL_ARRAY*));
			pset->pparray = pparray;
		}
		pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (pset->pparray[pset->count] == nullptr)
			return FALSE;
		if (!container_object_fetch_folder_properties(
		    tmp_set.pparray[i], pproptags, pset->pparray[pset->count]))
			return FALSE;	
		pset->count ++;
	}
	return TRUE;
}

BOOL container_object::query_container_table(const PROPTAG_ARRAY *pproptags,
	BOOL b_depth, uint32_t start_pos, int32_t row_needed,
	TARRAY_SET *pset)
{
	auto pcontainer = this;
	TARRAY_SET tmp_set;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (0 == row_needed) {
		pset->count = 0;
		pset->pparray = NULL;
		return TRUE;
	}
	tmp_set.count = 0;
	tmp_set.pparray = cu_alloc<TPROPVAL_ARRAY *>(100);
	if (tmp_set.pparray == nullptr)
		return FALSE;
	if (CONTAINER_TYPE_FOLDER == pcontainer->type) {
		if (!container_object_query_folder_hierarchy(pcontainer->id.exmdb_id.folder_id,
		    pproptags, b_depth, &tmp_set))
			return FALSE;	
	} else {
		auto pbase = ab_tree::AB.get(pcontainer->id.abtree_id.base_id);
		if (!pbase)
			return FALSE;
		if (pcontainer->id.abtree_id.minid == SPECIAL_CONTAINER_ROOT) {
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (tmp_set.pparray[tmp_set.count] == nullptr)
				return FALSE;
			if (!container_object_fetch_special_properties(SPECIAL_CONTAINER_GAL,
			    pproptags, tmp_set.pparray[tmp_set.count]))
				return FALSE;
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (tmp_set.pparray[tmp_set.count] == nullptr)
				return FALSE;
			if (!container_object_fetch_special_properties(SPECIAL_CONTAINER_PROVIDER,
			    pproptags, tmp_set.pparray[tmp_set.count]))
				return FALSE;
			tmp_set.count ++;
			tmp_set.pparray[tmp_set.count] = cu_alloc<TPROPVAL_ARRAY>();
			if (tmp_set.pparray[tmp_set.count] == nullptr)
				return FALSE;
			auto pinfo = zs_get_info();
			if (!exmdb_client->get_folder_properties(pinfo->get_maildir(),
				pinfo->cpid, rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
				container_object_get_folder_proptags(), &tmp_propvals)) {
				return FALSE;
			}
			if (!container_object_fetch_folder_properties(&tmp_propvals,
			    pproptags, tmp_set.pparray[tmp_set.count]))
				return FALSE;
			tmp_set.count ++;
			if (b_depth && !container_object_query_folder_hierarchy(
			    rop_util_make_eid_ex(1, PRIVATE_FID_CONTACTS),
			    pproptags, TRUE, &tmp_set))
				return FALSE;
			for (auto it = pbase->dbegin(); it != pbase->dend(); ++it)
				if (!container_object_get_specialtables_from_node(it,
				    pproptags, b_depth, &tmp_set))
					return FALSE;
		} else if (pcontainer->id.abtree_id.minid == SPECIAL_CONTAINER_GAL) {
			/* no subordinates */
		} else {
			if (!pbase->exists(pcontainer->id.abtree_id.minid)) {
				pset->count = 0;
				pset->pparray = NULL;
				return TRUE;
			}
			// NOTE: removed recursion as containers currently cannot contain containers
		}
	}
	pset->count = 0;
	pset->pparray = cu_alloc<TPROPVAL_ARRAY *>(tmp_set.count);
	if (pset->pparray == nullptr)
		return FALSE;
	uint32_t end_pos = safe_add_s(start_pos, row_needed, nullptr);
	if (row_needed >= 0) {
		if (end_pos > tmp_set.count)
			end_pos = tmp_set.count;
		for (size_t i = start_pos; i < end_pos; ++i)
			pset->pparray[pset->count++] = tmp_set.pparray[i];
	} else {
		mlog(LV_INFO, "I-1663: report me (c=%u s=%u n=%d)",
		        static_cast<unsigned int>(tmp_set.count),
		        static_cast<unsigned int>(start_pos),
		        static_cast<int>(row_needed));
	}
	return TRUE;
}

BOOL container_object::get_user_table_num(uint32_t *pnum)
{
	auto pcontainer = this;
	
	if (type != CONTAINER_TYPE_ABTREE) {
		if (contents.prow_set == nullptr && !load_user_table(nullptr))
			return false;
		*pnum = contents.prow_set != nullptr ?
		        contents.prow_set->count : 0;
		return TRUE;
	}
	if (NULL != pcontainer->contents.pminid_array) {
		*pnum = pcontainer->contents.pminid_array->count;
		return TRUE;
	}
	auto pbase = ab_tree::AB.get(pcontainer->id.abtree_id.base_id);
	if (!pbase)
		return FALSE;
	*pnum = 0;
	if (pcontainer->id.abtree_id.minid == ab_tree::minid::SC_GAL) {
		auto gs = pbase->users();
		auto hi = pbase->hidden();
		*pnum = uint32_t(gs-hi);
		return TRUE;
	} else if (0 == pcontainer->id.abtree_id.minid) {
		*pnum = 0;
		return TRUE;
	}
	ab_tree::ab_node node(pbase, pcontainer->id.abtree_id.minid);
	if (!node.exists())
		return TRUE;
	*pnum = uint32_t(node.children());
	return TRUE;
}

void container_object_get_user_table_all_proptags(
	PROPTAG_ARRAY *pproptags)
{
	static constexpr uint32_t p[] = {
		PR_DISPLAY_NAME, PR_NICKNAME, PR_SURNAME, PR_GIVEN_NAME,
		PR_MIDDLE_NAME, PR_TITLE, PR_PRIMARY_TELEPHONE_NUMBER,
		PR_MOBILE_TELEPHONE_NUMBER, PR_HOME_ADDRESS_STREET, PR_COMMENT,
		PR_COMPANY_NAME, PR_DEPARTMENT_NAME, PR_OFFICE_LOCATION,
		PR_ADDRTYPE, PR_SMTP_ADDRESS, PR_EMAIL_ADDRESS,
		PR_EMS_AB_DISPLAY_NAME_PRINTABLE, PR_ACCOUNT,
		PR_TRANSMITABLE_DISPLAY_NAME, PR_EMS_AB_PROXY_ADDRESSES,
		PR_OBJECT_TYPE, PR_DISPLAY_TYPE, PR_DISPLAY_TYPE_EX,
		PR_ENTRYID, PR_RECORD_KEY, PR_ORIGINAL_ENTRYID, PR_SEARCH_KEY,
		PR_INSTANCE_KEY, PR_MAPPING_SIGNATURE, PR_SEND_RICH_INFO,
		PR_TEMPLATEID, PR_EMS_AB_OBJECT_GUID, PR_CREATION_TIME,
		PR_EMS_AB_THUMBNAIL_PHOTO,
	};
	pproptags->count = std::size(p);
	pproptags->pproptag = deconst(p);
}

BOOL container_object::query_user_table(const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	auto pcontainer = this;
	BOOL b_forward;
	uint32_t first_pos;
	uint32_t row_count;
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
	if (pset->pparray == nullptr)
		return FALSE;
	if (CONTAINER_TYPE_ABTREE == pcontainer->type) {
		if (NULL != pcontainer->contents.pminid_array &&
			0 == pcontainer->contents.pminid_array->count) {
			pset->count = 0;
			pset->pparray = NULL;
			return TRUE;
		}
		auto pbase = ab_tree::AB.get(pcontainer->id.abtree_id.base_id);
		if (!pbase)
			return FALSE;
		if (NULL != pcontainer->contents.pminid_array) {
			for (size_t i = first_pos; i < first_pos+row_count &&
			     i < pcontainer->contents.pminid_array->count; ++i) {
				ab_tree::ab_node node(pbase, pcontainer->contents.pminid_array->pl[i]);
				if (!node.exists() || node.hidden() & AB_HIDE_FROM_AL)
					continue;
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (pset->pparray[pset->count] == nullptr)
					return FALSE;
				if (!ab_tree_fetch_node_properties(node,
				    pproptags, pset->pparray[pset->count]))
					return FALSE;	
				pset->count ++;
			}
		} else if (pcontainer->id.abtree_id.minid == SPECIAL_CONTAINER_GAL) {
			for (auto it = pbase->ubegin() + first_pos; it != pbase->uend(); ++it) {
				ab_tree::ab_node node(it);
				if (node.hidden() & AB_HIDE_FROM_GAL)
					continue;
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (pset->pparray[pset->count] == nullptr)
					return FALSE;
				if (!ab_tree_fetch_node_properties(node,
				    pproptags, pset->pparray[pset->count]))
					return FALSE;
				pset->count++;
				if (pset->count == row_count)
					break;
			}
		} else if (pcontainer->id.abtree_id.minid == SPECIAL_CONTAINER_EMPTY) {
			return TRUE;
		} else {
			ab_tree::ab_node node(pbase, pcontainer->id.abtree_id.minid);
			if (!node.exists())
				return TRUE;
			for (auto it = node.begin() + first_pos; it != node.end(); ++it) {
				ab_tree::ab_node child(pbase, *it);
				if(child.type() >= ab_tree::abnode_type::containers ||
				   child.hidden() & AB_HIDE_FROM_AL)
					continue;
				pset->pparray[pset->count] = cu_alloc<TPROPVAL_ARRAY>();
				if (pset->pparray[pset->count] == nullptr)
					return FALSE;
				if (!ab_tree_fetch_node_properties(child,
				    pproptags, pset->pparray[pset->count]))
					return FALSE;
				if (++pset->count == row_count)
					break;
			}
		}
	} else {
		if (pcontainer->contents.prow_set == nullptr &&
		    !pcontainer->load_user_table(nullptr))
			return FALSE;
		if (pcontainer->contents.prow_set != nullptr)
			for (size_t i = first_pos;
			     i < pcontainer->contents.prow_set->count &&
			     i < first_pos+row_count; ++i)
				pset->pparray[pset->count++] =
					pcontainer->contents.prow_set->pparray[i];
	}
	if (!b_forward) {
		for (size_t i = 0; i < pset->count / 2; ++i) {
			ppropvals = pset->pparray[i];
			pset->pparray[i] = pset->pparray[pset->count - 1 - i];
			pset->pparray[pset->count - 1 - i] = ppropvals;
		}
	}
	return TRUE;
}

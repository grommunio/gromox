// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021-2024 grommunio GmbH
// This file is part of Gromox.
#include <libHX/endian.h>
#include <libHX/string.h>
#include <gromox/util.hpp>
#include "ab_tree.hpp"
#include "common_util.hpp"
#include "zserver.hpp"

using namespace gromox;

static ec_error_t ab_tree_fetchprop(const ab_tree::ab_node& node,
    unsigned int proptag, void **prop)
{
	const auto obj = node.fetch_user();
	if (!obj)
		return ecNotFound;
	auto it = obj->propvals.find(proptag);
	if (it == obj->propvals.cend())
		return ecNotFound;

	switch (PROP_TYPE(proptag)) {
	case PT_BOOLEAN:
		*prop = cu_alloc<int8_t>();
		*static_cast<int8_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0) != 0;
		return ecSuccess;
	case PT_SHORT:
		*prop = cu_alloc<int16_t>();
		*static_cast<int16_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_LONG:
		*prop = cu_alloc<int32_t>();
		*static_cast<int32_t *>(*prop) = strtol(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_I8:
	case PT_SYSTIME:
		*prop = cu_alloc<int64_t>();
		*static_cast<int64_t *>(*prop) = strtoll(it->second.c_str(), nullptr, 0);
		return ecSuccess;
	case PT_STRING8:
	case PT_UNICODE:
		*prop = common_util_alloc(strlen(it->second.c_str()) + 1);
		if (*prop == nullptr)
			return ecServerOOM;
		strcpy(static_cast<char *>(*prop), it->second.c_str());
		return ecSuccess;
	case PT_BINARY: {
		*prop = cu_alloc<BINARY>();
		if (*prop == nullptr)
			return ecServerOOM;
		auto bv = static_cast<BINARY *>(*prop);
		bv->cb = it->second.size();
		bv->pv = common_util_alloc(it->second.size());
		if (bv->pv == nullptr)
			return ecServerOOM;
		memcpy(bv->pv, it->second.data(), bv->cb);
		return ecSuccess;
	}
	case PT_MV_UNICODE: {
		*prop = cu_alloc<STRING_ARRAY>();
		if (*prop == nullptr)
			return ecServerOOM;
		auto sa = static_cast<STRING_ARRAY *>(*prop);
		sa->count = 1;
		sa->ppstr = cu_alloc<char *>();
		if (sa->ppstr == nullptr)
			return ecServerOOM;
		sa->ppstr[0] = cu_alloc<char>(it->second.size() + 1);
		if (sa->ppstr[0] == nullptr)
			return ecServerOOM;
		strcpy(sa->ppstr[0], it->second.c_str());
		return ecSuccess;
	}
	}
	return ecNotFound;
}

/* Returns: TRUE (success or notfound), FALSE (fatal error/enomem/etc.) */
static BOOL ab_tree_fetch_node_property(const ab_tree::ab_node &pnode,
    proptag_t proptag, void **ppvalue)
{
	EXT_PUSH ext_push;
	
	*ppvalue = nullptr;
	auto node_type = pnode.type();
	/* Properties that need to be force-generated */
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
	case PR_CONTAINER_FLAGS: {
		if (node_type < ab_tree::abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(pvalue) = pnode.children_count() == 0 ?
			ab_tree::CF_RECIPIENTS | ab_tree::CF_UNMODIFIABLE : ab_tree::CF_ALL;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_DEPTH: {
		if (node_type < ab_tree::abnode_type::containers)
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = 1;
		*ppvalue = v;
		return TRUE;
	}
	case PR_EMS_AB_IS_MASTER: {
		if (node_type < ab_tree::abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint8_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(pvalue) = 0;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_HOME_MDB: {
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		std::string mdbdn;
		auto err = pnode.mdbdn(mdbdn);
		if (err != ecSuccess)
			return false;
		auto pvalue = common_util_dup(mdbdn);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_OBJECT_GUID: {
		auto pvalue = common_util_guid_to_binary(pnode.guid());
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_CONTAINERID: {
		auto pvalue = cu_alloc<uint32_t>();
		if (pvalue == nullptr)
			return FALSE;
		if (node_type >= ab_tree::abnode_type::containers)
			*static_cast<uint32_t *>(pvalue) = pnode.mid;
		else
			*static_cast<uint32_t *>(pvalue) = 0;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_ADDRTYPE:
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		*ppvalue = deconst("EX");
		return TRUE;
	case PR_EMAIL_ADDRESS: {
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		std::string dn;
		if (!pnode.dn(dn))
			return FALSE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		auto t = node_type >= ab_tree::abnode_type::containers ? MAPI_ABCONT :
		         node_type == ab_tree::abnode_type::mlist ? MAPI_DISTLIST : MAPI_MAILUSER;
		*v = static_cast<uint32_t>(t);
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE: {
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = pnode.dtyp();
		*ppvalue = v;
		return TRUE;
	}
	case PR_DISPLAY_TYPE_EX: {
		auto dtypx = pnode.dtypx();
		if (!dtypx.has_value())
			return TRUE;
		auto v = cu_alloc<uint32_t>();
		if (v == nullptr)
			return FALSE;
		*v = *dtypx;
		*ppvalue = v;
		return TRUE;
	}
	case PR_MAPPING_SIGNATURE: {
		auto bv = cu_alloc<BINARY>();
		if (bv == nullptr)
			return FALSE;
		*ppvalue = bv;
		bv->cb = sizeof(muidEMSAB);
		bv->pv = deconst(&muidEMSAB);
		return TRUE;
	}
	case PR_PARENT_ENTRYID:
		return TRUE;
	case PR_ENTRYID:
	case PR_RECORD_KEY:
	case PR_TEMPLATEID:
	case PR_ORIGINAL_ENTRYID: {
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		EMSAB_ENTRYID ab_entryid;
		ab_entryid.flags = 0;
		ab_entryid.type = pnode.etyp();
		if (!pnode.dn(ab_entryid.x500dn))
			return FALSE;
		bv->pv = common_util_alloc(1280);
		if (bv->pv == nullptr || !ext_push.init(bv->pv, 1280, 0) ||
		    ext_push.p_abk_eid(ab_entryid) != pack_result::ok)
			return FALSE;
		bv->cb = ext_push.m_offset;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_SEARCH_KEY: {
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		std::string dn;
		if (!pnode.dn(dn))
			return FALSE;
		bv->cb = dn.size() + 4;
		bv->pv = common_util_alloc(bv->cb);
		if (bv->pv == nullptr)
			return FALSE;
		sprintf(bv->pc, "EX:%s", dn.c_str());
		HX_strupper(bv->pc);
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_INSTANCE_KEY: {
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(pvalue);
		bv->cb = 4;
		bv->pv = common_util_alloc(4);
		if (bv->pv == nullptr)
			return FALSE;
		cpu_to_le32p(bv->pb, pnode.mid);
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_TRANSMITABLE_DISPLAY_NAME:
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		[[fallthrough]];
	case PR_DISPLAY_NAME:
	case PR_EMS_AB_DISPLAY_NAME_PRINTABLE: {
		std::string dn = pnode.displayname();
		if (dn.empty())
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return FALSE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_COMPANY_NAME: {
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		std::string dn;
		pnode.company_info(&dn, nullptr);
		if (dn.empty())
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_ACCOUNT:
	case PR_SMTP_ADDRESS: {
		std::string dn;
		if (node_type == ab_tree::abnode_type::mlist)
			pnode.mlist_info(&dn, nullptr, nullptr);
		else if (node_type == ab_tree::abnode_type::user)
			dn = znul(pnode.user_info(ab_tree::userinfo::mail_address));
		else
			return TRUE;
		if (dn.empty())
			return TRUE;
		auto pvalue = common_util_dup(dn);
		if (pvalue == nullptr)
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	case PR_EMS_AB_PROXY_ADDRESSES: {
		std::string dn;
		if (node_type == ab_tree::abnode_type::mlist)
			pnode.mlist_info(&dn, nullptr, nullptr);
		else if (node_type == ab_tree::abnode_type::user)
			dn = znul(pnode.user_info(ab_tree::userinfo::mail_address));
		else
			return TRUE;
		if (dn.empty())
			return TRUE;
		const auto alias_list = pnode.aliases();
		auto sa = cu_alloc<STRING_ARRAY>();
		if (sa == nullptr)
			return FALSE;
		sa->count = 1 + alias_list.size();
		sa->ppstr = cu_alloc<char *>(sa->count);
		if (sa->ppstr == nullptr)
			return FALSE;
		sa->ppstr[0] = cu_alloc<char>(dn.size() + 6);
		if (sa->ppstr[0] == nullptr)
			return FALSE;
		sprintf(sa->ppstr[0], "SMTP:%s", dn.c_str());
		size_t i = 1;
		for (const auto &a : alias_list) {
			sa->ppstr[i] = cu_alloc<char>(a.size() + 6);
			if (sa->ppstr[i] == nullptr)
				return false;
			strcpy(sa->ppstr[i], "SMTP:");
			strcat(sa->ppstr[i++], a.c_str());
		}
		*ppvalue = sa;
		return TRUE;
	}
	case PR_EMS_AB_THUMBNAIL_PHOTO: {
		auto path = pnode.user_info(ab_tree::userinfo::store_path);
		if (path == nullptr)
			return TRUE;
		auto pvalue = cu_alloc<BINARY>();
		if (pvalue == nullptr)
			return FALSE;
		auto bv = static_cast<BINARY *>(cu_read_storenamedprop(path,
		          PSETID_Gromox, "photo", PT_BINARY));
		if (bv != nullptr) {
			*ppvalue = bv;
			return TRUE;
		}
		std::string dn = path;
		dn += "/config/portrait.jpg";
		if (!common_util_load_file(dn.c_str(), pvalue))
			return TRUE;
		*ppvalue = pvalue;
		return TRUE;
	}
	}
	/* User-defined props */
	if (node_type == ab_tree::abnode_type::user || node_type == ab_tree::abnode_type::mlist) {
		auto ret = ab_tree_fetchprop(pnode, proptag, ppvalue);
		if (ret == ecSuccess)
			return TRUE;
		if (ret != ecNotFound)
			return false;
	}
	/*
	 * Fallback defaults in case ab_tree does not contain a prop
	 * (in case e.g. a user has not explicitly set SENDRICHINFO=0)
	 */
	switch (proptag) {
	case PR_SEND_RICH_INFO: {
		if (node_type >= ab_tree::abnode_type::containers)
			return TRUE;
		auto pvalue = cu_alloc<uint8_t>();
		if (pvalue == nullptr)
			return FALSE;
		*static_cast<uint8_t *>(pvalue) = 1;
		*ppvalue = pvalue;
		return TRUE;
	}
	}
	return TRUE;
}

BOOL ab_tree_fetch_node_properties(const ab_tree::ab_node& pnode,
                                    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (!ab_tree_fetch_node_property(pnode, tag, &pvalue))
			return FALSE;	
		if (pvalue == nullptr)
			continue;
		ppropvals->emplace_back(tag, pvalue);
	}
	return TRUE;
}

static bool ab_tree_resolve_node(const ab_tree::ab_node& pnode, const char *pstr)
{
	using ab_tree::userinfo;
	std::string dn = pnode.displayname();
	if (strcasestr(dn.c_str(), pstr) != nullptr)
		return true;
	if (pnode.dn(dn) && strcasecmp(dn.c_str(), pstr) == 0)
		return true;

	switch(pnode.type()) {
	case ab_tree::abnode_type::user: {
		auto s = pnode.user_info(userinfo::mail_address);
		if (s != nullptr && strcasestr(s, pstr) != nullptr)
			return true;
		for (const auto &a : pnode.aliases())
			if (strcasestr(a.c_str(), pstr) != nullptr)
				return true;
		for (auto info : {userinfo::nick_name, userinfo::job_title, userinfo::comment, userinfo::mobile_tel, userinfo::business_tel, userinfo::home_address}) {
			s = pnode.user_info(info);
			if(s != nullptr && strcasestr(s, pstr) != nullptr)
				return true;
		}
		break;
	}
	case ab_tree::abnode_type::mlist:
		pnode.mlist_info(&dn, nullptr, nullptr);
		if (strcasestr(dn.c_str(), pstr) != nullptr)
			return true;
		break;
	default:
		break;
	}
	return false;
}

bool ab_tree_resolvename(const ab_tree::ab_base* base, const char *pstr,
    std::vector<ab_tree::minid> &result_list) try
{
	result_list.clear();
	for (auto it = base->ubegin(); it != base->uend(); ++it) {
		ab_tree::ab_node node(it);
		if (node.hidden() & AB_HIDE_RESOLVE ||
		    !ab_tree_resolve_node(node, pstr))
			continue;
		result_list.push_back(*it);
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

static bool ab_tree_match_node(const ab_tree::ab_node& node, const RESTRICTION *pfilter)
{
	char *ptoken;
	void *pvalue;
	
	switch (pfilter->rt) {
	case RES_AND:
		for (unsigned int i = 0; i < pfilter->andor->count; ++i)
			if (!ab_tree_match_node(node, &pfilter->andor->pres[i]))
				return FALSE;
		return TRUE;
	case RES_OR:
		for (unsigned int i = 0; i < pfilter->andor->count; ++i)
			if (ab_tree_match_node(node, &pfilter->andor->pres[i]))
				return TRUE;
		return FALSE;
	case RES_NOT:
		if (ab_tree_match_node(node, &pfilter->xnot->res))
			return FALSE;
		return TRUE;
	case RES_CONTENT: {
		auto rcon = pfilter->cont;
		if (!rcon->comparable())
			return FALSE;
		if (!ab_tree_fetch_node_property(node, rcon->proptag, &pvalue))
			return FALSE;	
		return rcon->eval(pvalue);
	}
	case RES_PROPERTY: {
		auto rprop = pfilter->prop;
		if (!rprop->comparable())
			return false;
		if (rprop->proptag != PR_ANR) {
			if (!ab_tree_fetch_node_property(node, rprop->proptag, &pvalue))
				return false;
			return rprop->eval(pvalue);
		}
		if (ab_tree_fetch_node_property(node, PR_ACCOUNT, &pvalue) && pvalue != nullptr &&
		    strcasestr(static_cast<char *>(pvalue),
		    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
			return TRUE;
		/* =SMTP:user@company.com */
		ptoken = strchr(static_cast<char *>(rprop->propval.pvalue), ':');
		if (ptoken != nullptr && pvalue != nullptr &&
		    strcasestr(static_cast<char *>(pvalue), ptoken + 1) != nullptr)
			return TRUE;
		if (ab_tree_fetch_node_property(node, PR_DISPLAY_NAME, &pvalue) && pvalue != nullptr &&
		    strcasestr(static_cast<char *>(pvalue),
		    static_cast<char *>(rprop->propval.pvalue)) != nullptr)
			return TRUE;
		return FALSE;
	}
	case RES_BITMASK: {
		auto rbm = pfilter->bm;
		if (!rbm->comparable())
			return FALSE;
		if (!ab_tree_fetch_node_property(node, rbm->proptag, &pvalue) || pvalue == nullptr)
			return FALSE;
		return rbm->eval(pvalue);
	}
	case RES_EXIST: {
		auto node_type = node.type();
		if (node_type >= ab_tree::abnode_type::containers)
			return FALSE;
		if (ab_tree_fetch_node_property(node, pfilter->exist->proptag, &pvalue) && pvalue != nullptr)
			return TRUE;	
		return FALSE;
	}
	default:
		return FALSE;
	}
	return false;
}

BOOL ab_tree_match_minids(const ab_tree::ab_base *pbase, uint32_t container_id,
    const RESTRICTION *pfilter, LONG_ARRAY *pminids) try
{
	std::vector<ab_tree::minid> tlist;
	
	if (container_id == ab_tree::minid::SC_GAL) {
		for (auto it = pbase->ubegin(); it != pbase->uend(); ++it) {
			ab_tree::ab_node node(it);
			if (node.hidden() & AB_HIDE_FROM_GAL ||
			    !ab_tree_match_node(node, pfilter))
				continue;
			tlist.push_back(*it);
		}
	} else {
		ab_tree::ab_node node(pbase, container_id);
		if (!node.exists() || node.children_count() == 0) {
			pminids->count = 0;
			pminids->pl = NULL;
			return TRUE;
		}
		for (ab_tree::minid mid : node) {
			ab_tree::ab_node child(pbase, mid);
			if (child.type() >= ab_tree::abnode_type::containers ||
			    child.hidden() & AB_HIDE_FROM_AL ||
			    !ab_tree_match_node(child, pfilter))
				continue;
			tlist.push_back(mid);
		}
	}
	pminids->count = uint32_t(tlist.size());
	if (0 == pminids->count) {
		pminids->pl = NULL;
	} else {
		pminids->pl = cu_alloc<uint32_t>(pminids->count);
		if (NULL == pminids->pl) {
			pminids->count = 0;
			return FALSE;
		}
		size_t count = 0;
		for (auto mid : tlist)
			pminids->pl[count++] = mid;
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

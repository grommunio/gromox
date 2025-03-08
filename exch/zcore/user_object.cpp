// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <memory>
#include <libHX/string.h>
#include <gromox/ab_tree.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/util.hpp>
#include "ab_tree.hpp"
#include "common_util.hpp"
#include "objects.hpp"
#include "system_services.hpp"
#include "zserver.hpp"

using namespace gromox;

std::unique_ptr<oneoff_object> oneoff_object::create(const ONEOFF_ENTRYID &e) try
{
	return std::unique_ptr<oneoff_object>(new oneoff_object(e));
} catch (const std::bad_alloc &) {
	return nullptr;
}

const uint32_t oneoff_object::all_tags_raw[] = {
	PR_ADDRTYPE, PR_DISPLAY_NAME, PR_DISPLAY_TYPE, PR_EMAIL_ADDRESS,
	PR_OBJECT_TYPE, PR_SEARCH_KEY, PR_SEND_INTERNET_ENCODING,
	PR_SEND_RICH_INFO, PR_SMTP_ADDRESS,
};
const PROPTAG_ARRAY oneoff_object::all_tags =
	{std::size(all_tags_raw), deconst(all_tags_raw)};

oneoff_object::oneoff_object(const ONEOFF_ENTRYID &e) :
	m_flags(e.ctrl_flags), m_dispname(znul(e.pdisplay_name)),
	m_addrtype(znul(e.paddress_type)), m_emaddr(znul(e.pmail_address))
{}

ec_error_t oneoff_object::get_props(const PROPTAG_ARRAY *tags, TPROPVAL_ARRAY *vals)
{
	static constexpr uint32_t disptype = DT_MAILUSER;
	static constexpr auto objtype = static_cast<uint32_t>(MAPI_MAILUSER);
	vals->ppropval = cu_alloc<TAGGED_PROPVAL>(std::size(all_tags_raw));
	if (vals->ppropval == nullptr)
		return ecServerOOM;
	for (size_t i = 0; i < tags->count; ++i) {
		auto &vc = vals->ppropval[vals->count];
		switch (tags->pproptag[i]) {
		case PR_ADDRTYPE:      vc.pvalue = deconst(m_addrtype.c_str()); break;
		case PR_DISPLAY_NAME:  vc.pvalue = deconst(m_dispname.c_str()); break;
		case PR_DISPLAY_TYPE:  vc.pvalue = deconst(&disptype); break;
		case PR_EMAIL_ADDRESS: vc.pvalue = deconst(m_emaddr.c_str()); break;
		case PR_OBJECT_TYPE:   vc.pvalue = deconst(&objtype); break;
		case PR_SEARCH_KEY: {
			auto s = cu_alloc<char>(m_emaddr.size() + 6);
			strcpy(s, "SMTP:");
			strcat(s, m_emaddr.c_str());
			HX_strupper(s);
			auto bin = cu_alloc<BINARY>();
			if (bin == nullptr)
				return ecServerOOM;
			bin->cb = m_emaddr.size() + 6;
			bin->pc = s;
			vc.pvalue = bin;
			break;
		}
		case PR_SEND_INTERNET_ENCODING: {
			auto enc = cu_alloc<uint32_t>();
			if (enc == nullptr)
				return ecServerOOM;
			*enc = m_flags & 0x7E;
			vc.pvalue = enc;
			break;
		}
		case PR_SEND_RICH_INFO: {
			auto rich = cu_alloc<BOOL>();
			if (rich == nullptr)
				return ecServerOOM;
			*rich = !!(m_flags & MAPI_ONE_OFF_NO_RICH_INFO);
			vc.pvalue = rich;
			break;
		}
		case PR_SMTP_ADDRESS:
			if (m_emaddr.empty() || strcasecmp(m_addrtype.c_str(), "SMTP") != 0)
				continue;
			vc.pvalue = deconst(m_emaddr.c_str());
			break;
		default:
			continue;
		}
		vals->ppropval[vals->count++].proptag = tags->pproptag[i];
	}
	return ecSuccess;
}

std::unique_ptr<user_object> user_object::create(int base_id, uint32_t minid)
{
	std::unique_ptr<user_object> puser;
	try {
		puser.reset(new user_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	puser->base_id = base_id;
	puser->minid = minid;
	return puser;
}

bool user_object::valid()
{
	auto puser = this;
	auto pbase = ab_tree::AB.get(puser->base_id);
	if (!pbase)
		return FALSE;
	if (pbase->exists(puser->minid))
		return true;
	pbase.reset();
	ab_tree::minid mid(puser->minid);
	std::string username;
	if (mid.type() != ab_tree::minid::Type::address ||
	    mysql_adaptor_userid_to_name(mid.value(), username) != ecSuccess)
		return FALSE;
	return true;
}

BOOL user_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto puser = this;
	char tmp_buff[1024];
	static constexpr auto fake_type = static_cast<uint32_t>(MAPI_MAILUSER);
	
	auto pbase = ab_tree::AB.get(puser->base_id);
	if (!pbase)
		return FALSE;
	ab_tree::ab_node node(pbase, puser->minid);
	if (pbase->exists(puser->minid))
		return ab_tree_fetch_node_properties(node, pproptags, ppropvals);
	pbase.reset();
	/* if user is hidden from addressbook tree, we simply
		return the necessary information to the caller */
	auto w_otype = pproptags->has(PR_OBJECT_TYPE);
	auto w_atype = pproptags->has(PR_ADDRTYPE);
	auto w_smtp  = pproptags->has(PR_SMTP_ADDRESS);
	auto w_email = pproptags->has(PR_EMAIL_ADDRESS);
	auto w_dname = pproptags->has(PR_DISPLAY_NAME);
	auto w_acct  = pproptags->has(PR_ACCOUNT);
	bool wx_name = w_smtp || w_email || w_dname || w_acct;
	if (!w_otype && !w_atype && !wx_name) {
		ppropvals->count = 0;
		ppropvals->ppropval = nullptr;
		return TRUE;
	}
	ppropvals->count = 0;
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(6);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	if (w_otype)
		ppropvals->emplace_back(PR_OBJECT_TYPE, &fake_type);
	if (w_atype)
		ppropvals->emplace_back(PR_ADDRTYPE, "EX");
	std::string username;
	if (!wx_name ||
	    node.mid.type() != ab_tree::minid::Type::address ||
	    mysql_adaptor_userid_to_name(node.mid.value(), username) != ecSuccess)
		return TRUE;
	if (w_smtp) {
		auto s = common_util_dup(username);
		if (s == nullptr)
			return FALSE;
		ppropvals->emplace_back(PR_SMTP_ADDRESS, s);
	}
	if (w_acct) {
		auto s = common_util_dup(username);
		if (s == nullptr)
			return FALSE;
		ppropvals->emplace_back(PR_ACCOUNT, s);
	}
	std::string essdn;
	if (w_email && cvt_username_to_essdn(username.c_str(), g_org_name,
	    mysql_adaptor_get_user_ids, mysql_adaptor_get_domain_ids,
	    essdn) == ecSuccess) {
		auto s = common_util_dup(essdn);
		if (s == nullptr)
			return FALSE;
		ppropvals->emplace_back(PR_EMAIL_ADDRESS, s);
	}
	if (w_dname && mysql_adaptor_get_user_displayname(username.c_str(),
	    tmp_buff, std::size(tmp_buff))) {
		auto s = *tmp_buff != '\0' ? common_util_dup(tmp_buff) : common_util_dup(username);
		if (s == nullptr)
			return FALSE;
		ppropvals->emplace_back(PR_DISPLAY_NAME, s);
	}
	return TRUE;
}

ec_error_t user_object::load_list_members(const RESTRICTION *res) try
{
	auto base = ab_tree::AB.get(base_id);
	if (base == nullptr)
		return ecSuccess;
	ab_tree::ab_node node(base, minid);
	if (!node.exists())
		return ecSuccess;
	std::string mlistaddr;
	if (mysql_adaptor_userid_to_name(node.mid.value(), mlistaddr) != ecSuccess)
		return ecSuccess;
	std::vector<std::string> member_list;
	int ret = 0;
	if (!mysql_adaptor_get_mlist_memb(mlistaddr.c_str(), mlistaddr.c_str(), &ret, member_list))
		return ecSuccess;
	m_members.clear();
	for (const auto &memb : member_list) {
		unsigned int user_id = 0;
		if (!mysql_adaptor_get_user_ids(memb.c_str(), &user_id, nullptr, nullptr))
			continue;
		auto mid = ab_tree::minid(ab_tree::minid::address, user_id);
		node = {base, mid};
		LONG_ARRAY unused{};
		if (!node.exists() ||
		    !ab_tree_match_minids(base.get(), mid, res, &unused))
			continue;
		free(unused.pl);
		m_members.push_back(mid);
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-2187: ENOMEM");
	return ecServerOOM;
}

ec_error_t user_object::query_member_table(const PROPTAG_ARRAY *proptags,
    uint32_t start_pos, int32_t row_needed, TARRAY_SET *set)
{
	bool b_forward;
	uint32_t first_pos, row_count;

	if (row_needed == 0) {
		set->count = 0;
		set->pparray = nullptr;
		return ecSuccess;
	} else if (row_needed > 0) {
		b_forward = true;
		first_pos = start_pos;
		row_count = row_needed;
	} else {
		b_forward = false;
		if (static_cast<int64_t>(start_pos) + 1 + row_needed < 0) {
			first_pos = 0;
			row_count = start_pos + 1;
		} else {
			first_pos = start_pos + 1 + row_needed;
			row_count = -row_needed;
		}
	}
	set->count = 0;
	set->pparray = cu_alloc<TPROPVAL_ARRAY *>(row_count);
	if (set->pparray == nullptr)
		return ecServerOOM;
	if (m_members.size() == 0) {
		set->count = 0;
		set->pparray = nullptr;
		return ecSuccess;
	}
	auto base = ab_tree::AB.get(base_id);
	if (base == nullptr)
		return ecNotFound;
	for (size_t i = first_pos; i < first_pos + row_count &&
	     i < m_members.size(); ++i) {
		ab_tree::ab_node node(base, m_members[i]);
		if (!node.exists())
			continue;
		set->pparray[set->count] = cu_alloc<TPROPVAL_ARRAY>();
		if (set->pparray[set->count] == nullptr)
			return ecServerOOM;
		if (!ab_tree_fetch_node_properties(node,
		    proptags, set->pparray[set->count]))
			return ecNotFound;
		++set->count;
	}
	if (!b_forward) {
		for (size_t i = 0; i < set->count / 2; ++i) {
			auto propvals = set->pparray[i];
			set->pparray[i] = set->pparray[set->count-1-i];
			set->pparray[set->count-1-i] = propvals;
		}
	}
	return ecSuccess;
}

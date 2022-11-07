// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <memory>
#include <gromox/ab_tree.hpp>
#include <gromox/util.hpp>
#include "ab_tree.h"
#include "common_util.h"
#include "objects.hpp"
#include "system_services.hpp"
#include "zarafa_server.h"

using namespace gromox;

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
	char username[UADDR_SIZE];
	auto pbase = ab_tree_get_base(puser->base_id);
	if (pbase == nullptr)
		return FALSE;
	auto pnode = ab_tree_minid_to_node(pbase.get(), puser->minid);
	pbase.reset();
	if (pnode != nullptr)
		return true;
	if (ab_tree_get_minid_type(puser->minid) != minid_type::address ||
	    !system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
	    username, GX_ARRAY_SIZE(username)))
		return FALSE;
	return true;
}

BOOL user_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto puser = this;
	char username[UADDR_SIZE];
	char tmp_buff[1024];
	static const uint32_t fake_type = MAPI_MAILUSER;
	
	auto pbase = ab_tree_get_base(puser->base_id);
	if (pbase == nullptr)
		return FALSE;
	auto pnode = ab_tree_minid_to_node(pbase.get(), puser->minid);
	if (NULL == pnode) {
		pbase.reset();
		/* if user is hidden from addressbook tree, we simply
			return the necessary information to the caller */
		if (pproptags->has(PR_OBJECT_TYPE) ||
		    pproptags->has(PR_SMTP_ADDRESS) ||
		    pproptags->has(PR_ADDRTYPE) ||
		    pproptags->has(PR_EMAIL_ADDRESS) ||
		    pproptags->has(PR_DISPLAY_NAME) ||
		    pproptags->has(PR_ACCOUNT)) {
			ppropvals->count = 0;
			auto *vc = ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
			if (NULL == ppropvals->ppropval) {
				return FALSE;
			}
			if (pproptags->has(PR_OBJECT_TYPE)) {
				vc->proptag = PR_OBJECT_TYPE;
				vc->pvalue = deconst(&fake_type);
				ppropvals->count ++;
				++vc;
			}
			if (pproptags->has(PR_ADDRTYPE)) {
				vc->proptag = PR_ADDRTYPE;
				vc->pvalue = deconst("EX");
				ppropvals->count ++;
				++vc;
			}
			if ((pproptags->has(PR_SMTP_ADDRESS) ||
			    pproptags->has(PR_EMAIL_ADDRESS) ||
			    pproptags->has(PR_DISPLAY_NAME) ||
			    pproptags->has(PR_ACCOUNT)) &&
			    ab_tree_get_minid_type(puser->minid) == minid_type::address &&
			    system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
			    username, GX_ARRAY_SIZE(username))) {
				if (pproptags->has(PR_SMTP_ADDRESS)) {
					vc->proptag = PR_SMTP_ADDRESS;
					vc->pvalue = common_util_dup(username);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (pproptags->has(PR_ACCOUNT)) {
					vc->proptag = PR_ACCOUNT;
					vc->pvalue = common_util_dup(username);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (pproptags->has(PR_EMAIL_ADDRESS) &&
				    common_util_username_to_essdn(username, tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
					vc->proptag = PR_EMAIL_ADDRESS;
					vc->pvalue = common_util_dup(tmp_buff);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (pproptags->has(PR_DISPLAY_NAME) &&
				    system_services_get_user_displayname(username,
				    tmp_buff, arsizeof(tmp_buff))) {
					if ('\0' == tmp_buff[0]) {
						strcpy(tmp_buff, username);
					}
					vc->proptag = PR_DISPLAY_NAME;
					vc->pvalue = common_util_dup(tmp_buff);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;	
					++vc;
				}
			}
		} else {
			ppropvals->count = 0;
			ppropvals->ppropval = NULL;
		}
		return TRUE;
	}
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	return ab_tree_fetch_node_properties(pnode, pproptags, ppropvals);
}

ec_error_t user_object::load_list_members(const RESTRICTION *res) try
{
	auto base = ab_tree_get_base(base_id);
	if (base == nullptr)
		return ecSuccess;
	auto node = ab_tree_minid_to_node(base.get(), minid);
	if (node == nullptr)
		return ecSuccess;
	char mlistaddr[UADDR_SIZE]{};
	if (!system_services_get_username_from_id(ab_tree_get_minid_value(minid),
	    mlistaddr, std::size(mlistaddr)))
		return ecSuccess;
	std::vector<std::string> member_list;
	int ret = 0;
	if (!system_services_get_mlist_memb(mlistaddr, mlistaddr, &ret, member_list))
		return ecSuccess;
	m_members.clear();
	auto info = zarafa_server_get_info();
	for (const auto &memb : member_list) {
		int user_id;
		if (!system_services_get_id_from_username(memb.c_str(), &user_id))
			continue;
		auto mid = ab_tree_make_minid(minid_type::address, user_id);
		node = ab_tree_minid_to_node(base.get(), mid);
		LONG_ARRAY unused{};
		if (node == nullptr ||
		    !ab_tree_match_minids(base.get(), mid, info->cpid, res, &unused))
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
	auto base = ab_tree_get_base(base_id);
	if (base == nullptr)
		return ecNotFound;
	for (size_t i = first_pos; i < first_pos + row_count &&
	     i < m_members.size(); ++i) {
		auto node = ab_tree_minid_to_node(base.get(), m_members[i]);
		if (node == nullptr)
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

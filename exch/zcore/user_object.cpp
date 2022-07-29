// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <memory>
#include <gromox/ab_tree.hpp>
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

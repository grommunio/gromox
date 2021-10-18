// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "system_services.h"
#include "zarafa_server.h"
#include "user_object.h"
#include "common_util.h"
#include "ab_tree.h"
#include <cstdio>

std::unique_ptr<user_object> user_object::create(int base_id, uint32_t minid)
{
	std::unique_ptr<USER_OBJECT> puser;
	try {
		puser.reset(new user_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	puser->base_id = base_id;
	puser->minid = minid;
	return puser;
}

BOOL USER_OBJECT::check_valid()
{
	auto puser = this;
	char username[UADDR_SIZE];
	SIMPLE_TREE_NODE *pnode;
	auto pbase = ab_tree_get_base(puser->base_id);
	if (pbase == nullptr)
		return FALSE;
	pnode = ab_tree_minid_to_node(pbase.get(), puser->minid);
	pbase.reset();
	if (NULL == pnode) {
		if (ab_tree_get_minid_type(puser->minid) != MINID_TYPE_ADDRESS ||
		    !system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
		    username, GX_ARRAY_SIZE(username)))
			return FALSE;
	}
	return TRUE;
}

BOOL USER_OBJECT::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto puser = this;
	char username[UADDR_SIZE];
	char tmp_buff[1024];
	SIMPLE_TREE_NODE *pnode;
	static const uint32_t fake_type = MAPI_MAILUSER;
	
	auto pbase = ab_tree_get_base(puser->base_id);
	if (pbase == nullptr)
		return FALSE;
	pnode = ab_tree_minid_to_node(pbase.get(), puser->minid);
	if (NULL == pnode) {
		pbase.reset();
		/* if user is hidden from addressbook tree, we simply
			return the necessary information to the caller */
		if (common_util_index_proptags(pproptags, PR_OBJECT_TYPE) >= 0 ||
		    common_util_index_proptags(pproptags, PR_SMTP_ADDRESS) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_ADDRESSTYPE) >= 0 ||
		    common_util_index_proptags(pproptags, PR_EMAIL_ADDRESS) >= 0 ||
		    common_util_index_proptags(pproptags, PR_DISPLAY_NAME) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_ACCOUNT) >= 0) {
			ppropvals->count = 0;
			auto *vc = ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
			if (NULL == ppropvals->ppropval) {
				return FALSE;
			}
			if (common_util_index_proptags(pproptags, PR_OBJECT_TYPE) >= 0) {
				vc->proptag = PR_OBJECT_TYPE;
				vc->pvalue = deconst(&fake_type);
				ppropvals->count ++;
				++vc;
			}
			if (common_util_index_proptags(pproptags,
				PROP_TAG_ADDRESSTYPE) >= 0) {
				vc->proptag = PROP_TAG_ADDRESSTYPE;
				vc->pvalue = deconst("EX");
				ppropvals->count ++;
				++vc;
			}
			if ((common_util_index_proptags(pproptags, PR_SMTP_ADDRESS) >= 0 ||
			    common_util_index_proptags(pproptags, PR_EMAIL_ADDRESS) >= 0 ||
			    common_util_index_proptags(pproptags, PR_DISPLAY_NAME) >= 0 ||
				common_util_index_proptags(pproptags,
				PROP_TAG_ACCOUNT) >= 0) && MINID_TYPE_ADDRESS
				== ab_tree_get_minid_type(puser->minid) &&
			    system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
			    username, GX_ARRAY_SIZE(username))) {
				if (common_util_index_proptags(pproptags, PR_SMTP_ADDRESS) >= 0) {
					vc->proptag = PR_SMTP_ADDRESS;
					vc->pvalue = common_util_dup(username);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (common_util_index_proptags(pproptags,
					PROP_TAG_ACCOUNT) >= 0) {
					vc->proptag = PROP_TAG_ACCOUNT;
					vc->pvalue = common_util_dup(username);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (common_util_index_proptags(pproptags, PR_EMAIL_ADDRESS) >= 0 &&
				    common_util_username_to_essdn(username, tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
					vc->proptag = PR_EMAIL_ADDRESS;
					vc->pvalue = common_util_dup(tmp_buff);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (common_util_index_proptags(pproptags, PR_DISPLAY_NAME) >= 0 &&
				    system_services_get_user_displayname(username, tmp_buff)) {
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
	if (FALSE == ab_tree_fetch_node_properties(
		pnode, pproptags, ppropvals)) {
		return FALSE;	
	}
	return TRUE;
}

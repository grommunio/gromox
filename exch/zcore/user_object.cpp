// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include "system_services.h"
#include "zarafa_server.h"
#include "user_object.h"
#include "common_util.h"
#include "ab_tree.h"
#include <cstdio>

USER_OBJECT* user_object_create(int base_id, uint32_t minid)
{
	auto puser = me_alloc<USER_OBJECT>();
	if (NULL == puser) {
		return NULL;
	}
	puser->base_id = base_id;
	puser->minid = minid;
	return puser;
}

BOOL user_object_check_valid(USER_OBJECT *puser)
{
	char username[UADDR_SIZE];
	SIMPLE_TREE_NODE *pnode;
	auto pbase = ab_tree_get_base(puser->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	pnode = ab_tree_minid_to_node(pbase, puser->minid);
	pbase.reset();
	if (NULL == pnode) {
		if (ab_tree_get_minid_type(puser->minid) != MINID_TYPE_ADDRESS ||
		    !system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
		    username, GX_ARRAY_SIZE(username)))
			return FALSE;
	}
	return TRUE;
}

void user_object_free(USER_OBJECT *puser)
{
	free(puser);
}

BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	char username[UADDR_SIZE];
	char tmp_buff[1024];
	SIMPLE_TREE_NODE *pnode;
	static const uint32_t fake_type = OBJECT_USER;
	
	auto pbase = ab_tree_get_base(puser->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	pnode = ab_tree_minid_to_node(pbase, puser->minid);
	if (NULL == pnode) {
		pbase.reset();
		/* if user is hidden from addressbook tree, we simply
			return the necessary information to the caller */
		if (common_util_index_proptags(pproptags,
			PROP_TAG_OBJECTTYPE) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_SMTPADDRESS) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_ADDRESSTYPE) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_EMAILADDRESS) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_DISPLAYNAME) >= 0 ||
			common_util_index_proptags(pproptags,
			PROP_TAG_ACCOUNT) >= 0) {
			ppropvals->count = 0;
			auto *vc = ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(3);
			if (NULL == ppropvals->ppropval) {
				return FALSE;
			}
			if (common_util_index_proptags(pproptags,
				PROP_TAG_OBJECTTYPE) >= 0) {
				vc->proptag = PROP_TAG_OBJECTTYPE;
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
			if ((common_util_index_proptags(pproptags,
				PROP_TAG_SMTPADDRESS) >= 0 ||
				common_util_index_proptags(pproptags,
				PROP_TAG_EMAILADDRESS) >= 0 ||
				common_util_index_proptags(pproptags,
				PROP_TAG_DISPLAYNAME) >= 0 ||
				common_util_index_proptags(pproptags,
				PROP_TAG_ACCOUNT) >= 0) && MINID_TYPE_ADDRESS
				== ab_tree_get_minid_type(puser->minid) &&
			    system_services_get_username_from_id(ab_tree_get_minid_value(puser->minid),
			    username, GX_ARRAY_SIZE(username))) {
				if (common_util_index_proptags(pproptags,
					PROP_TAG_SMTPADDRESS) >= 0) {
					vc->proptag = PROP_TAG_SMTPADDRESS;
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
				if (common_util_index_proptags(pproptags,
					PROP_TAG_EMAILADDRESS) >= 0 && TRUE ==
				    common_util_username_to_essdn(username,
				    tmp_buff, GX_ARRAY_SIZE(tmp_buff))) {
					vc->proptag = PROP_TAG_EMAILADDRESS;
					vc->pvalue = common_util_dup(tmp_buff);
					if (vc->pvalue == nullptr)
						return FALSE;
					ppropvals->count ++;
					++vc;
				}
				if (common_util_index_proptags(pproptags,
					PROP_TAG_DISPLAYNAME) >= 0 && TRUE ==
					system_services_get_user_displayname(
					username, tmp_buff)) {
					if ('\0' == tmp_buff[0]) {
						strcpy(tmp_buff, username);
					}
					vc->proptag = PROP_TAG_DISPLAYNAME;
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

#include "zarafa_server.h"
#include "user_object.h"
#include "common_util.h"
#include "ab_tree.h"
#include <stdio.h>

USER_OBJECT* user_object_create(int base_id, uint32_t minid)
{
	USER_OBJECT *puser;
	
	puser = malloc(sizeof(USER_OBJECT));
	if (NULL == puser) {
		return NULL;
	}
	puser->base_id = base_id;
	puser->minid = minid;
	return puser;
}

void user_object_free(USER_OBJECT *puser)
{
	free(puser);
}

BOOL user_object_get_properties(USER_OBJECT *puser,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	AB_BASE *pbase;
	USER_INFO *pinfo;
	SIMPLE_TREE_NODE *pnode;
	static uint32_t fake_type = OBJECT_USER;
	
	pbase = ab_tree_get_base(puser->base_id);
	if (NULL == pbase) {
		return FALSE;
	}
	pnode = ab_tree_minid_to_node(pbase, puser->minid);
	if (NULL == pnode) {
		ab_tree_put_base(pbase);
		if (common_util_index_proptags(pproptags,
			PROP_TAG_OBJECTTYPE) >= 0) {
			ppropvals->count = 1;
			ppropvals->ppropval = common_util_alloc(sizeof(TAGGED_PROPVAL));
			if (NULL == ppropvals->ppropval) {
				return FALSE;
			}
			ppropvals->ppropval->proptag = PROP_TAG_OBJECTTYPE;
			ppropvals->ppropval->pvalue = &fake_type;
		} else {
			ppropvals->count = 0;
			ppropvals->ppropval = NULL;
		}
		return TRUE;
	}
	ppropvals->ppropval = common_util_alloc(
	sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		ab_tree_put_base(pbase);
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	if (FALSE == ab_tree_fetch_node_properties(
		pnode, pproptags, ppropvals)) {
		ab_tree_put_base(pbase);
		return FALSE;	
	}
	ab_tree_put_base(pbase);
	return TRUE;
}

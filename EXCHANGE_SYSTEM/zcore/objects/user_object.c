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
	puser->pemail_addr = NULL;
	return puser;
}

BOOL user_object_set_oneoff(USER_OBJECT *puser, const char *oneoff_string)
{
	EMAIL_ADDR email_addr;
	
	if (NULL != puser->pemail_addr) {
		free(puser->pemail_addr);
		puser->pemail_addr = NULL;
	}
	parse_email_addr(&email_addr, oneoff_string);
	if ('\0' == email_addr.local_part[0]
		|| '\0' == email_addr.domain[0]) {
		return FALSE;	
	}
	puser->pemail_addr = malloc(sizeof(EMAIL_ADDR));
	if (NULL == puser->pemail_addr) {
		return FALSE;
	}
	memcpy(puser->pemail_addr, &email_addr, sizeof(EMAIL_ADDR));
	return TRUE;
}

void user_object_free(USER_OBJECT *puser)
{
	if (NULL != puser->pemail_addr) {
		free(puser->pemail_addr);
	}
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
	static uint32_t obj_type = OBJECT_USER;
	static uint32_t dsp_type = DISPLAY_TYPE_MAILUSER;
	
	ppropvals->ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	if (NULL != puser->pemail_addr) {
		for (i=0; i<pproptags->count; i++) {
			ppropvals->ppropval[ppropvals->count].proptag =
									pproptags->pproptag[i];
			switch (pproptags->pproptag[i]) {
			case PROP_TAG_ABPROVIDERID:
				pvalue = common_util_alloc(sizeof(BINARY));
				if (NULL == pvalue) {
					return FALSE;
				}
				((BINARY*)pvalue)->cb = 16;
				((BINARY*)pvalue)->pb = common_util_get_muidecsab();
				ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
				ppropvals->count ++;
				break;
			case PROP_TAG_DISPLAYNAME:
			case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
			case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
				ppropvals->ppropval[ppropvals->count].pvalue =
							puser->pemail_addr->display_name;
				ppropvals->count ++;
				break;
			case PROP_TAG_ADDRESSTYPE:
				ppropvals->ppropval[ppropvals->count].pvalue = "SMTP";
				ppropvals->count ++;
				break;
			case PROP_TAG_SMTPADDRESS:
			case PROP_TAG_EMAILADDRESS:
				ppropvals->ppropval[ppropvals->count].pvalue =
										common_util_alloc(256);
				if (NULL == ppropvals->ppropval[ppropvals->count].pvalue) {
					return FALSE;
				}
				sprintf(ppropvals->ppropval[ppropvals->count].pvalue,
							"%s@%s", puser->pemail_addr->local_part,
							puser->pemail_addr->domain);
				ppropvals->count ++;
				break;
			case PROP_TAG_OBJECTTYPE:
				ppropvals->ppropval[ppropvals->count].pvalue = &obj_type;
				ppropvals->count ++;
				break;
			case PROP_TAG_DISPLAYTYPE:
			case PROP_TAG_DISPLAYTYPEEX:
				ppropvals->ppropval[ppropvals->count].pvalue = &dsp_type;
				ppropvals->count ++;
				break;
			}
		}
	} else {
		pbase = ab_tree_get_base(puser->base_id);
		if (NULL == pbase) {
			return FALSE;
		}
		pnode = ab_tree_minid_to_node(pbase, puser->minid);
		if (NULL == pnode) {
			ppropvals->count = 0;
			return TRUE;
		}
		pinfo = zarafa_server_get_info();
		if (FALSE == ab_tree_fetch_node_properties(
			pnode, pproptags, ppropvals)) {
			return FALSE;	
		}
		common_util_replace_address_type(ppropvals, TRUE);
	}
	return TRUE;
}

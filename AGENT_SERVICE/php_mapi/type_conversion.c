#include "type_conversion.h"
#include <iconv.h>
#define TIME_FIXUP_CONSTANT_INT				11644473600LL

uint64_t unix_to_nttime(time_t unix_time)
{
	uint64_t nt_time; 

	nt_time = unix_time;
	nt_time += TIME_FIXUP_CONSTANT_INT;
	nt_time *= 10000000;
	return nt_time;
}

time_t nttime_to_unix(uint64_t nt_time)
{
	uint64_t unix_time;

	unix_time = nt_time;
	unix_time /= 10000000;
	unix_time -= TIME_FIXUP_CONSTANT_INT;
	return (time_t)unix_time;
}

/* in php-mapi the PROPVAL_TYPE_STRING means utf-8
	string we don't user PROPVAL_TYPE_WSTRING,
	there's no definition for ansi string */
uint32_t proptag_to_phptag(uint32_t proptag)
{
	uint32_t proptag1;
	
	proptag1 = proptag;
	switch (proptag & 0xFFFF) {
	case PROPVAL_TYPE_WSTRING:
		proptag1 &= 0xFFFF0000;
		proptag1 |= PROPVAL_TYPE_STRING;
		break;
	case PROPVAL_TYPE_WSTRING_ARRAY:
		proptag1 &= 0xFFFF0000;
		proptag1 |= PROPVAL_TYPE_STRING_ARRAY;
		break;
	}
	return proptag1;
}

uint32_t phptag_to_proptag(uint32_t proptag)
{
	uint32_t proptag1;
	
	proptag1 = proptag;
	switch (proptag & 0xFFFF) {
	case PROPVAL_TYPE_STRING:
		proptag1 &= 0xFFFF0000;
		proptag1 |= PROPVAL_TYPE_WSTRING;
		break;
	case PROPVAL_TYPE_STRING_ARRAY:
		proptag1 &= 0xFFFF0000;
		proptag1 |= PROPVAL_TYPE_WSTRING_ARRAY;
		break;
	}
	return proptag1;
}

zend_bool php_to_binary_array(zval *pzval,
	BINARY_ARRAY *pbins TSRMLS_DC)
{
	int i;
	zval *pentry;
	zval **ppentry;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	pbins->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	if (0 == pbins->count) {
		pbins->pbin = NULL;
		return 1;
	}
	pbins->pbin = emalloc(sizeof(BINARY)*pbins->count);
	if (NULL == pbins->pbin) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<pbins->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		pentry = *ppentry;
		convert_to_string_ex(&pentry);
		pbins->pbin[i].cb = pentry->value.str.len;
		if (0 == pentry->value.str.len) {
			pbins->pbin[i].pb = NULL;
		} else {
			pbins->pbin[i].pb = emalloc(pbins->pbin[i].cb);
			if (NULL == pbins->pbin[i].pb) {
				return 0;
			}
			memcpy(pbins->pbin[i].pb,
				pentry->value.str.val,
				pentry->value.str.len);
		}
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

zend_bool binary_array_to_php(const BINARY_ARRAY *pbins,
	zval **ppzval TSRMLS_DC)
{
	int i;
	zval *pzval;
	
	MAKE_STD_ZVAL(pzval);
	array_init(pzval);
	for (i=0; i<pbins->count; i++) {
		add_next_index_stringl(
			pzval, pbins->pbin[i].pb,
			pbins->pbin[i].cb, 1);
	}
	*ppzval = pzval;
	return 1;
}

zend_bool php_to_sortorder_set(zval *pzval,
	SORTORDER_SET *pset TSRMLS_DC)
{
	int i;
	char *pkey;
	zval **ppentry;
	uint32_t proptag;
	unsigned long idx;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	pset->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	pset->ccategories = 0;
	pset->cexpanded = 0;
	if (0 == pset->count) {
		pset->psort = NULL;
		return 1;
	}
	pset->psort = emalloc(sizeof(SORT_ORDER)*pset->count);
	if (NULL == pset->psort) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<pset->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		pkey = NULL;
		zend_hash_get_current_key(ptarget_hash, &pkey, &idx, 0);
		if (NULL != pkey) {
			proptag = atoi(pkey);
		} else {
			proptag = idx;
		}
		proptag = phptag_to_proptag(proptag);
		pset->psort[i].propid = proptag >> 16;
		pset->psort[i].type = proptag & 0xFFFF;
		convert_to_long_ex(&ppentry[0]);
		pset->psort[i].table_sort = ppentry[0]->value.lval;
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

zend_bool php_to_proptag_array(zval *pzval,
	PROPTAG_ARRAY *pproptags TSRMLS_DC)
{
	int i;
	zval **ppentry;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	pproptags->count = zend_hash_num_elements(ptarget_hash);
	if (0 == pproptags->count) {
		pproptags->pproptag = NULL;
		return 1;
	}
	pproptags->pproptag = emalloc(sizeof(uint32_t)*pproptags->count);
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<pproptags->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		convert_to_long_ex(ppentry);
		pproptags->pproptag[i] =
			phptag_to_proptag(ppentry[0]->value.lval);
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

static void* php_to_propval(zval **ppentry, uint16_t proptype)
{
	int j, k;
	void *pvalue;
	char *pstring;
	zval **ppdata_entry;
	ACTION_BLOCK *pblock;
	HashTable *pdata_hash;
	HashTable *paction_hash;
	RESTRICTION	prestriction;
	HashTable *precipient_hash;
	TPROPVAL_ARRAY tmp_propvals;
	RECIPIENT_BLOCK *prcpt_block;
	
	switch(proptype)	{
	case PROPVAL_TYPE_SHORT:
		convert_to_long_ex(ppentry);
		pvalue = emalloc(sizeof(uint16_t));
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint16_t*)pvalue = ppentry[0]->value.lval;
		break;
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		convert_to_long_ex(ppentry);
		pvalue = emalloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint32_t*)pvalue = ppentry[0]->value.lval;
		break;
	case PROPVAL_TYPE_FLOAT:
		convert_to_double_ex(ppentry);
		pvalue = emalloc(sizeof(float));
		if (NULL == pvalue) {
			return NULL;
		}
		*(float*)pvalue = (float)ppentry[0]->value.dval;
		break;
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		convert_to_double_ex(ppentry);
		pvalue = emalloc(sizeof(double));
		if (NULL == pvalue) {
			return NULL;
		}
		*(double*)pvalue = ppentry[0]->value.dval;
		break;
	case PROPVAL_TYPE_LONGLONG:
		convert_to_double_ex(ppentry);
		pvalue = emalloc(sizeof(uint64_t));
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint64_t*)pvalue = (uint64_t)ppentry[0]->value.dval;
		break;
	case PROPVAL_TYPE_BYTE:
		convert_to_boolean_ex(ppentry);
		pvalue = emalloc(sizeof(uint8_t));
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint8_t*)pvalue = ppentry[0]->value.lval;
		break;
	case PROPVAL_TYPE_FILETIME:
		/* convert unix timestamp to nt timestamp */
		convert_to_long_ex(ppentry);
		pvalue = emalloc(sizeof(uint64_t));
		if (NULL == pvalue) {
			return NULL;
		}
		*(uint64_t*)pvalue = unix_to_nttime(ppentry[0]->value.lval);
		break;
	case PROPVAL_TYPE_BINARY:
		convert_to_string_ex(ppentry);
		pvalue = emalloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return NULL;
		}
		((BINARY*)pvalue)->cb = ppentry[0]->value.str.len;
		if (0 == ppentry[0]->value.str.len) {
			((BINARY*)pvalue)->pb = NULL;
		} else {
			((BINARY*)pvalue)->pb = emalloc(ppentry[0]->value.str.len);
			if (NULL == ((BINARY*)pvalue)->pb) {
				return NULL;
			}
			memcpy(((BINARY*)pvalue)->pb,
				ppentry[0]->value.str.val,
				ppentry[0]->value.str.len);
		}
		break;
	case PROPVAL_TYPE_STRING:
	case PROPVAL_TYPE_WSTRING:
		convert_to_string_ex(ppentry);
		pvalue = emalloc(ppentry[0]->value.str.len + 1);
		if (NULL == pvalue) {
			return NULL;
		}
		memcpy(pvalue, ppentry[0]->value.str.val,
			ppentry[0]->value.str.len);
		((char*)pvalue)[ppentry[0]->value.str.len] = '\0';
		break;
	case PROPVAL_TYPE_GUID:
		convert_to_string_ex(ppentry);
		if (ppentry[0]->value.str.len != sizeof(GUID)) {
			return NULL;
		}
		pvalue = emalloc(sizeof(GUID));
		if (NULL == pvalue) {
			return NULL;
		}
		memcpy(pvalue, ppentry[0]->value.str.val, sizeof(GUID));
		break;
	case PROPVAL_TYPE_SHORT_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(SHORT_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((SHORT_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((SHORT_ARRAY*)pvalue)->count) {
			((SHORT_ARRAY*)pvalue)->ps = NULL;
			break;
		}
		((SHORT_ARRAY*)pvalue)->ps =
			emalloc(sizeof(uint16_t)*
			((SHORT_ARRAY*)pvalue)->count);
		if (NULL == ((SHORT_ARRAY*)pvalue)->ps) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((SHORT_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(
				pdata_hash, (void**)&ppdata_entry);
			convert_to_long_ex(ppdata_entry);
			((SHORT_ARRAY*)pvalue)->ps[j] =
				ppdata_entry[0]->value.lval;
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_LONG_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(LONG_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((LONG_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((LONG_ARRAY*)pvalue)->count) {
			((LONG_ARRAY*)pvalue)->pl = NULL;
			break;
		}
		((LONG_ARRAY*)pvalue)->pl =
			emalloc(sizeof(uint32_t)*
			((LONG_ARRAY*)pvalue)->count);
		if (NULL == ((LONG_ARRAY*)pvalue)->pl) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((LONG_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(
				pdata_hash, (void**)&ppdata_entry);
			convert_to_long_ex(ppdata_entry);
			((LONG_ARRAY*)pvalue)->pl[j] =
				ppdata_entry[0]->value.lval;
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_LONGLONG_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(LONGLONG_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((LONGLONG_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((LONGLONG_ARRAY*)pvalue)->count) {
			((LONGLONG_ARRAY*)pvalue)->pll = NULL;
			break;
		}
		((LONGLONG_ARRAY*)pvalue)->pll =
			emalloc(sizeof(uint64_t)*
			((LONGLONG_ARRAY*)pvalue)->count);
		if (NULL == ((LONGLONG_ARRAY*)pvalue)->pll) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((LONGLONG_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(
				pdata_hash, (void**)&ppdata_entry);
			convert_to_double_ex(ppdata_entry);
			((LONGLONG_ARRAY*)pvalue)->pll[j] =
					ppdata_entry[0]->value.dval;
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_STRING_ARRAY:
	case PROPVAL_TYPE_WSTRING_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(STRING_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((STRING_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((STRING_ARRAY*)pvalue)->count) {
			((STRING_ARRAY*)pvalue)->ppstr = NULL;
			break;
		}
		((STRING_ARRAY*)pvalue)->ppstr = emalloc(
			sizeof(char*)*((STRING_ARRAY*)pvalue)->count);
		if (NULL == ((STRING_ARRAY*)pvalue)->ppstr) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((STRING_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(pdata_hash, (void**)&ppdata_entry);
			convert_to_string_ex(ppdata_entry);
			pstring = emalloc(ppdata_entry[0]->value.str.len + 1);
			if (NULL == pstring) {
				return NULL;
			}
			((STRING_ARRAY*)pvalue)->ppstr[j] = pstring;
			memcpy(pstring, ppdata_entry[0]->value.str.val,
							ppdata_entry[0]->value.str.len);
			pstring[ppdata_entry[0]->value.str.len] = '\0';
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_BINARY_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(BINARY_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((BINARY_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((BINARY_ARRAY*)pvalue)->count) {
			((BINARY_ARRAY*)pvalue)->pbin = NULL;
			break;
		}
		((BINARY_ARRAY*)pvalue)->pbin = emalloc(
			sizeof(BINARY)*((BINARY_ARRAY*)pvalue)->count);
		if (NULL == ((BINARY_ARRAY*)pvalue)->pbin) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((BINARY_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(
				pdata_hash, (void**)&ppdata_entry);
			convert_to_string_ex(ppdata_entry);
			((BINARY_ARRAY*)pvalue)->pbin[j].cb =
					ppdata_entry[0]->value.str.len;
			if (0 == ppdata_entry[0]->value.str.len) {
				((BINARY_ARRAY*)pvalue)->pbin[j].pb = NULL;
			} else {
				((BINARY_ARRAY*)pvalue)->pbin[j].pb
					= emalloc(ppdata_entry[0]->value.str.len);
				if (NULL == ((BINARY_ARRAY*)pvalue)->pbin[j].pb) {
					return NULL;
				}
				memcpy(((BINARY_ARRAY*)pvalue)->pbin[j].pb,
					ppdata_entry[0]->value.str.val,
					ppdata_entry[0]->value.str.len);
			}
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_GUID_ARRAY:
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			return NULL;
		}
		pvalue = emalloc(sizeof(GUID_ARRAY));
		if (NULL == pvalue) {
			return NULL;
		}
		((GUID_ARRAY*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((GUID_ARRAY*)pvalue)->count) {
			((GUID_ARRAY*)pvalue)->pguid = NULL;
			break;
		}
		((GUID_ARRAY*)pvalue)->pguid = emalloc(
			sizeof(GUID)*((GUID_ARRAY*)pvalue)->count);
		if (NULL == ((GUID_ARRAY*)pvalue)->pguid) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((GUID_ARRAY*)pvalue)->count; j++) {
			zend_hash_get_current_data(pdata_hash, (void**)&ppdata_entry);
			convert_to_string_ex(ppdata_entry);
			if (ppdata_entry[0]->value.str.len != sizeof(GUID)) {
				return NULL;
			}
			memcpy(&((GUID_ARRAY*)pvalue)->pguid[j],
				ppdata_entry[0]->value.str.val, sizeof(GUID));
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_RULE:
		pvalue = emalloc(sizeof(RULE_ACTIONS));
		if (NULL == pvalue) {
			return NULL;
		}
		pdata_hash = HASH_OF(ppentry[0]);
		if (NULL == pdata_hash) {
			((RULE_ACTIONS*)pvalue)->count = 0;
			((RULE_ACTIONS*)pvalue)->pblock = NULL;
			break;
		}
		((RULE_ACTIONS*)pvalue)->count =
			zend_hash_num_elements(pdata_hash);
		if (0 == ((RULE_ACTIONS*)pvalue)->count) {
			((RULE_ACTIONS*)pvalue)->pblock = NULL;
			break;
		}
		((RULE_ACTIONS*)pvalue)->pblock = emalloc(sizeof(
			ACTION_BLOCK)*((RULE_ACTIONS*)pvalue)->count);
		if (NULL == ((RULE_ACTIONS*)pvalue)->pblock) {
			return NULL;
		}
		zend_hash_internal_pointer_reset(pdata_hash);
		for (j=0; j<((RULE_ACTIONS*)pvalue)->count; j++) {
			zend_hash_get_current_data(pdata_hash, (void**)&ppentry);
			paction_hash = HASH_OF(ppentry[0]);
			if (NULL == paction_hash) {
				return NULL;
			}
			if (zend_hash_find(paction_hash,
				"action", sizeof("action"),
				(void**)&ppdata_entry) != SUCCESS) {
				return NULL;
			}
			convert_to_long_ex(ppdata_entry);
			pblock = ((RULE_ACTIONS*)pvalue)->pblock + j;
			pblock->type = Z_LVAL_PP(ppdata_entry);
			/* option field user defined flags, default 0 */
			if (zend_hash_find(paction_hash,
				"flags", sizeof("flags"),
				(void**)&ppdata_entry) == SUCCESS) {
				convert_to_long_ex(ppdata_entry);
				pblock->flags = Z_LVAL_PP(ppdata_entry);
			} else {
				pblock->flags = 0;
			}
			/* option field used with OP_REPLAY and OP_FORWARD, default 0 */
			if (zend_hash_find(paction_hash,
				"flavor", sizeof("flavor"),
				(void**)&ppdata_entry) == SUCCESS) {
				convert_to_long_ex(ppdata_entry);
				pblock->flavor = Z_LVAL_PP(ppdata_entry);
			} else {
				pblock->flavor = 0;
			}
			switch (pblock->type) {
			case ACTION_TYPE_OP_MOVE:
			case ACTION_TYPE_OP_COPY:
				pblock->pdata = emalloc(sizeof(MOVECOPY_ACTION));
				if (NULL == pblock->pdata) {
					return NULL;
				}
				if (zend_hash_find(paction_hash,
					"storeentryid", sizeof("storeentryid"),
					(void**)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				convert_to_string_ex(ppdata_entry);
				((MOVECOPY_ACTION*)pblock->pdata)->store_eid.cb =
									ppdata_entry[0]->value.str.len;
				((MOVECOPY_ACTION*)pblock->pdata)->store_eid.pb =
							emalloc(ppdata_entry[0]->value.str.len);
				if (NULL == ((MOVECOPY_ACTION*)pblock->pdata)->store_eid.pb) {
					return NULL;
				}
				memcpy(((MOVECOPY_ACTION*)
					pblock->pdata)->store_eid.pb,
					ppdata_entry[0]->value.str.val,
					ppdata_entry[0]->value.str.len);
				if (zend_hash_find(paction_hash,
					"folderentryid", sizeof("folderentryid"),
					(void **)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				convert_to_string_ex(ppdata_entry);
				((MOVECOPY_ACTION*)pblock->pdata)->folder_eid.cb =
									ppdata_entry[0]->value.str.len;
				((MOVECOPY_ACTION*)pblock->pdata)->folder_eid.pb =
							emalloc(ppdata_entry[0]->value.str.len);
				if (NULL == ((MOVECOPY_ACTION*)pblock->pdata)->folder_eid.pb) {
					return NULL;
				}
				memcpy(((MOVECOPY_ACTION*)
					pblock->pdata)->folder_eid.pb,
					ppdata_entry[0]->value.str.val,
					ppdata_entry[0]->value.str.len);
				break;
			case ACTION_TYPE_OP_REPLY:
			case ACTION_TYPE_OP_OOF_REPLY:
				if (zend_hash_find(paction_hash,
					"replyentryid", sizeof("replyentryid"),
					(void**)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				convert_to_string_ex(ppdata_entry);
				pblock->pdata = emalloc(sizeof(REPLY_ACTION));
				if (NULL == pblock->pdata) {
					return NULL;
				}
				((REPLY_ACTION*)pblock->pdata)->message_eid.cb =
									ppdata_entry[0]->value.str.len;
				((REPLY_ACTION*)pblock->pdata)->message_eid.pb =
						emalloc(ppdata_entry[0]->value.str.len);
				if (NULL == ((REPLY_ACTION*)pblock->pdata)->message_eid.pb) {
					return NULL;
				}
				memcpy(((REPLY_ACTION*)
					pblock->pdata)->message_eid.pb,
					ppdata_entry[0]->value.str.val,
					ppdata_entry[0]->value.str.len);
				if (zend_hash_find(paction_hash,
					"replyguid", sizeof("replyguid"),
					(void **)&ppdata_entry) == SUCCESS) {
					convert_to_string_ex(ppdata_entry);
					if (ppdata_entry[0]->value.str.len != sizeof(GUID)) {
						return NULL;
					}
					memcpy(&((REPLY_ACTION*)pblock->pdata)->template_guid,
							ppdata_entry[0]->value.str.val, sizeof(GUID));
				} else {
					memset(&((REPLY_ACTION*)
						pblock->pdata)->template_guid, 0, sizeof(GUID));
				}
				break;
			case ACTION_TYPE_OP_DEFER_ACTION:
				if (zend_hash_find(paction_hash, "dam", sizeof("dam"),
					(void**)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				convert_to_string_ex(ppdata_entry);
				if (0 == ppdata_entry[0]->value.str.len) {
					return NULL;
				}
				pblock->length = ppdata_entry[0]->value.str.len
						+ sizeof(uint8_t) + 2*sizeof(uint32_t);
				pblock->pdata = emalloc(ppdata_entry[0]->value.str.len);
				if (NULL == pblock->pdata) {
					return NULL;
				}
				memcpy(pblock->pdata,
					ppdata_entry[0]->value.str.val,
					ppdata_entry[0]->value.str.len);
				break;
			case ACTION_TYPE_OP_BOUNCE:
				if (zend_hash_find(paction_hash, "code", sizeof("code"),
					(void**)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				convert_to_long_ex(ppdata_entry);
				pblock->pdata = emalloc(sizeof(uint32_t));
				if (NULL == pblock->pdata) {
					return NULL;
				}
				*(uint32_t*)pblock->pdata = Z_LVAL_PP(ppdata_entry);
				break;
			case ACTION_TYPE_OP_FORWARD:
			case ACTION_TYPE_OP_DELEGATE:
				if (zend_hash_find(paction_hash, "adrlist",
					sizeof("adrlist"), (void**)&ppdata_entry)
					!= SUCCESS || ppdata_entry[0]->type != IS_ARRAY) {
					return NULL;
				}
				pblock->pdata = emalloc(sizeof(FORWARDDELEGATE_ACTION));
				if (NULL == pblock->pdata) {
					return NULL;
				}
				precipient_hash = HASH_OF(ppdata_entry[0]);
				((FORWARDDELEGATE_ACTION*)pblock->pdata)->count =
						zend_hash_num_elements(precipient_hash);
				if (0 == ((FORWARDDELEGATE_ACTION*)pblock->pdata)->count) {
					return NULL;
				}
				((FORWARDDELEGATE_ACTION*)pblock->pdata)->pblock =
					emalloc(sizeof(RECIPIENT_BLOCK)*
					((FORWARDDELEGATE_ACTION*)pblock->pdata)->count);
				if (NULL == ((FORWARDDELEGATE_ACTION*)
					pblock->pdata)->pblock) {
					return NULL;
				}
				zend_hash_internal_pointer_reset(precipient_hash);
				for (k=0; k<((FORWARDDELEGATE_ACTION*)
					pblock->pdata)->count; k++) {
					zend_hash_get_current_data(
						precipient_hash, (void**)&ppdata_entry);
					if (!php_to_tpropval_array(ppdata_entry[0],
						&tmp_propvals TSRMLS_CC)) {
						return NULL;
					}
					prcpt_block = ((FORWARDDELEGATE_ACTION*)
								pblock->pdata)->pblock + k;
					prcpt_block->reserved = 0;
					prcpt_block->count = tmp_propvals.count;
					prcpt_block->ppropval = tmp_propvals.ppropval;
					zend_hash_move_forward(precipient_hash);
				}
				break;
			case ACTION_TYPE_OP_TAG:
				if (zend_hash_find(paction_hash,
					"proptag", sizeof("proptag"),
					(void**)&ppdata_entry) != SUCCESS) {
					return NULL;
				}
				if (!php_to_tpropval_array(
					ppdata_entry[0], &tmp_propvals TSRMLS_CC)) {
					return NULL;
				}
				if (1 != tmp_propvals.count) {
					return NULL;
				}
				pblock->pdata = tmp_propvals.ppropval;
				break;
			case ACTION_TYPE_OP_DELETE:
			case ACTION_TYPE_OP_MARK_AS_READ:
				pblock->pdata = NULL;
				break;
			default:
				return NULL;
			}
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case PROPVAL_TYPE_RESTRICTION:
		pvalue = emalloc(sizeof(RESTRICTION));
		if (NULL == pvalue) {
			return NULL;
		}
		if (!php_to_restriction(ppentry[0], pvalue TSRMLS_CC)) {
			return NULL;
		}
		break;
	default:
		return NULL;
	}
	return pvalue;
}

zend_bool php_to_tpropval_array(zval *pzval,
	TPROPVAL_ARRAY *ppropvals TSRMLS_DC)
{
	int i;
	char *pstring;
	zval **ppentry;
	unsigned long idx;
	HashTable *ptarget_hash;
	
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	ppropvals->count = zend_hash_num_elements(ptarget_hash);
	if (0 == ppropvals->count) {
	   ppropvals->ppropval = NULL;
	   return 1;
	}
	ppropvals->ppropval = emalloc(sizeof(
		TAGGED_PROPVAL)*ppropvals->count);
	if (NULL == ppropvals->ppropval) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<ppropvals->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		zend_hash_get_current_key(
			ptarget_hash, &pstring, &idx, 0);
		ppropvals->ppropval[i].proptag = phptag_to_proptag(idx);
		ppropvals->ppropval[i].pvalue =
			php_to_propval(ppentry, idx & 0xFFFF);
		if (NULL == ppropvals->ppropval[i].pvalue) {
			return 0;
		}
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

zend_bool php_to_tarray_set(zval *pzval, TARRAY_SET *pset TSRMLS_DC) 
{
	int i;
	zval **ppentry;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	if (pzval->type != IS_ARRAY) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	pset->count = zend_hash_num_elements(ptarget_hash);
	if (0 == pset->count) {
		pset->pparray = NULL;
		return 1;
	}
	pset->pparray = emalloc(sizeof(TPROPVAL_ARRAY*)*pset->count);
	if (NULL == pset->pparray) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<pset->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		if (ppentry[0]->type != IS_ARRAY) {
			return 0;
		}
		pset->pparray[i] = emalloc(sizeof(TPROPVAL_ARRAY));
		if (NULL == pset->pparray[i]) {
			return 0;
		}
		if (!php_to_tpropval_array(ppentry[0],
			pset->pparray[i] TSRMLS_CC)) {
			return 0;
		}
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

zend_bool php_to_rule_list(zval *pzval, RULE_LIST *plist TSRMLS_DC)
{
	int i;
	zval **ppdata;
	zval **ppentry;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	if (pzval->type != IS_ARRAY) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	plist->count = zend_hash_num_elements(ptarget_hash);
	if (0 == plist->count) {
		plist->prule = NULL;
		return 1;
	}
	plist->prule = emalloc(sizeof(RULE_DATA)*plist->count);
	if (NULL == plist->prule) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<plist->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		if (Z_TYPE_PP(ppentry) != IS_ARRAY) {
			return 0;
		}
		if (!zend_hash_find(HASH_OF(ppentry[0]), "properties",
			sizeof("properties"), (void**)&ppdata) == SUCCESS) {
			return 0;	
		}
		if (!php_to_tpropval_array(ppdata[0],
			&plist->prule[i].propvals TSRMLS_CC)) {
			return 0;
		}
		if (!zend_hash_find(HASH_OF(ppentry[0]), "rowflags",
			sizeof("rowflags"), (void**)&ppdata) == SUCCESS) {
			return 0;	
		}
		plist->prule[i].flags = Z_LVAL_PP(ppdata);
		zend_hash_move_forward(ptarget_hash);
	}
	return 1;
}

#define IDX_VALUE									0
#define IDX_RELOP									1
#define IDX_FUZZYLEVEL								2
#define IDX_SIZE									3
#define IDX_TYPE									4
#define IDX_MASK									5
#define IDX_PROPTAG									6
#define IDX_PROPTAG1								7
#define IDX_PROPTAG2								8
#define IDX_PROPVALS								9
#define IDX_RESTRICTION								10

zend_bool php_to_restriction(zval *pzval, RESTRICTION *pres TSRMLS_DC)
{
	int i;
	zval **pptype_entry;
	zval **ppvalue_entry;
	HashTable *pres_hash;
	HashTable *pdata_hash;
	TPROPVAL_ARRAY tmp_propvals;
	
	pres_hash = HASH_OF(pzval);
	if (NULL == pres_hash || zend_hash_num_elements(pres_hash) != 2) {
		return 0;
	}
	zend_hash_internal_pointer_reset(pres_hash);
	/* 0=>type, 1=>value array */
	zend_hash_get_current_data(pres_hash, (void**)&pptype_entry);
	zend_hash_move_forward(pres_hash);
	zend_hash_get_current_data(pres_hash, (void**)&ppvalue_entry);
	pres->rt = pptype_entry[0]->value.lval;
	pdata_hash = HASH_OF(ppvalue_entry[0]);
	if (NULL == pdata_hash) {
		return 0;
	}
	zend_hash_internal_pointer_reset(pdata_hash);
	switch(pres->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		pres->pres = emalloc(sizeof(RESTRICTION_AND_OR));
		if (NULL == pres->pres) {
			return 0;
		}
		((RESTRICTION_AND_OR*)pres->pres)->count =
				zend_hash_num_elements(pdata_hash);
		((RESTRICTION_AND_OR*)pres->pres)->pres = emalloc(sizeof(
			RESTRICTION)*((RESTRICTION_AND_OR*)pres->pres)->count);
		if (NULL == ((RESTRICTION_AND_OR*)pres->pres)->pres) {
			return 0;
		}
		for (i=0; i<((RESTRICTION_AND_OR*)pres->pres)->count; i++) {
			zend_hash_get_current_data(pdata_hash, (void**)&ppvalue_entry);
			if (!php_to_restriction(ppvalue_entry[0],
				&((RESTRICTION_AND_OR*)pres->pres)->pres[i] TSRMLS_CC)) {
				return 0;
			}
			zend_hash_move_forward(pdata_hash);
		}
		break;
	case RESTRICTION_TYPE_NOT:
		pres->pres = emalloc(sizeof(RESTRICTION_NOT));
		if (NULL == pres->pres) {
			return 0;
		}
		zend_hash_get_current_data(pdata_hash, (void**)&ppvalue_entry);
		if (!php_to_restriction(ppvalue_entry[0],
			&((RESTRICTION_NOT*)pres->pres)->res TSRMLS_CC)) {
			return 0;
		}
		break;
	case RESTRICTION_TYPE_SUBOBJ:
		pres->pres = emalloc(sizeof(RESTRICTION_SUBOBJ));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		((RESTRICTION_SUBOBJ*)pres->pres)->subobject =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		if (zend_hash_index_find(
			pdata_hash, IDX_RESTRICTION,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		if (!php_to_restriction(ppvalue_entry[0],
			&((RESTRICTION_SUBOBJ*)pres->pres)->res TSRMLS_CC)) {
			return 0;	
		}
		break;
	case RESTRICTION_TYPE_COMMENT:
		pres->pres = emalloc(sizeof(RESTRICTION_COMMENT));
		if (NULL == pres->pres) {
			return 0;
		}
		((RESTRICTION_COMMENT*)pres->pres)->pres =
						emalloc(sizeof(RESTRICTION));
		if (NULL == ((RESTRICTION_COMMENT*)pres->pres)->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_RESTRICTION,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		if (!php_to_restriction(ppvalue_entry[0],
			((RESTRICTION_COMMENT*)pres->pres)->pres TSRMLS_CC)) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_PROPVALS,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		if (!php_to_tpropval_array(
			ppvalue_entry[0], &tmp_propvals TSRMLS_CC)) {
			return 0;
		}
		((RESTRICTION_COMMENT*)pres->pres)->count = tmp_propvals.count;
		((RESTRICTION_COMMENT*)pres->pres)->ppropval = tmp_propvals.ppropval;
		break;
	case RESTRICTION_TYPE_CONTENT:
		pres->pres = emalloc(sizeof(RESTRICTION_CONTENT));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_CONTENT*)pres->pres)->proptag =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		if (zend_hash_index_find(pdata_hash, IDX_FUZZYLEVEL,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level =
							ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_VALUE,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		if (ppvalue_entry[0]->type == IS_ARRAY) {
			if (!php_to_tpropval_array(
				ppvalue_entry[0], &tmp_propvals TSRMLS_CC)) {
				return 0;
			}
			if (1 != tmp_propvals.count) {
				return 0;
			}
			((RESTRICTION_CONTENT*)pres->pres)->propval =
									*tmp_propvals.ppropval;
		} else {
			((RESTRICTION_CONTENT*)pres->pres)->propval.proptag =
				((RESTRICTION_CONTENT*)pres->pres)->proptag;
			((RESTRICTION_CONTENT*)pres->pres)->propval.pvalue =
				php_to_propval(ppvalue_entry,
				((RESTRICTION_CONTENT*)pres->pres)->proptag&0xFFFF);
			if (NULL == ((RESTRICTION_CONTENT*)pres->pres)->propval.pvalue) {
				return 0;
			}
		}
		break;
	case RESTRICTION_TYPE_PROPERTY:
		pres->pres = emalloc(sizeof(RESTRICTION_PROPERTY));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_PROPERTY*)pres->pres)->proptag =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		if (zend_hash_index_find(pdata_hash, IDX_RELOP,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_PROPERTY*)pres->pres)->relop =
						ppvalue_entry[0]->value.lval;
		
		if (zend_hash_index_find(pdata_hash, IDX_VALUE,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		if (ppvalue_entry[0]->type == IS_ARRAY) {
			if (!php_to_tpropval_array(
				ppvalue_entry[0], &tmp_propvals TSRMLS_CC)) {
				return 0;
			}
			if (1 != tmp_propvals.count) {
				return 0;
			}
			((RESTRICTION_PROPERTY*)pres->pres)->propval =
									*tmp_propvals.ppropval;
		} else {
			((RESTRICTION_PROPERTY*)pres->pres)->propval.proptag =
				((RESTRICTION_PROPERTY*)pres->pres)->proptag;
			((RESTRICTION_PROPERTY*)pres->pres)->propval.pvalue =
				php_to_propval(ppvalue_entry,
				((RESTRICTION_PROPERTY*)pres->pres)->proptag&0xFFFF);
			if (NULL == ((RESTRICTION_PROPERTY*)pres->pres)->propval.pvalue) {
				return 0;
			}
		}
		break;
	case RESTRICTION_TYPE_PROPCOMPARE:
		pres->pres = emalloc(sizeof(RESTRICTION_PROPCOMPARE));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_RELOP,
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_PROPCOMPARE*)pres->pres)->relop =
							ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG1,
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1 =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG2,
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2 =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		break;
	case RESTRICTION_TYPE_BITMASK:
		pres->pres = emalloc(sizeof(RESTRICTION_BITMASK));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_TYPE,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_BITMASK*)pres->pres)->bitmask_relop =
								ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_MASK,
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_BITMASK*)pres->pres)->mask =
						ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_BITMASK*)pres->pres)->proptag =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		break;
	case RESTRICTION_TYPE_SIZE:
		pres->pres = emalloc(sizeof(RESTRICTION_SIZE));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_SIZE,
				(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_SIZE*)pres->pres)->size =
					ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_RELOP,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_SIZE*)pres->pres)->relop =
					ppvalue_entry[0]->value.lval;
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_SIZE*)pres->pres)->proptag =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		break;
	case RESTRICTION_TYPE_EXIST:
		pres->pres = emalloc(sizeof(RESTRICTION_EXIST));
		if (NULL == pres->pres) {
			return 0;
		}
		if (zend_hash_index_find(pdata_hash, IDX_PROPTAG,
			(void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		((RESTRICTION_EXIST*)pres->pres)->proptag =
			phptag_to_proptag(ppvalue_entry[0]->value.lval);
		break;
	default:
		return 0;
	}
	return 1;
}

zend_bool restriction_to_php(const RESTRICTION *pres,
	zval **ppret TSRMLS_DC)
{
	int i;
	zval *pzret;
	char key[16];
	zval *pzrops;
	zval *pzentry;
	zval *pzarray;
	zval *pzrestriction;
	TPROPVAL_ARRAY tmp_propvals;
	
    MAKE_STD_ZVAL(pzret);
	array_init(pzret);
	switch (pres->rt) {
	case RESTRICTION_TYPE_AND:
	case RESTRICTION_TYPE_OR:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		for (i=0; i<((RESTRICTION_AND_OR*)pres->pres)->count; i++) {
			sprintf(key, "%i", i);
			if (!restriction_to_php(
				&((RESTRICTION_AND_OR*)pres->pres)->pres[i],
				&pzentry TSRMLS_CC)) {
				return 0;
			}
			add_assoc_zval(pzarray, key, pzentry);
		}
		break;
	case RESTRICTION_TYPE_NOT:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		if (!restriction_to_php(
			&((RESTRICTION_NOT*)pres->pres)->res,
			&pzentry TSRMLS_CC)) {
			return 0;	
		}
		add_assoc_zval(pzarray, "0", pzentry);
		break;
	case RESTRICTION_TYPE_CONTENT:
		tmp_propvals.count = 1;
		tmp_propvals.ppropval = &((RESTRICTION_CONTENT*)pres->pres)->propval;
		if (!tpropval_array_to_php(&tmp_propvals, &pzrops TSRMLS_CC)) {
			return 0;
		}
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_VALUE);
		add_assoc_zval(pzarray, key, pzrops);		
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_CONTENT*)pres->pres)->proptag));
		sprintf(key, "%i", IDX_FUZZYLEVEL);
		add_assoc_long(pzarray, key,
			((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level);
		break;
	case RESTRICTION_TYPE_PROPERTY:
		tmp_propvals.count = 1;
		tmp_propvals.ppropval = &((RESTRICTION_CONTENT*)pres->pres)->propval;
		if (!tpropval_array_to_php(&tmp_propvals, &pzrops TSRMLS_CC)) {
			return 0;
		}
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_VALUE);
		add_assoc_zval(pzarray, key, pzrops);
		sprintf(key, "%i", IDX_RELOP);
		add_assoc_long(pzarray, key,
			((RESTRICTION_PROPERTY*)pres->pres)->relop);
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_PROPERTY*)pres->pres)->proptag));
		break;
	case RESTRICTION_TYPE_PROPCOMPARE:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_RELOP);
		add_assoc_long(pzarray, key,
			((RESTRICTION_PROPCOMPARE*)pres->pres)->relop);
		sprintf(key, "%i", IDX_PROPTAG1);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1));
		sprintf(key, "%i", IDX_PROPTAG2);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2));
		break;
	case RESTRICTION_TYPE_BITMASK:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_TYPE);
		add_assoc_long(pzarray, key,
			((RESTRICTION_BITMASK*)pres->pres)->bitmask_relop);
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_BITMASK*)pres->pres)->proptag));
		sprintf(key, "%i", IDX_MASK);
		add_assoc_long(pzarray, key,
			((RESTRICTION_BITMASK*)pres->pres)->mask);
		break;
	case RESTRICTION_TYPE_SIZE:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_RELOP);
		add_assoc_long(pzarray, key,
			((RESTRICTION_SIZE*)pres->pres)->relop);
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_SIZE*)pres->pres)->proptag));
		sprintf(key, "%i", IDX_SIZE);
		add_assoc_long(pzarray, key,
			((RESTRICTION_SIZE*)pres->pres)->size);
		break;
	case RESTRICTION_TYPE_EXIST:
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_EXIST*)pres->pres)->proptag));
		break;
	case RESTRICTION_TYPE_SUBOBJ:
		if (!restriction_to_php(
			&((RESTRICTION_SUBOBJ*)pres->pres)->res,
			&pzrestriction TSRMLS_CC)) {
			return 0;	
		}
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_PROPTAG);
		add_assoc_long(pzarray, key, proptag_to_phptag(
			((RESTRICTION_SUBOBJ*)pres->pres)->subobject));
		sprintf(key, "%i", IDX_RESTRICTION);
		add_assoc_zval(pzarray, key, pzrestriction);
		break;
	case RESTRICTION_TYPE_COMMENT:
		tmp_propvals.count = ((RESTRICTION_COMMENT*)pres->pres)->count;
		tmp_propvals.ppropval = ((RESTRICTION_COMMENT*)pres->pres)->ppropval;
		if (!tpropval_array_to_php(&tmp_propvals, &pzrops TSRMLS_CC)) {
			return 0;
		}
		if (!restriction_to_php(((RESTRICTION_COMMENT*)
			pres->pres)->pres, &pzrestriction TSRMLS_CC)) {
			return 0;	
		}
		MAKE_STD_ZVAL(pzarray);
		array_init(pzarray);
		sprintf(key, "%i", IDX_PROPVALS);
		add_assoc_zval(pzarray, key, pzrops);
		sprintf(key, "%i", IDX_RESTRICTION);
		add_assoc_zval(pzarray, key, pzrestriction);
		break;
	default:
		return 0;
	}
	add_assoc_long(pzret, "0", pres->rt);
	add_assoc_zval(pzret, "1", pzarray);
	*ppret = pzret;
	return 1;
}

zend_bool proptag_array_to_php(const PROPTAG_ARRAY *pproptags,
	zval **ppret TSRMLS_DC)
{
	int i;
	zval *pzret;
	
	MAKE_STD_ZVAL(pzret);
	array_init(pzret);
	for (i=0; i<pproptags->count; i++) {
		add_next_index_long(pzret,
			proptag_to_phptag(pproptags->pproptag[i]));
	}
	*ppret = pzret;
	return 1;
}

zend_bool tpropval_array_to_php(const TPROPVAL_ARRAY *ppropvals,
	zval **ppret TSRMLS_DC)
{
	int i, j, k;
	zval *pzret;
	char key[16];
	zval *pzmval;
	zval *pzalist;
	zval *pzactval;
	zval *pzpropval;
	zval *pzactarray;
	RULE_ACTIONS *prule;
	char proptag_string[16];
	TAGGED_PROPVAL *ppropval;
	TPROPVAL_ARRAY tmp_propvals;
	
	MAKE_STD_ZVAL(pzret);
	array_init(pzret);
	for (i=0; i<ppropvals->count; i++) {
		ppropval = &ppropvals->ppropval[i];
		/*
		* PHP wants a string as array key. PHP will transform this to zval integer when possible.
		* Because MAPI works with ULONGS, some properties (namedproperties) are bigger than LONG_MAX
		* and they will be stored as a zval string.
		* To prevent this we cast the ULONG to a signed long. The number will look a bit weird but it
		* will work.
		*/
		sprintf(proptag_string, "%u", proptag_to_phptag(ppropval->proptag));
		switch (ppropval->proptag & 0xFFFF) {
		case PROPVAL_TYPE_LONG:
		case PROPVAL_TYPE_ERROR:
			add_assoc_long(pzret, proptag_string, *(uint32_t*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_SHORT:
			add_assoc_long(pzret, proptag_string, *(uint16_t*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_DOUBLE:
		case PROPVAL_TYPE_FLOATINGTIME:
			add_assoc_double(pzret, proptag_string, *(double*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_LONGLONG:
 			add_assoc_double(pzret, proptag_string, *(uint64_t*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_FLOAT:
			add_assoc_double(pzret, proptag_string, *(float*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_BYTE:
			add_assoc_bool(pzret, proptag_string, *(uint8_t*)ppropval->pvalue);
			break;
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
			add_assoc_string(pzret, proptag_string, ppropval->pvalue, 1);
			break;
		case PROPVAL_TYPE_BINARY:
			add_assoc_stringl(pzret, proptag_string,
				((BINARY*)ppropval->pvalue)->pb,
				((BINARY*)ppropval->pvalue)->cb, 1);
			break;
		case PROPVAL_TYPE_FILETIME:
			add_assoc_long(pzret, proptag_string,
				nttime_to_unix(*(uint64_t*)ppropval->pvalue));
			break;
		case PROPVAL_TYPE_GUID:
			add_assoc_stringl(pzret, proptag_string,
				ppropval->pvalue, sizeof(GUID), 1);
			break;
		case PROPVAL_TYPE_SHORT_ARRAY:
			MAKE_STD_ZVAL(pzmval);
			array_init(pzmval);
			for (j=0; j<((SHORT_ARRAY*)ppropval->pvalue)->count; j++) {
				sprintf(key, "%i", j);
				add_assoc_long(pzmval, key,
					((SHORT_ARRAY*)ppropval->pvalue)->ps[j]);
			}
			add_assoc_zval(pzret, proptag_string, pzmval);
			break;
		case PROPVAL_TYPE_LONG_ARRAY:
			MAKE_STD_ZVAL(pzmval);
			array_init(pzmval);
			for (j=0; j<((LONG_ARRAY*)ppropval->pvalue)->count; j++) {
				sprintf(key, "%i", j);
				add_assoc_long(pzmval, key,
					((LONG_ARRAY*)ppropval->pvalue)->pl[j]);
			}
			add_assoc_zval(pzret, proptag_string, pzmval);
			break;
		case PROPVAL_TYPE_BINARY_ARRAY:
			MAKE_STD_ZVAL(pzmval);
			array_init(pzmval);
			for (j=0; j<((BINARY_ARRAY*)ppropval->pvalue)->count; j++) {
				sprintf(key, "%i", j);
				add_assoc_stringl(pzmval, key,
					((BINARY_ARRAY*)ppropval->pvalue)->pbin[j].pb,
					((BINARY_ARRAY*)ppropval->pvalue)->pbin[j].cb, 1);
			}
			add_assoc_zval(pzret, proptag_string, pzmval);
			break;
		case PROPVAL_TYPE_STRING_ARRAY:
		case PROPVAL_TYPE_WSTRING_ARRAY:
			MAKE_STD_ZVAL(pzmval);
			array_init(pzmval);
			for (j=0; j<((STRING_ARRAY*)ppropval->pvalue)->count; j++) {
				sprintf(key, "%i", j);
				add_assoc_string(pzmval, key,
					((STRING_ARRAY*)ppropval->pvalue)->ppstr[j], 1);
			}
			add_assoc_zval(pzret, proptag_string, pzmval);
			break;
		case PROPVAL_TYPE_GUID_ARRAY:
			MAKE_STD_ZVAL(pzmval);
			array_init(pzmval);
			for (j=0; j<((GUID_ARRAY*)ppropval->pvalue)->count; j++) {
				sprintf(key, "%i", j);
				add_assoc_stringl(pzmval, key,
					(char*)&((GUID_ARRAY*)ppropval->pvalue)->pguid[j],
					sizeof(GUID), 1);
			}
			add_assoc_zval(pzret, proptag_string, pzmval);
			break;
		case PROPVAL_TYPE_RULE:
			prule = (RULE_ACTIONS*)ppropval->pvalue;
			MAKE_STD_ZVAL(pzactarray);
			array_init(pzactarray);
			for (j=0; j<prule->count; j++) {
				MAKE_STD_ZVAL(pzactval);
				array_init(pzactval);
				add_assoc_long(pzactval, "action", prule->pblock[j].type);
				add_assoc_long(pzactval, "flags", prule->pblock[j].flags);
				add_assoc_long(pzactval, "flavor", prule->pblock[j].flavor);
				switch (prule->pblock[j].type) {
				case ACTION_TYPE_OP_MOVE:
				case ACTION_TYPE_OP_COPY:
					add_assoc_stringl(pzactval, "storeentryid",
						((MOVECOPY_ACTION*)
						prule->pblock[j].pdata)->store_eid.pb,
						((MOVECOPY_ACTION*)
						prule->pblock[j].pdata)->store_eid.cb, 1);
					add_assoc_stringl(pzactval, "folderentryid",
						((MOVECOPY_ACTION*)
						prule->pblock[j].pdata)->folder_eid.pb,
						((MOVECOPY_ACTION*)
						prule->pblock[j].pdata)->folder_eid.cb, 1);
					break;
				case ACTION_TYPE_OP_REPLY:
				case ACTION_TYPE_OP_OOF_REPLY:
					add_assoc_stringl(pzactval, "replyentryid",
						((REPLY_ACTION*)
						prule->pblock[j].pdata)->message_eid.pb,
						((REPLY_ACTION*)
						prule->pblock[j].pdata)->message_eid.cb, 1);
					add_assoc_stringl(
						pzactval, "replyguid",
						(char*)&((REPLY_ACTION*)
						prule->pblock[j].pdata)->template_guid,
						sizeof(GUID), 1);
					break;
				case ACTION_TYPE_OP_DEFER_ACTION:
					add_assoc_stringl(pzactval, "dam",
						prule->pblock[j].pdata, prule->pblock[j].length
						- sizeof(uint8_t) - 2*sizeof(uint32_t), 1);
					break;
				case ACTION_TYPE_OP_BOUNCE:
					add_assoc_long(pzactval, "code",
						*(uint32_t*)prule->pblock[j].pdata);
					break;
				case ACTION_TYPE_OP_FORWARD:
				case ACTION_TYPE_OP_DELEGATE:
					MAKE_STD_ZVAL(pzalist);
					array_init(pzalist);
					for (k=0; k<((FORWARDDELEGATE_ACTION*)
						prule->pblock[j].pdata)->count; k++) {
						tmp_propvals.count = ((FORWARDDELEGATE_ACTION*)
								prule->pblock[j].pdata)->pblock[k].count;
						tmp_propvals.ppropval = ((FORWARDDELEGATE_ACTION*)
								prule->pblock[j].pdata)->pblock[k].ppropval;
						if (!tpropval_array_to_php(&tmp_propvals,
							&pzpropval TSRMLS_CC)) {
							return 0;
						}
						zend_hash_next_index_insert(HASH_OF(pzalist),
									&pzpropval, sizeof(zval*), NULL);
					}
					add_assoc_zval(pzactval, "adrlist", pzalist);
					break;
				case ACTION_TYPE_OP_TAG:
					tmp_propvals.count = 1;
					tmp_propvals.ppropval = prule->pblock[j].pdata;
					if (!tpropval_array_to_php(&tmp_propvals,
						&pzalist TSRMLS_CC)) {
						return 0;
					}
					add_assoc_zval(pzactval, "proptag", pzalist);
					break;
				case ACTION_TYPE_OP_DELETE:
				case ACTION_TYPE_OP_MARK_AS_READ:
					break;
				default:
					return 0;
				};
				sprintf(key, "%i", j);
				add_assoc_zval(pzactarray, key, pzactval);
			}
			add_assoc_zval(pzret, proptag_string, pzactarray);
			break;
		case PROPVAL_TYPE_RESTRICTION:
			if (!restriction_to_php(ppropval->pvalue,
				&pzactval TSRMLS_CC)) {
				return 0;
			}
			add_assoc_zval(pzret, proptag_string, pzactval);
			break;
		}
	}
	*ppret = pzret;
	return 1;
}

zend_bool tarray_set_to_php(const TARRAY_SET *pset,
	zval **ppret TSRMLS_DC)
{
	int i;
	zval *pret;
	zval *pzpropval;
	
	MAKE_STD_ZVAL(pret);
	array_init(pret);
	for (i=0; i<pset->count; i++) {
		tpropval_array_to_php(pset->pparray[i],
						&pzpropval TSRMLS_CC);
		zend_hash_next_index_insert(HASH_OF(pret),
				&pzpropval, sizeof(zval*), NULL);
	}
	*ppret = pret;
	return 1;
}

zend_bool state_array_to_php(const STATE_ARRAY *pstates,
	zval **ppret TSRMLS_DC)
{
	int i;
	zval *pzval;
	zval *pzret;
	
	MAKE_STD_ZVAL(pzret);
	array_init(pzret);
	for (i=0; i<pstates->count; i++) {
		MAKE_STD_ZVAL(pzval);
		array_init(pzval);
		add_assoc_stringl(pzval, "sourcekey",
			pstates->pstate[i].source_key.pb,
			pstates->pstate[i].source_key.cb, 1);
		add_assoc_long(pzval, "flags",
			pstates->pstate[i].message_flags);
		add_next_index_zval(pzret, pzval);
	}
	*ppret = pzret;
	return 1;
}

zend_bool php_to_state_array(zval *pzval,
	STATE_ARRAY *pstates TSRMLS_DC)
{
	int i; 
	zval *pentry;
	zval **ppentry;
	zval **ppvalue_entry;
	HashTable *ptarget_hash;
	
	if (NULL == pzval) {
		return 0;
	}
	ptarget_hash = HASH_OF(pzval);
	if (NULL == ptarget_hash) {
		return 0;
	}
	pstates->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	if (0 == pstates->count) {
		pstates->pstate = NULL;
		return 1;
	}
	pstates->pstate = emalloc(sizeof(MESSAGE_STATE)*pstates->count);
	if (NULL == pstates->pstate) {
		return 0;
	}
	zend_hash_internal_pointer_reset(ptarget_hash);
	for (i=0; i<pstates->count; i++) {
		zend_hash_get_current_data(ptarget_hash, (void**)&ppentry);
		pentry = *ppentry;
		if (zend_hash_find(HASH_OF(pentry),
			"sourcekey", sizeof("sourcekey"),
			(void **)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_string_ex(ppvalue_entry);
		pstates->pstate[i].source_key.cb =
			ppvalue_entry[0]->value.str.len;
		pstates->pstate[i].source_key.pb =
			emalloc(ppvalue_entry[0]->value.str.len);
		if (NULL == pstates->pstate[i].source_key.pb) {
			return 0;
		}
		memcpy(pstates->pstate[i].source_key.pb,
			ppvalue_entry[0]->value.str.val,
			ppvalue_entry[0]->value.str.len);
		if (zend_hash_find(HASH_OF(pentry), "flags",
			sizeof("flags"), (void**)&ppvalue_entry) == FAILURE) {
			return 0;
		}
		convert_to_long_ex(ppvalue_entry);
		pstates->pstate[i].message_flags = ppvalue_entry[0]->value.lval;
	}
	return 1;
}

zend_bool znotification_array_to_php(
	ZNOTIFICATION_ARRAY *pnotifications, zval **ppret TSRMLS_DC)
{
	int i;
	zval *pzret;
	zval *pzvalprops;
	zval *pzvalnotif;
	NEWMAIL_ZNOTIFICATION *pnew_notification;
	OBJECT_ZNOTIFICATION *pobject_notification;
	
	MAKE_STD_ZVAL(pzret);
	array_init(pzret);
	for (i=0; i<pnotifications->count; i++) {
		MAKE_STD_ZVAL(pzvalnotif);
		array_init(pzvalnotif);
		add_assoc_long(pzvalnotif, "eventtype",
			pnotifications->ppnotification[i]->event_type);
		switch(pnotifications->ppnotification[i]->event_type) {
		case EVENT_TYPE_NEWMAIL:
			pnew_notification =
				pnotifications->ppnotification[i]->pnotification_data;
			add_assoc_stringl(pzvalnotif, "entryid",
				pnew_notification->entryid.pb,
				pnew_notification->entryid.cb, 1);
			add_assoc_stringl(pzvalnotif, "parentid",
				pnew_notification->parentid.pb,
				pnew_notification->parentid.cb, 1);
			add_assoc_long(pzvalnotif, "flags",
				pnew_notification->flags);
			add_assoc_string(pzvalnotif, "messageclass",
				pnew_notification->message_class, 1);
			add_assoc_long(pzvalnotif, "messageflags",
				pnew_notification->message_flags);
			break;
		case EVENT_TYPE_OBJECTCREATED:
		case EVENT_TYPE_OBJECTDELETED:
		case EVENT_TYPE_OBJECTMODIFIED:
		case EVENT_TYPE_OBJECTMOVED:
		case EVENT_TYPE_OBJECTCOPIED:
		case EVENT_TYPE_SEARCHCOMPLETE:
			pobject_notification =
				pnotifications->ppnotification[i]->pnotification_data;
			if (NULL != pobject_notification->pentryid) {
				add_assoc_stringl(pzvalnotif, "entryid",
					pobject_notification->pentryid->pb,
					pobject_notification->pentryid->cb, 1);
			}
			add_assoc_long(pzvalnotif, "objtype",
				pobject_notification->object_type);
			if (NULL != pobject_notification->pparentid) {
				add_assoc_stringl(pzvalnotif, "parentid", 
				pobject_notification->pparentid->pb,
				pobject_notification->pparentid->cb, 1);
			}
			if (NULL != pobject_notification->pold_entryid) {
				add_assoc_stringl(pzvalnotif, "oldid",
				pobject_notification->pold_entryid->pb,
				pobject_notification->pold_entryid->cb, 1);
			}
			if (NULL != pobject_notification->pold_parentid) {
				add_assoc_stringl(pzvalnotif, "oldparentid", 
				pobject_notification->pold_parentid->pb,
				pobject_notification->pold_parentid->cb, 1);
			}
			if (NULL != pobject_notification->pproptags) {
				if (!proptag_array_to_php(
					pobject_notification->pproptags,
					&pzvalprops TSRMLS_CC)) {
					return 0;
				}
				add_assoc_zval(pzvalnotif, "proptagarray", pzvalprops);
			}
			break;
		default:
			continue;
		}
		add_next_index_zval(pzret, pzvalnotif);
	}
	*ppret = pzret;
	return 1;
}

zend_bool php_to_propname_array(zval *pzval_names,
	zval *pzval_guids, PROPNAME_ARRAY *ppropnames TSRMLS_DC)
{
	int i;
	zval **ppentry;
	zval **ppguidentry;
	HashTable *pguidhash;
	HashTable *pnameshash;
	static GUID guid_appointment = {0x00062002, 0x0000, 0x0000,
			{0xC0, 0x00}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
	
	pnameshash = Z_ARRVAL_P(pzval_names);
	if (NULL != pzval_guids) {
		pguidhash = Z_ARRVAL_P(pzval_guids);
	} else {
		pguidhash = NULL;
	}
	ppropnames->count = zend_hash_num_elements(pnameshash);
	if (NULL != pguidhash && ppropnames->count !=
		zend_hash_num_elements(pguidhash)) {
		return 0;
	}
	if (0 == ppropnames->count) {
		ppropnames->ppropname = NULL;
		return 1;
	}
	ppropnames->ppropname = emalloc(sizeof(PROPERTY_NAME)*ppropnames->count);
	if (NULL == ppropnames->ppropname) {
		return 0;
	}
	zend_hash_internal_pointer_reset(pnameshash);
	if (NULL != pguidhash) {
		zend_hash_internal_pointer_reset(pguidhash);
	}
	for (i=0; i<ppropnames->count; i++) {
		zend_hash_get_current_data(pnameshash,(void**)&ppentry);
		if (NULL != pguidhash) {
			zend_hash_get_current_data(pguidhash, (void**)&ppguidentry);
		}
		ppropnames->ppropname[i].guid = guid_appointment;
		if (NULL != pguidhash) {
			if (sizeof(GUID) == ppguidentry[0]->value.str.len) {
				memcpy(&ppropnames->ppropname[i].guid,
					ppguidentry[0]->value.str.val, sizeof(GUID));
			}
		}
		switch(ppentry[0]->type) {
		case IS_LONG:
			ppropnames->ppropname[i].kind = KIND_LID;
			ppropnames->ppropname[i].plid = emalloc(sizeof(uint32_t));
			if (NULL == ppropnames->ppropname[i].plid) {
				return 0;
			}
			*ppropnames->ppropname[i].plid = ppentry[0]->value.lval;
			ppropnames->ppropname[i].pname = NULL;
			break;
		case IS_STRING:
			ppropnames->ppropname[i].kind = KIND_NAME;
			ppropnames->ppropname[i].plid = NULL;
			ppropnames->ppropname[i].pname =
				estrdup(ppentry[0]->value.str.val);
			if (NULL == ppropnames->ppropname[i].pname) {
				return 0;
			}
			break;
		case IS_DOUBLE:
			ppropnames->ppropname[i].kind = KIND_LID;
			ppropnames->ppropname[i].plid = emalloc(sizeof(uint32_t));
			if (NULL == ppropnames->ppropname[i].plid) {
				return 0;
			}
			*ppropnames->ppropname[i].plid =
				(uint32_t)ppentry[0]->value.dval;
			ppropnames->ppropname[i].pname = NULL;
			break;
		default:
			return 0;
		}
		zend_hash_move_forward(pnameshash);
		if(NULL != pguidhash) {
			zend_hash_move_forward(pguidhash);
		}
	}
	return 1;
}

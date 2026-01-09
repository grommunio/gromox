// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <fmt/core.h>
#include <libHX/defs.h>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/rop_util.hpp>
#include <gromox/zcore_types.hpp>
#include "type_conversion.hpp"
#include "ext.hpp"

using namespace gromox;

/* In PHP-MAPI, PT_STRING8 means UTF-8
 * string. We do not use PT_UNICODE,
	there's no definition for ansi string */
proptag_t proptag_to_phptag(proptag_t proptag)
{
	switch (PROP_TYPE(proptag)) {
	case PT_UNICODE:
		return CHANGE_PROP_TYPE(proptag, PT_STRING8);
	case PT_MV_UNICODE:
		return CHANGE_PROP_TYPE(proptag, PT_MV_STRING8);
	default:
		return proptag;
	}
}

proptag_t phptag_to_proptag(proptag_t proptag)
{
	switch (PROP_TYPE(proptag)) {
	case PT_STRING8:
		return CHANGE_PROP_TYPE(proptag, PT_UNICODE);
	case PT_MV_STRING8:
		return CHANGE_PROP_TYPE(proptag, PT_MV_UNICODE);
	default:
		return proptag;
	}
}

ec_error_t php_to_binary_array(zval *pzval, BINARY_ARRAY *pbins)
{
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	pbins->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	if (0 == pbins->count) {
		pbins->pbin = NULL;
		return ecSuccess;
	}
	pbins->pbin = sta_malloc<BINARY>(pbins->count);
	if (NULL == pbins->pbin) {
		pbins->count = 0;
		return ecMAPIOOM;
	}

	size_t i = 0;
	zval *entry;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, entry) {
		zstrplus str(zval_get_string(entry));
		pbins->pbin[i].cb = str->len;
		if (str->len == 0) {
			pbins->pbin[i].pb = NULL;
		} else {
			pbins->pbin[i].pb = sta_malloc<uint8_t>(pbins->pbin[i].cb);
			if (NULL == pbins->pbin[i].pb) {
				pbins->pbin[i].cb = 0;
				return ecMAPIOOM;
			}
			memcpy(pbins->pbin[i].pb, str->val, str->len);
		}
		++i;
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t binary_array_to_php(const BINARY_ARRAY &pbins, zval *pzval)
{
	zarray_init(pzval);
	for (const auto &bin : pbins)
		add_next_index_stringl(pzval, bin.pc, bin.cb);
	return ecSuccess;
}

ec_error_t fb_array_to_php(const std::vector<freebusy_event> &fbs, zval *pzval)
{
	zval pzvalfbevent;
	zarray_init(pzval);
	for (const auto &e : fbs) {
		zarray_init(&pzvalfbevent);
		add_assoc_long(&pzvalfbevent, "start", e.start_time);
		add_assoc_long(&pzvalfbevent, "end", e.end_time);
		add_assoc_long(&pzvalfbevent, "busystatus", e.busy_status);
		if (!e.has_details) {
			add_next_index_zval(pzval, &pzvalfbevent);
			continue;
		}
		if (e.id != nullptr)
			add_assoc_string(&pzvalfbevent, "id", e.id);
		if (e.subject != nullptr)
			add_assoc_string(&pzvalfbevent, "subject", e.subject);
		if (e.location != nullptr)
			add_assoc_string(&pzvalfbevent, "location", e.location);
		add_assoc_bool(&pzvalfbevent, "meeting", e.is_meeting);
		add_assoc_bool(&pzvalfbevent, "recurring", e.is_recurring);
		add_assoc_bool(&pzvalfbevent, "exception", e.is_exception);
		add_assoc_bool(&pzvalfbevent, "reminderset", e.is_reminderset);
		add_assoc_bool(&pzvalfbevent, "private", e.is_private);
		add_next_index_zval(pzval, &pzvalfbevent);
	}
	return ecSuccess;
}

ec_error_t php_to_sortorder_set(zval *pzval, SORTORDER_SET *pset)
{
	unsigned long idx;
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	pset->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	pset->ccategories = 0;
	pset->cexpanded = 0;
	if (0 == pset->count) {
		pset->psort = NULL;
		return ecSuccess;
	}
	pset->psort = sta_malloc<SORT_ORDER>(pset->count);
	if (NULL == pset->psort) {
		pset->count = 0;
		return ecMAPIOOM;
	}

	zend_string *key;
	zval *entry;
	size_t i = 0;
	ZEND_HASH_FOREACH_KEY_VAL(ptarget_hash, idx, key, entry) {
		auto proptag = phptag_to_proptag(key != nullptr ? strtol(key->val, nullptr, 0) : idx);
		pset->psort[i].propid = PROP_ID(proptag);
		pset->psort[i].type = PROP_TYPE(proptag);
		pset->psort[i].table_sort = zval_get_long(entry);
		++i;
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t php_to_proptag_array(zval *pzval, PROPTAG_ARRAY *pproptags)
{
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	pproptags->count = zend_hash_num_elements(ptarget_hash);
	if (0 == pproptags->count) {
		pproptags->pproptag = NULL;
		return ecSuccess;
	}
	pproptags->pproptag = sta_malloc<uint32_t>(pproptags->count);
	if (pproptags->pproptag == nullptr) {
		pproptags->count = 0;
		return ecMAPIOOM;
	}
	size_t i = 0;
	zval *entry;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, entry) {
		pproptags->pproptag[i++] = phptag_to_proptag(zval_get_long(entry));
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t php_to_proptag_array(zval *pzval, std::vector<proptag_t> &tags) try
{
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	auto ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	tags.clear();
	zval *entry;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, entry) {
		tags.emplace_back(phptag_to_proptag(zval_get_long(entry)));
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecServerOOM;
}

ec_error_t php_to_proptag_array(zval *zv, std::optional<std::vector<proptag_t>> &tags)
{
	tags.emplace();
	return php_to_proptag_array(zv, *tags);
}

static void *php_to_propval(zval *entry, proptype_t proptype)
{
	int j = 0;
	void *pvalue;
	char *pstring;
	zval *data_entry;
	ACTION_BLOCK *pblock;
	HashTable *pdata_hash;
	HashTable *paction_hash;
	HashTable *precipient_hash;
	TPROPVAL_ARRAY tmp_propvals;
	RECIPIENT_BLOCK *prcpt_block;
	zstrplus str_action(zend_string_init("action", sizeof("action") - 1, 0));
	zstrplus str_flags(zend_string_init("flags", sizeof("flags") - 1, 0));
	zstrplus str_flavor(zend_string_init("flavor", sizeof("flavor") - 1, 0));
	zstrplus str_storeentryid(zend_string_init("storeentryid", sizeof("storeentryid") - 1, 0));
	zstrplus str_folderentryid(zend_string_init("folderentryid", sizeof("folderentryid") - 1, 0));
	zstrplus str_replyentryid(zend_string_init("replyentryid", sizeof("replyentryid") - 1, 0));
	zstrplus str_replyguid(zend_string_init("replyguid", sizeof("replyguid") - 1, 0));
	zstrplus str_dam(zend_string_init("dam", sizeof("dam") - 1, 0));
	zstrplus str_code(zend_string_init("code", sizeof("code") - 1, 0));
	zstrplus str_adrlist(zend_string_init("adrlist", sizeof("adrlist") - 1, 0));
	zstrplus str_proptag(zend_string_init("proptag", sizeof("proptag") - 1, 0));
	
	if (entry == nullptr)
		return nullptr;
	switch(proptype)	{
	case PT_SHORT:
		pvalue = emalloc(sizeof(uint16_t));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<uint16_t *>(pvalue) = zval_get_long(entry);
		break;
	case PT_LONG:
	case PT_ERROR:
		pvalue = emalloc(sizeof(uint32_t));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<uint32_t *>(pvalue) = zval_get_long(entry);
		break;
	case PT_FLOAT:
		pvalue = emalloc(sizeof(float));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<float *>(pvalue) = zval_get_double(entry);
		break;
	case PT_DOUBLE:
	case PT_APPTIME:
		pvalue = emalloc(sizeof(double));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<double *>(pvalue) = zval_get_double(entry);
		break;
	case PT_CURRENCY:
	case PT_I8:
		pvalue = emalloc(sizeof(uint64_t));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<uint64_t *>(pvalue) = zval_get_double(entry);
		break;
	case PT_BOOLEAN:
		pvalue = emalloc(sizeof(uint8_t));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<uint8_t *>(pvalue) = zval_is_true(entry);
		break;
	case PT_SYSTIME:
		/* convert unix timestamp to nt timestamp */
		pvalue = emalloc(sizeof(uint64_t));
		if (pvalue == nullptr)
			return NULL;
		*static_cast<uint64_t *>(pvalue) = rop_util_unix_to_nttime(zval_get_long(entry));
		break;
	case PT_BINARY: {
		zstrplus str(zval_get_string(entry));
		pvalue = emalloc(sizeof(BINARY));
		auto bin = static_cast<BINARY *>(pvalue);
		if (bin == nullptr)
			return NULL;
		bin->cb = str->len;
		if (str->len == 0) {
			bin->pb = nullptr;
		} else {
			bin->pb = sta_malloc<uint8_t>(str->len);
			if (bin->pb == nullptr) {
				bin->cb = 0;
				return NULL;
			}
			memcpy(bin->pb, str->val, str->len);
		}
		break;
	}
	case PT_STRING8:
	case PT_UNICODE: {
		zstrplus str(zval_get_string(entry));
		pvalue = emalloc(str->len + 1);
		if (pvalue == nullptr)
			return NULL;
		memcpy(pvalue, str->val, str->len);
		static_cast<char *>(pvalue)[str->len] = '\0';
		break;
	}
	case PT_CLSID: {
		zstrplus str(zval_get_string(entry));
		if (str->len != sizeof(GUID))
			return NULL;
		pvalue = emalloc(sizeof(GUID));
		if (pvalue == nullptr)
			return NULL;
		memcpy(pvalue, str->val, sizeof(GUID));
		break;
	}
	case PT_MV_SHORT: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(SHORT_ARRAY));
		auto xs = static_cast<SHORT_ARRAY *>(pvalue);
		if (xs == nullptr)
			return NULL;
		xs->count = zend_hash_num_elements(pdata_hash);
		if (xs->count == 0) {
			xs->ps = nullptr;
			break;
		}
		xs->ps = sta_malloc<uint16_t>(xs->count);
		if (xs->ps == nullptr) {
			xs->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xs->ps[j++] = zval_get_long(data_entry);
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_LONG: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(LONG_ARRAY));
		auto xl = static_cast<LONG_ARRAY *>(pvalue);
		if (xl == nullptr)
			return NULL;
		xl->count = zend_hash_num_elements(pdata_hash);
		if (xl->count == 0) {
			xl->pl = nullptr;
			break;
		}
		xl->pl = sta_malloc<uint32_t>(xl->count);
		if (xl->pl == nullptr) {
			xl->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xl->pl[j++] = zval_get_long(data_entry);
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_CURRENCY:
	case PT_MV_I8: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(LONGLONG_ARRAY));
		auto xl = static_cast<LONGLONG_ARRAY *>(pvalue);
		if (xl == nullptr)
			return NULL;
		xl->count = zend_hash_num_elements(pdata_hash);
		if (xl->count == 0) {
			xl->pll = nullptr;
			break;
		}
		xl->pll = sta_malloc<uint64_t>(xl->count);
		if (xl->pll == nullptr) {
			xl->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xl->pll[j++] = zval_get_double(data_entry);
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_FLOAT: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(FLOAT_ARRAY));
		auto xl = static_cast<FLOAT_ARRAY *>(pvalue);
		if (xl == nullptr)
			return NULL;
		xl->count = zend_hash_num_elements(pdata_hash);
		if (xl->count == 0) {
			xl->mval = nullptr;
			break;
		}
		xl->mval = sta_malloc<float>(xl->count);
		if (xl->mval == nullptr) {
			xl->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xl->mval[j++] = zval_get_double(data_entry);
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(DOUBLE_ARRAY));
		auto xl = static_cast<DOUBLE_ARRAY *>(pvalue);
		if (xl == nullptr)
			return NULL;
		xl->count = zend_hash_num_elements(pdata_hash);
		if (xl->count == 0) {
			xl->mval = nullptr;
			break;
		}
		xl->mval = sta_malloc<double>(xl->count);
		if (xl->mval == nullptr) {
			xl->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xl->mval[j++] = zval_get_double(data_entry);
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(STRING_ARRAY));
		auto xs = static_cast<STRING_ARRAY *>(pvalue);
		if (xs == nullptr)
			return NULL;
		xs->count = zend_hash_num_elements(pdata_hash);
		if (xs->count == 0) {
			xs->ppstr = nullptr;
			break;
		}
		xs->ppstr = sta_malloc<char *>(xs->count);
		if (xs->ppstr == nullptr) {
			xs->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			zstrplus str(zval_get_string(data_entry));
			pstring = sta_malloc<char>(str->len + 1);
			if (pstring == nullptr)
				return NULL;
			xs->ppstr[j++] = pstring;
			memcpy(pstring, str->val, str->len);
			pstring[str->len] = '\0';
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_SYSTIME: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return nullptr;
		pvalue = emalloc(sizeof(LONGLONG_ARRAY));
		auto xl = static_cast<LONGLONG_ARRAY *>(pvalue);
		if (xl == nullptr)
			return nullptr;
		xl->count = zend_hash_num_elements(pdata_hash);
		if (xl->count == 0) {
			xl->pll = nullptr;
			break;
		}
		xl->pll = sta_malloc<uint64_t>(xl->count);
		if (xl->pll == nullptr) {
			xl->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			xl->pll[j++] = rop_util_unix_to_nttime(zval_get_long(data_entry));
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_BINARY: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(BINARY_ARRAY));
		auto xb = static_cast<BINARY_ARRAY *>(pvalue);
		if (xb == nullptr)
			return NULL;
		xb->count = zend_hash_num_elements(pdata_hash);
		if (xb->count == 0) {
			xb->pbin = nullptr;
			break;
		}
		xb->pbin = sta_malloc<BINARY>(xb->count);
		if (xb->pbin == nullptr) {
			xb->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			zstrplus str(zval_get_string(data_entry));
			xb->pbin[j].cb = str->len;
			if (str->len == 0) {
				xb->pbin[j].pb = NULL;
			} else {
				xb->pbin[j].pb = sta_malloc<uint8_t>(str->len);
				if (xb->pbin[j].pb == nullptr)
					return NULL;
				memcpy(xb->pbin[j].pb, str->val, str->len);
			}
			++j;
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_MV_CLSID: {
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (pdata_hash == nullptr)
			return NULL;
		pvalue = emalloc(sizeof(GUID_ARRAY));
		auto xb = static_cast<GUID_ARRAY *>(pvalue);
		if (xb == nullptr)
			return NULL;
		xb->count = zend_hash_num_elements(pdata_hash);
		if (xb->count == 0) {
			xb->pguid = nullptr;
			break;
		}
		xb->pguid = sta_malloc<GUID>(xb->count);
		if (xb->pguid == nullptr) {
			xb->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			zstrplus str(zval_get_string(data_entry));
			if (str->len != sizeof(GUID))
				return NULL;
			memcpy(&xb->pguid[j], Z_STRVAL_P(data_entry), sizeof(GUID));
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_ACTIONS: {
		pvalue = emalloc(sizeof(RULE_ACTIONS));
		auto xr = static_cast<RULE_ACTIONS *>(pvalue);
		if (xr == nullptr)
			return NULL;
		ZVAL_DEREF(entry);
		pdata_hash = HASH_OF(entry);
		if (NULL == pdata_hash) {
			xr->count = 0;
			xr->pblock = NULL;
			break;
		}
		xr->count = zend_hash_num_elements(pdata_hash);
		if (xr->count == 0) {
			xr->pblock = nullptr;
			break;
		}
		xr->pblock = sta_malloc<ACTION_BLOCK>(xr->count);
		if (xr->pblock == nullptr) {
			xr->count = 0;
			return NULL;
		}
		ZEND_HASH_FOREACH_VAL(pdata_hash, data_entry) {
			ZVAL_DEREF(data_entry);
			paction_hash = HASH_OF(data_entry);
			if (paction_hash == nullptr)
				return NULL;
			data_entry = zend_hash_find(paction_hash, str_action.get());
			if (data_entry == nullptr)
				return NULL;
			pblock = &xr->pblock[j];
			pblock->type = zval_get_long(data_entry);
			/* option field user defined flags, default 0 */
			data_entry = zend_hash_find(paction_hash, str_flags.get());
			pblock->flags = data_entry != nullptr ? zval_get_long(data_entry) : 0;
			/* option field used with OP_REPLAY and OP_FORWARD, default 0 */
			data_entry = zend_hash_find(paction_hash, str_flavor.get());
			pblock->flavor = data_entry != nullptr ? zval_get_long(data_entry) : 0;
			switch (pblock->type) {
			case OP_MOVE:
			case OP_COPY: {
				pblock->pdata = emalloc(sizeof(ZMOVECOPY_ACTION));
				auto xq = static_cast<ZMOVECOPY_ACTION *>(pblock->pdata);
				if (xq == nullptr)
					return NULL;

				data_entry = zend_hash_find(paction_hash, str_storeentryid.get());
				if (data_entry == nullptr)
					return NULL;
				zstrplus str1(zval_get_string(data_entry));
				xq->store_eid.cb = str1->len;
				xq->store_eid.pb = sta_malloc<uint8_t>(str1->len);
				if (xq->store_eid.pb == nullptr) {
					xq->store_eid.cb = 0;
					return NULL;
				}
				memcpy(xq->store_eid.pb, str1->val, str1->len);

				data_entry = zend_hash_find(paction_hash, str_folderentryid.get());
				if (data_entry == nullptr)
					return NULL;
				zstrplus str2(zval_get_string(data_entry));
				xq->folder_eid.cb = str2->len;
				xq->folder_eid.pb = sta_malloc<uint8_t>(str2->len);
				if (xq->folder_eid.pb == nullptr)
					return NULL;
				memcpy(xq->folder_eid.pb, str2->val, str2->len);
				break;
			}
			case OP_REPLY:
			case OP_OOF_REPLY: {
				data_entry = zend_hash_find(paction_hash, str_replyentryid.get());
				if (data_entry == nullptr)
					return NULL;
				zstrplus str1(zval_get_string(data_entry));
				pblock->pdata = emalloc(sizeof(ZREPLY_ACTION));
				auto xq = static_cast<ZREPLY_ACTION *>(pblock->pdata);
				if (xq == nullptr)
					return NULL;
				xq->message_eid.cb = str1->len;
				xq->message_eid.pb = sta_malloc<uint8_t>(str1->len);
				if (xq->message_eid.pb == nullptr) {
					xq->message_eid.cb = 0;
					return NULL;
				}
				memcpy(xq->message_eid.pb, str1->val, str1->len);

				data_entry = zend_hash_find(paction_hash, str_replyguid.get());
				if (data_entry != nullptr) {
					zstrplus str2(zval_get_string(data_entry));
					if (str2->len != sizeof(GUID))
						return NULL;
					memcpy(&xq->template_guid, str2->val, sizeof(GUID));
				} else {
					memset(&xq->template_guid, 0, sizeof(GUID));
				}
				break;
			}
			case OP_DEFER_ACTION: {
				data_entry = zend_hash_find(paction_hash, str_dam.get());
				if (data_entry == nullptr)
					return NULL;
				zstrplus str1(zval_get_string(data_entry));
				if (str1->len == 0)
					return NULL;
				pblock->length = str1->len + sizeof(uint8_t) + 2 * sizeof(uint32_t);
				pblock->pdata = emalloc(str1->len);
				if (pblock->pdata == nullptr)
					return NULL;
				memcpy(pblock->pdata, str1->val, str1->len);
				break;
			}
			case OP_BOUNCE:
				data_entry = zend_hash_find(paction_hash, str_code.get());
				if (data_entry == nullptr)
					return NULL;
				pblock->pdata = emalloc(sizeof(uint32_t));
				if (pblock->pdata == nullptr)
					return NULL;
				*static_cast<uint32_t *>(pblock->pdata) = zval_get_long(data_entry);
				break;
			case OP_FORWARD:
			case OP_DELEGATE: {
				data_entry = zend_hash_find(paction_hash, str_adrlist.get());
				if (data_entry == nullptr || Z_TYPE_P(data_entry) != IS_ARRAY)
					return NULL;
				pblock->pdata = emalloc(sizeof(FORWARDDELEGATE_ACTION));
				auto xq = static_cast<FORWARDDELEGATE_ACTION *>(pblock->pdata);
				if (xq == nullptr)
					return NULL;
				ZVAL_DEREF(data_entry);
				precipient_hash = HASH_OF(data_entry);
				xq->count = zend_hash_num_elements(precipient_hash);
				if (xq->count == 0)
					return NULL;
				xq->pblock = sta_malloc<RECIPIENT_BLOCK>(xq->count);
				if (xq->pblock == nullptr) {
					xq->count = 0;
					return NULL;
				}
				int k = 0;
				ZEND_HASH_FOREACH_VAL(precipient_hash, data_entry) {
					auto err = php_to_tpropval_array(data_entry, &tmp_propvals);
					if (err != ecSuccess)
						return NULL;
					prcpt_block = &xq->pblock[k];
					prcpt_block->reserved = 0;
					prcpt_block->count = tmp_propvals.count;
					prcpt_block->ppropval = tmp_propvals.ppropval;
					++k;
				} ZEND_HASH_FOREACH_END();
				break;
			}
			case OP_TAG: {
				data_entry = zend_hash_find(paction_hash, str_proptag.get());
				if (data_entry == nullptr)
					return NULL;
				auto err = php_to_tpropval_array(data_entry, &tmp_propvals);
				if (err != ecSuccess)
					return NULL;
				if (tmp_propvals.count != 1)
					return NULL;
				pblock->pdata = tmp_propvals.ppropval;
				break;
			}
			case OP_DELETE:
			case OP_MARK_AS_READ:
				pblock->pdata = NULL;
				break;
			default:
				return NULL;
			}
			++j;
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case PT_SRESTRICTION: {
		pvalue = emalloc(sizeof(RESTRICTION));
		if (pvalue == nullptr)
			return NULL;
		auto err = php_to_restriction(entry, static_cast<RESTRICTION *>(pvalue));
		if (err != ecSuccess)
			return NULL;
		break;
	}
	default:
		return NULL;
	}
	return pvalue;
}

ec_error_t php_to_tpropval_array(zval *pzval, TPROPVAL_ARRAY *ppropvals)
{
	zend_string *pstring;
	unsigned long idx;
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	ppropvals->count = zend_hash_num_elements(ptarget_hash);
	if (0 == ppropvals->count) {
	   ppropvals->ppropval = NULL;
		return ecSuccess;
	}
	ppropvals->ppropval = sta_malloc<TAGGED_PROPVAL>(ppropvals->count);
	if (NULL == ppropvals->ppropval) {
		ppropvals->count = 0;
		return ecMAPIOOM;
	}

	zval *entry;
	size_t i = 0;
	ZEND_HASH_FOREACH_KEY_VAL(ptarget_hash, idx, pstring, entry) {
		static_cast<void>(pstring);
		ppropvals->ppropval[i].proptag = phptag_to_proptag(idx);
		ppropvals->ppropval[i].pvalue = php_to_propval(entry, PROP_TYPE(idx));
		if (ppropvals->ppropval[i].pvalue == nullptr)
			return ecError;
		++i;
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t php_to_tarray_set(zval *pzval, TARRAY_SET *pset)
{
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	if (Z_TYPE_P(pzval) != IS_ARRAY)
		return ecInvalidParam;
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	pset->count = zend_hash_num_elements(ptarget_hash);
	if (0 == pset->count) {
		pset->pparray = NULL;
		return ecSuccess;
	}
	pset->pparray = sta_malloc<TPROPVAL_ARRAY *>(pset->count);
	if (NULL == pset->pparray) {
		pset->count = 0;
		return ecMAPIOOM;
	}

	zval *entry;
	size_t i = 0;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, entry) {
		if (Z_TYPE_P(entry) != IS_ARRAY)
			return ecInvalidParam;
		pset->pparray[i] = st_malloc<TPROPVAL_ARRAY>();
		if (pset->pparray[i] == nullptr)
			return ecMAPIOOM;
		auto err = php_to_tpropval_array(entry, pset->pparray[i]);
		if (err != ecSuccess)
			return err;
		++i;
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t php_to_rule_list(zval *pzval, RULE_LIST *plist)
{
	zstrplus str_properties(zend_string_init("properties", sizeof("properties") - 1, 0));
	zstrplus str_rowflags(zend_string_init("rowflags", sizeof("rowflags") - 1, 0));
	HashTable *ptarget_hash;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	if (Z_TYPE_P(pzval) != IS_ARRAY)
		return ecInvalidParam;
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	plist->count = zend_hash_num_elements(ptarget_hash);
	if (0 == plist->count) {
		plist->prule = NULL;
		return ecSuccess;
	}
	plist->prule = sta_malloc<RULE_DATA>(plist->count);
	if (NULL == plist->prule) {
		plist->count = 0;
		return ecMAPIOOM;
	}

	zval *entry;
	size_t i = 0;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, entry) {
		ZVAL_DEREF(entry);
		if (Z_TYPE_P(entry) != IS_ARRAY)
			return ecInvalidParam;
		auto data = zend_hash_find(HASH_OF(entry), str_properties.get());
		if (data == nullptr)
			return ecInvalidParam;
		auto err = php_to_tpropval_array(data, &plist->prule[i].propvals);
		if (err != ecSuccess)
			return err;
		data = zend_hash_find(HASH_OF(entry), str_rowflags.get());
		if (data == nullptr)
			return ecInvalidParam;
		plist->prule[i].flags = zval_get_long(data);
		++i;
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
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

ec_error_t php_to_restriction(zval *pzval, RESTRICTION *pres)
{
	int i;
	HashTable *pres_hash;
	HashTable *pdata_hash;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	pres_hash = HASH_OF(pzval);
	if (pres_hash == nullptr || zend_hash_num_elements(pres_hash) != 2)
		return ecInvalidParam;

	HashPosition hpos;
	zend_hash_internal_pointer_reset_ex(pres_hash, &hpos);
	/* 0=>type, 1=>value array */
	auto type_entry = zend_hash_get_current_data_ex(pres_hash, &hpos);
	zend_hash_move_forward_ex(pres_hash, &hpos);
	auto value_entry = zend_hash_get_current_data_ex(pres_hash, &hpos);
	pres->rt = static_cast<mapi_rtype>(zval_get_long(type_entry));
	ZVAL_DEREF(value_entry);
	pdata_hash = HASH_OF(value_entry);
	if (pdata_hash == nullptr)
		return ecInvalidParam;
	switch(pres->rt) {
	case RES_AND:
	case RES_OR: {
		pres->pres = emalloc(sizeof(RESTRICTION_AND_OR));
		auto andor = pres->andor;
		if (andor == nullptr)
			return ecMAPIOOM;
		andor->count = zend_hash_num_elements(pdata_hash);
		andor->pres = sta_malloc<RESTRICTION>(andor->count);
		if (andor->pres == nullptr) {
			andor->count = 0;
			return ecMAPIOOM;
		}
		i = 0;
		ZEND_HASH_FOREACH_VAL(pdata_hash, value_entry) {
			auto err = php_to_restriction(value_entry, &andor->pres[i++]);
			if (err != ecSuccess)
				return err;
		} ZEND_HASH_FOREACH_END();
		break;
	}
	case RES_NOT: {
		pres->pres = emalloc(sizeof(RESTRICTION_NOT));
		auto rnot = pres->xnot;
		if (rnot == nullptr)
			return ecMAPIOOM;
		HashPosition hpos2;
		zend_hash_internal_pointer_reset_ex(pdata_hash, &hpos2);
		value_entry = zend_hash_get_current_data_ex(pdata_hash, &hpos2);
		auto err = php_to_restriction(value_entry, &rnot->res);
		if (err != ecSuccess)
			return err;
		break;
	}
	case RES_SUBRESTRICTION: {
		pres->pres = emalloc(sizeof(RESTRICTION_SUBOBJ));
		auto rsub = pres->sub;
		if (rsub == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rsub->subobject = phptag_to_proptag(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_RESTRICTION);
		if (value_entry == nullptr)
			return ecInvalidParam;
		auto err = php_to_restriction(value_entry, &rsub->res);
		if (err != ecSuccess)
			return err;
		break;
	}
	case RES_COMMENT:
	case RES_ANNOTATION: {
		pres->pres = emalloc(sizeof(RESTRICTION_COMMENT));
		auto rcom = pres->comment;
		if (rcom == nullptr)
			return ecMAPIOOM;
		rcom->pres = st_malloc<RESTRICTION>();
		if (rcom->pres == nullptr)
			/* memory leak */
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_RESTRICTION);
		if (value_entry == nullptr)
			return ecInvalidParam;
		auto err = php_to_restriction(value_entry, rcom->pres);
		if (err != ecSuccess)
			return err;
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPVALS);
		if (value_entry == nullptr)
			return ecInvalidParam;
		err = php_to_tpropval_array(value_entry, &tmp_propvals);
		if (err != ecSuccess)
			return err;
		rcom->count = tmp_propvals.count;
		rcom->ppropval = tmp_propvals.ppropval;
		break;
	}
	case RES_CONTENT: {
		pres->pres = emalloc(sizeof(RESTRICTION_CONTENT));
		auto rcon = pres->cont;
		if (rcon == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rcon->proptag = phptag_to_proptag(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_FUZZYLEVEL);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rcon->fuzzy_level = zval_get_long(value_entry);
		value_entry = zend_hash_index_find(pdata_hash, IDX_VALUE);
		if (value_entry == nullptr)
			return ecInvalidParam;
		if (Z_TYPE_P(value_entry) == IS_ARRAY) {
			auto err = php_to_tpropval_array(value_entry, &tmp_propvals);
			if (err != ecSuccess)
				return err;
			if (tmp_propvals.count != 1)
				return ecInvalidParam;
			rcon->propval = *tmp_propvals.ppropval;
		} else {
			rcon->propval.proptag = rcon->proptag;
			rcon->propval.pvalue = php_to_propval(value_entry, PROP_TYPE(rcon->proptag));
			if (rcon->propval.pvalue == nullptr)
				return ecError;
		}
		break;
	}
	case RES_PROPERTY: {
		pres->pres = emalloc(sizeof(RESTRICTION_PROPERTY));
		auto rprop = pres->prop;
		if (rprop == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rprop->proptag = phptag_to_proptag(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_RELOP);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rprop->relop = static_cast<enum relop>(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_VALUE);
		if (value_entry == nullptr)
			return ecInvalidParam;
		if (Z_TYPE_P(value_entry) == IS_ARRAY) {
			auto err = php_to_tpropval_array(value_entry, &tmp_propvals);
			if (err != ecSuccess)
				return err;
			if (tmp_propvals.count != 1)
				return ecInvalidParam;
			rprop->propval = *tmp_propvals.ppropval;
		} else {
			rprop->propval.proptag = rprop->proptag;
			rprop->propval.pvalue = php_to_propval(value_entry, PROP_TYPE(rprop->proptag));
			if (rprop->propval.pvalue == nullptr)
				return ecError;
		}
		break;
	}
	case RES_PROPCOMPARE: {
		pres->pres = emalloc(sizeof(RESTRICTION_PROPCOMPARE));
		auto rprop = pres->pcmp;
		if (rprop == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_RELOP);
		if (value_entry == nullptr)
			/* memory leak */
			return ecInvalidParam;
		rprop->relop = static_cast<enum relop>(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG1);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rprop->proptag1 = zval_get_long(value_entry);
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG2);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rprop->proptag2 = zval_get_long(value_entry);
		break;
	}
	case RES_BITMASK: {
		pres->pres = emalloc(sizeof(RESTRICTION_BITMASK));
		auto rbm = pres->bm;
		if (rbm == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_TYPE);
		if (value_entry == nullptr)
			/* memory leak */
			return ecInvalidParam;
		rbm->bitmask_relop = static_cast<enum bm_relop>(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_MASK);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rbm->mask = zval_get_long(value_entry);
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rbm->proptag = phptag_to_proptag(zval_get_long(value_entry));
		break;
	}
	case RES_SIZE: {
		pres->pres = emalloc(sizeof(RESTRICTION_SIZE));
		auto rsize = pres->size;
		if (rsize == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_SIZE);
		if (value_entry == nullptr)
			/* memory leak */
			return ecInvalidParam;
		rsize->size = zval_get_long(value_entry);
		value_entry = zend_hash_index_find(pdata_hash, IDX_RELOP);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rsize->relop = static_cast<enum relop>(zval_get_long(value_entry));
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rsize->proptag = phptag_to_proptag(zval_get_long(value_entry));
		break;
	}
	case RES_EXIST: {
		pres->pres = emalloc(sizeof(RESTRICTION_EXIST));
		auto rex = pres->exist;
		if (rex == nullptr)
			return ecMAPIOOM;
		value_entry = zend_hash_index_find(pdata_hash, IDX_PROPTAG);
		if (value_entry == nullptr)
			return ecInvalidParam;
		rex->proptag = phptag_to_proptag(zval_get_long(value_entry));
		break;
	}
	default:
		return ecInvalidParam;
	}
	return ecSuccess;
}

template<typename V, size_t N> static inline char *itoa(V &&v, char (&buf)[N]) try
{
	static_assert(N > 0);
	auto r = fmt::format_to_n(buf, std::size(buf) - 1, "{}", v);
	buf[r.size] = '\0';
	return buf;
} catch (...) {
	*buf = '\0';
	return buf;
}

ec_error_t restriction_to_php(const RESTRICTION &pres, zval *pzret)
{
	char key[HXSIZEOF_Z64];
	zval pzrops, pzentry, pzarray, pzrestriction;
	TPROPVAL_ARRAY tmp_propvals;
	
	zarray_init(pzret);
	switch (pres.rt) {
	case RES_AND:
	case RES_OR: {
		auto &andor = *pres.andor;
		zarray_init(&pzarray);
		for (size_t i = 0; i < andor.count; ++i) {
			auto err = restriction_to_php(andor.pres[i], &pzentry);
			if (err != ecSuccess)
				return err;
			add_assoc_zval(&pzarray, itoa(i, key), &pzentry);
		}
		break;
	}
	case RES_NOT: {
		auto &rnot = *pres.xnot;
		zarray_init(&pzarray);
		auto err = restriction_to_php(rnot.res, &pzentry);
		if (err != ecSuccess)
			return err;	
		add_assoc_zval(&pzarray, "0", &pzentry);
		break;
	}
	case RES_CONTENT: {
		auto &rcon = *pres.cont;
		tmp_propvals.count = 1;
		tmp_propvals.ppropval = deconst(&rcon.propval);
		auto err = tpropval_array_to_php(tmp_propvals, &pzrops);
		if (err != ecSuccess)
			return err;
		zarray_init(&pzarray);
		add_assoc_zval(&pzarray, itoa(IDX_VALUE, key), &pzrops);
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rcon.proptag));
		add_assoc_long(&pzarray, itoa(IDX_FUZZYLEVEL, key), rcon.fuzzy_level);
		break;
	}
	case RES_PROPERTY: {
		auto &rprop = *pres.prop;
		tmp_propvals.count = 1;
		tmp_propvals.ppropval = deconst(&rprop.propval);
		auto err = tpropval_array_to_php(tmp_propvals, &pzrops);
		if (err != ecSuccess)
			return err;
		zarray_init(&pzarray);
		add_assoc_zval(&pzarray, itoa(IDX_VALUE, key), &pzrops);
		add_assoc_long(&pzarray, itoa(IDX_RELOP, key), static_cast<uint8_t>(rprop.relop));
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rprop.proptag));
		break;
	}
	case RES_PROPCOMPARE: {
		auto &rprop = *pres.pcmp;
		zarray_init(&pzarray);
		add_assoc_long(&pzarray, itoa(IDX_RELOP, key), static_cast<uint8_t>(rprop.relop));
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG1, key), proptag_to_phptag(rprop.proptag1));
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG2, key), proptag_to_phptag(rprop.proptag2));
		break;
	}
	case RES_BITMASK: {
		auto &rbm = *pres.bm;
		zarray_init(&pzarray);
		add_assoc_long(&pzarray, itoa(IDX_TYPE, key), static_cast<uint8_t>(rbm.bitmask_relop));
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rbm.proptag));
		add_assoc_long(&pzarray, itoa(IDX_MASK, key), rbm.mask);
		break;
	}
	case RES_SIZE: {
		auto &rsize = *pres.size;
		zarray_init(&pzarray);
		add_assoc_long(&pzarray, itoa(IDX_RELOP, key), static_cast<uint8_t>(rsize.relop));
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rsize.proptag));
		add_assoc_long(&pzarray, itoa(IDX_SIZE, key), rsize.size);
		break;
	}
	case RES_EXIST: {
		auto &rex = *pres.exist;
		zarray_init(&pzarray);
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rex.proptag));
		break;
	}
	case RES_SUBRESTRICTION: {
		auto &rsub = *pres.sub;
		auto err = restriction_to_php(rsub.res, &pzrestriction);
		if (err != ecSuccess)
			return err;	
		zarray_init(&pzarray);
		add_assoc_long(&pzarray, itoa(IDX_PROPTAG, key), proptag_to_phptag(rsub.subobject));
		add_assoc_zval(&pzarray, itoa(IDX_RESTRICTION, key), &pzrestriction);
		break;
	}
	case RES_COMMENT:
	case RES_ANNOTATION: {
		auto &rcom = *pres.comment;
		tmp_propvals.count = rcom.count;
		tmp_propvals.ppropval = rcom.ppropval;
		auto err = tpropval_array_to_php(tmp_propvals, &pzrops);
		if (err != ecSuccess)
			return err;
		err = restriction_to_php(*rcom.pres, &pzrestriction);
		if (err != ecSuccess)
			return err;	
		zarray_init(&pzarray);
		add_assoc_zval(&pzarray, itoa(IDX_PROPVALS, key), &pzrops);
		add_assoc_zval(&pzarray, itoa(IDX_RESTRICTION, key), &pzrestriction);
		break;
	}
	default:
		return ecInvalidParam;
	}
	add_assoc_long(pzret, "0", static_cast<uint8_t>(pres.rt));
	add_assoc_zval(pzret, "1", &pzarray);
	return ecSuccess;
}

static ec_error_t proptag_array_to_php(const std::vector<proptag_t> &tags, zval *pzret)
{
	zarray_init(pzret);
	for (auto t : tags)
		add_next_index_long(pzret, proptag_to_phptag(t));
	return ecSuccess;
}

ec_error_t tpropval_array_to_php(const TPROPVAL_ARRAY &ppropvals, zval *pzret) try
{
	char key[HXSIZEOF_Z64];
	zval pzmval, pzalist, pzactval, pzpropval, pzactarray;
	TPROPVAL_ARRAY tmp_propvals;
	
	zarray_init(pzret);
	for (const auto &pv : ppropvals) {
		/*
		* PHP wants a string as array key. PHP will transform this to zval integer when possible.
		* Because MAPI works with ULONGS, some properties (namedproperties) are bigger than LONG_MAX
		* and they will be stored as a zval string.
		* To prevent this we cast the ULONG to a signed long. The number will look a bit weird but it
		* will work.
		*/
		auto pts = std::to_string(proptag_to_phptag(pv.proptag));
		switch (PROP_TYPE(pv.proptag)) {
		case PT_LONG:
		case PT_ERROR:
			add_assoc_long(pzret, pts.c_str(), *static_cast<const uint32_t *>(pv.pvalue));
			break;
		case PT_SHORT:
			add_assoc_long(pzret, pts.c_str(), *static_cast<const uint16_t *>(pv.pvalue));
			break;
		case PT_DOUBLE:
		case PT_APPTIME:
			add_assoc_double(pzret, pts.c_str(), *static_cast<const double *>(pv.pvalue));
			break;
		case PT_CURRENCY:
		case PT_I8:
			add_assoc_double(pzret, pts.c_str(), *static_cast<const uint64_t *>(pv.pvalue));
			break;
		case PT_FLOAT:
			add_assoc_double(pzret, pts.c_str(), *static_cast<const float *>(pv.pvalue));
			break;
		case PT_BOOLEAN:
			add_assoc_bool(pzret, pts.c_str(), *static_cast<const uint8_t *>(pv.pvalue));
			break;
		case PT_STRING8:
		case PT_UNICODE:
			add_assoc_string(pzret, pts.c_str(), static_cast<const char *>(pv.pvalue));
			break;
		case PT_BINARY: {
			auto &bin = *static_cast<const BINARY *>(pv.pvalue);
			add_assoc_stringl(pzret, pts.c_str(), bin.pc, bin.cb);
			break;
		}
		case PT_SYSTIME:
			add_assoc_long(pzret, pts.c_str(),
				rop_util_nttime_to_unix(*static_cast<const uint64_t *>(pv.pvalue)));
			break;
		case PT_CLSID:
			add_assoc_stringl(pzret, pts.c_str(),
				static_cast<const char *>(pv.pvalue), sizeof(GUID));
			break;
		case PT_MV_SHORT: {
			zarray_init(&pzmval);
			auto &xs = *static_cast<const SHORT_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xs.count; ++j)
				add_assoc_long(&pzmval, itoa(j, key), xs.ps[j]);
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_LONG: {
			zarray_init(&pzmval);
			auto &xl = *static_cast<const LONG_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xl.count; ++j)
				add_assoc_long(&pzmval, itoa(j, key), xl.pl[j]);
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_FLOAT: {
			zarray_init(&pzmval);
			auto &xl = *static_cast<const FLOAT_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xl.count; ++j) {
				snprintf(key, std::size(key), "%zu", j);
				add_assoc_double(&pzmval, key, xl.mval[j]);
			}
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_DOUBLE:
		case PT_MV_APPTIME: {
			zarray_init(&pzmval);
			auto &xl = *static_cast<const DOUBLE_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xl.count; ++j) {
				snprintf(key, std::size(key), "%zu", j);
				add_assoc_double(&pzmval, key, xl.mval[j]);
			}
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_BINARY: {
			zarray_init(&pzmval);
			auto &xb = *static_cast<const BINARY_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xb.count; ++j)
				add_assoc_stringl(&pzmval, itoa(j, key), xb.pbin[j].pc, xb.pbin[j].cb);
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_STRING8:
		case PT_MV_UNICODE: {
			zarray_init(&pzmval);
			auto &xs = *static_cast<const STRING_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xs.count; ++j)
				add_assoc_string(&pzmval, itoa(j, key), xs.ppstr[j]);
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_MV_CLSID: {
			zarray_init(&pzmval);
			auto &xb = *static_cast<const GUID_ARRAY *>(pv.pvalue);
			for (size_t j = 0; j < xb.count; ++j)
				add_assoc_stringl(&pzmval, itoa(j, key),
					reinterpret_cast<const char *>(&xb.pguid[j]),
					sizeof(GUID));
			add_assoc_zval(pzret, pts.c_str(), &pzmval);
			break;
		}
		case PT_ACTIONS: {
			auto prulelist = static_cast<const RULE_ACTIONS *>(pv.pvalue);
			size_t j = 0;
			zarray_init(&pzactarray);
			for (const auto &act : *prulelist) {
				zarray_init(&pzactval);
				add_assoc_long(&pzactval, "action", act.type);
				add_assoc_long(&pzactval, "flags", act.flags);
				add_assoc_long(&pzactval, "flavor", act.flavor);
				switch (act.type) {
				case OP_MOVE:
				case OP_COPY: {
					auto &xq = *static_cast<const ZMOVECOPY_ACTION *>(act.pdata);
					add_assoc_stringl(&pzactval, "storeentryid",
						xq.store_eid.pc, xq.store_eid.cb);
					add_assoc_stringl(&pzactval, "folderentryid",
						xq.folder_eid.pc, xq.folder_eid.cb);
					break;
				}
				case OP_REPLY:
				case OP_OOF_REPLY: {
					auto &xq = *static_cast<const ZREPLY_ACTION *>(act.pdata);
					add_assoc_stringl(&pzactval, "replyentryid",
						xq.message_eid.pc, xq.message_eid.cb);
					add_assoc_stringl(
						&pzactval, "replyguid",
						reinterpret_cast<const char *>(&xq.template_guid),
						sizeof(GUID)); //XXX FLATUID
					break;
				}
				case OP_DEFER_ACTION:
					add_assoc_stringl(&pzactval, "dam",
						static_cast<const char *>(act.pdata), act.length
						- sizeof(uint8_t) - 2*sizeof(uint32_t));
					break;
				case OP_BOUNCE:
					add_assoc_long(&pzactval, "code",
						*static_cast<uint32_t *>(act.pdata));
					break;
				case OP_FORWARD:
				case OP_DELEGATE: {
					zarray_init(&pzalist);
					auto &xq = *static_cast<const FORWARDDELEGATE_ACTION *>(act.pdata);
					for (const auto &block : xq) {
						tmp_propvals.count = block.count;
						tmp_propvals.ppropval = block.ppropval;
						auto err = tpropval_array_to_php(tmp_propvals, &pzpropval);
						if (err != ecSuccess)
							return err;
						zend_hash_next_index_insert(HASH_OF(&pzalist),
									&pzpropval);
					}
					add_assoc_zval(&pzactval, "adrlist", &pzalist);
					break;
				}
				case OP_TAG: {
					tmp_propvals.count = 1;
					tmp_propvals.ppropval = deconst(static_cast<const TAGGED_PROPVAL *>(act.pdata));
					auto err = tpropval_array_to_php(tmp_propvals, &pzalist);
					if (err != ecSuccess)
						return err;
					add_assoc_zval(&pzactval, "proptag", &pzalist);
					break;
				}
				case OP_DELETE:
				case OP_MARK_AS_READ:
					break;
				default:
					return ecInvalidParam;
				};
				add_assoc_zval(&pzactarray, itoa(j, key), &pzactval);
				++j;
			}
			add_assoc_zval(pzret, pts.c_str(), &pzactarray);
			break;
		}
		case PT_SRESTRICTION: {
			auto err = restriction_to_php(*static_cast<const RESTRICTION *>(pv.pvalue), &pzactval);
			if (err != ecSuccess)
				return err;
			add_assoc_zval(pzret, pts.c_str(), &pzactval);
			break;
		}
		}
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	return ecMAPIOOM;
}

ec_error_t tarray_set_to_php(const TARRAY_SET &pset, zval *pret)
{
	zval pzpropval;
	
	zarray_init(pret);
	for (const auto &row : pset) {
		auto err = tpropval_array_to_php(row, &pzpropval);
		if (err != ecSuccess)
			return err;
		zend_hash_next_index_insert(HASH_OF(pret), &pzpropval);
	}
	return ecSuccess;
}

ec_error_t state_array_to_php(const STATE_ARRAY &pstates, zval *pzret)
{
	zval pzval;
	
	zarray_init(pzret);
	for (const auto &state : pstates) {
		zarray_init(&pzval);
		add_assoc_stringl(&pzval, "sourcekey", state.source_key.pc, state.source_key.cb);
		add_assoc_long(&pzval, "flags", state.message_flags);
		add_next_index_zval(pzret, &pzval);
	}
	return ecSuccess;
}

ec_error_t php_to_state_array(zval *pzval, STATE_ARRAY *pstates)
{
	int i; 
	zval *pentry;
	HashTable *ptarget_hash;
	zstrplus str_sourcekey(zend_string_init("sourcekey", sizeof("sourcekey") - 1, 0));
	zstrplus str_flags(zend_string_init("flags", sizeof("flags") - 1, 0));
	
	if (pzval == nullptr)
		return ecInvalidParam;
	ZVAL_DEREF(pzval);
	ptarget_hash = HASH_OF(pzval);
	if (ptarget_hash == nullptr)
		return ecInvalidParam;
	pstates->count = zend_hash_num_elements(Z_ARRVAL_P(pzval));
	if (0 == pstates->count) {
		pstates->pstate = NULL;
		return ecSuccess;
	}
	pstates->pstate = sta_malloc<MESSAGE_STATE>(pstates->count);
	if (NULL == pstates->pstate) {
		pstates->count = 0;
		return ecMAPIOOM;
	}
	i = 0;
	ZEND_HASH_FOREACH_VAL(ptarget_hash, pentry) {
		ZVAL_DEREF(pentry);
		auto value_entry = zend_hash_find(HASH_OF(pentry), str_sourcekey.get());
		if (value_entry == nullptr)
			return ecInvalidParam;
		zstrplus str(zval_get_string(value_entry));
		pstates->pstate[i].source_key.cb = str->len;
		pstates->pstate[i].source_key.pb = sta_malloc<uint8_t>(str->len);
		if (NULL == pstates->pstate[i].source_key.pb) {
			pstates->pstate[i].source_key.cb = 0;
			return ecMAPIOOM;
		}
		memcpy(pstates->pstate[i].source_key.pb, str->val, str->len);
		value_entry = zend_hash_find(HASH_OF(pentry), str_flags.get());
		if (value_entry == nullptr)
			return ecInvalidParam;
		pstates->pstate[i++].message_flags = zval_get_long(value_entry);
	} ZEND_HASH_FOREACH_END();
	return ecSuccess;
}

ec_error_t znotification_array_to_php(const ZNOTIFICATION_ARRAY &pnotifications, zval *pzret)
{
	zval pzvalprops, pzvalnotif;
	
	zarray_init(pzret);
	for (const auto &nt : pnotifications) {
		zarray_init(&pzvalnotif);
		add_assoc_long(&pzvalnotif, "eventtype", nt.event_type);
		switch (nt.event_type) {
		case fnevNewMail: {
			if (nt.pentryid.has_value())
				add_assoc_stringl(&pzvalnotif, "entryid", nt.pentryid->data(), nt.pentryid->size());
			if (nt.pparentid.has_value())
				add_assoc_stringl(&pzvalnotif, "parentid", nt.pparentid->data(), nt.pparentid->size());
			add_assoc_long(&pzvalnotif, "flags", nt.flags);
			add_assoc_stringl(&pzvalnotif, "messageclass", nt.message_class.data(), nt.message_class.size());
			add_assoc_long(&pzvalnotif, "messageflags", nt.message_flags);
			break;
		}
		case fnevObjectCreated:
		case fnevObjectDeleted:
		case fnevObjectModified:
		case fnevObjectMoved:
		case fnevObjectCopied:
		case fnevSearchComplete: {
			auto pobject_notification = &nt;
			if (pobject_notification->pentryid.has_value()) {
				add_assoc_stringl(&pzvalnotif, "entryid",
					pobject_notification->pentryid->data(),
					pobject_notification->pentryid->size());
			}
			add_assoc_long(&pzvalnotif, "objtype",
				static_cast<uint32_t>(pobject_notification->object_type));
			if (pobject_notification->pparentid.has_value()) {
				add_assoc_stringl(&pzvalnotif, "parentid",
					pobject_notification->pparentid->data(),
					pobject_notification->pparentid->size());
			}
			if (pobject_notification->pold_entryid.has_value()) {
				add_assoc_stringl(&pzvalnotif, "oldid",
					pobject_notification->pold_entryid->data(),
					pobject_notification->pold_entryid->size());
			}
			if (pobject_notification->pold_parentid.has_value()) {
				add_assoc_stringl(&pzvalnotif, "oldparentid",
					pobject_notification->pold_parentid->data(),
					pobject_notification->pold_parentid->size());
			}
			if (pobject_notification->pproptags.has_value()) {
				auto err = proptag_array_to_php(*pobject_notification->pproptags, &pzvalprops);
				if (err != ecSuccess)
					return err;
				add_assoc_zval(&pzvalnotif, "proptagarray", &pzvalprops);
			}
			break;
		}
		default:
			continue;
		}
		add_next_index_zval(pzret, &pzvalnotif);
	}
	return ecSuccess;
}

ec_error_t php_to_propname_array(zval *pzval_names, zval *pzval_guids,
    PROPNAME_ARRAY *ppropnames)
{
	int i;
	HashTable *pnameshash;
	
	pnameshash = Z_ARRVAL_P(pzval_names);
	auto pguidhash = pzval_guids != nullptr ? Z_ARRVAL_P(pzval_guids) : nullptr;
	ppropnames->count = zend_hash_num_elements(pnameshash);
	if (NULL != pguidhash && ppropnames->count !=
		zend_hash_num_elements(pguidhash)) {
		return ecInvalidParam;
	}
	if (0 == ppropnames->count) {
		ppropnames->ppropname = NULL;
		return ecSuccess;
	}
	ppropnames->ppropname = sta_malloc<PROPERTY_NAME>(ppropnames->count);
	if (NULL == ppropnames->ppropname) {
		ppropnames->count = 0;
		return ecMAPIOOM;
	}
	zend_hash_internal_pointer_reset(pnameshash);
	if (pguidhash != nullptr)
		zend_hash_internal_pointer_reset(pguidhash);
	HashPosition thpos, ghpos;
	zend_hash_internal_pointer_reset_ex(pnameshash, &thpos);
	if (pguidhash != nullptr)
		zend_hash_internal_pointer_reset_ex(pguidhash, &ghpos);
	for (i=0; i<ppropnames->count; i++) {
		auto entry = zend_hash_get_current_data_ex(pnameshash, &thpos);
		zval *guidentry = nullptr;
		if (pguidhash != nullptr)
			guidentry = zend_hash_get_current_data_ex(pguidhash, &ghpos);
		ppropnames->ppropname[i].guid = PSETID_Appointment; // compat with Zarafa
		if (pguidhash != nullptr && guidentry != nullptr &&
		    Z_TYPE_P(guidentry) == IS_STRING &&
		    Z_STRLEN_P(guidentry) == sizeof(GUID))
			memcpy(&ppropnames->ppropname[i].guid, Z_STRVAL_P(guidentry), sizeof(GUID));
		switch (Z_TYPE_P(entry)) {
		case IS_LONG:
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = zval_get_long(entry);
			ppropnames->ppropname[i].pname = NULL;
			break;
		case IS_STRING:
			ppropnames->ppropname[i].kind = MNID_STRING;
			ppropnames->ppropname[i].lid = 0;
			ppropnames->ppropname[i].pname = estrdup(Z_STRVAL_P(entry));
			if (ppropnames->ppropname[i].pname == nullptr)
				return ecMAPIOOM;
			break;
		case IS_DOUBLE:
			ppropnames->ppropname[i].kind = MNID_ID;
			ppropnames->ppropname[i].lid = zval_get_long(entry);
			ppropnames->ppropname[i].pname = NULL;
			break;
		default:
			return ecInvalidParam;
		}
		zend_hash_move_forward_ex(pnameshash, &thpos);
		if (pguidhash != nullptr)
			zend_hash_move_forward_ex(pguidhash, &ghpos);
	}
	return ecSuccess;
}

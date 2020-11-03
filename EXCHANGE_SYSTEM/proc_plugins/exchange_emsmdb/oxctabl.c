#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "rops.h"
#include "common_util.h"
#include "exmdb_client.h"
#include "table_object.h"
#include "rop_processor.h"
#include "processor_types.h"
#include "emsmdb_interface.h"

#define MAXIMUM_CONTENT_ROWS				127

static BOOL oxctable_verify_columns_and_sorts(
	const PROPTAG_ARRAY *pcolumns,
	const SORTORDER_SET *psort_criteria)
{
	int i;
	uint32_t proptag;
	
	proptag = 0;
	for (i=0; i<psort_criteria->count; i++) {
		if (0 == (psort_criteria->psort[i].type & 0x2000)) {
			continue;
		}
		if (0 == (psort_criteria->psort[i].type & 0x1000)) {
			return FALSE;
		}
		proptag = PROP_TAG(psort_criteria->psort[i].type, psort_criteria->psort[i].propid);
		break;
	}
	for (i=0; i<pcolumns->count; i++) {
		if (pcolumns->pproptag[i] & 0x2000) {
			if (proptag != pcolumns->pproptag[i]) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

uint32_t rop_setcolumns(uint8_t table_flags,
	const PROPTAG_ARRAY *pproptags, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	uint16_t type;
	int object_type;
	TABLE_OBJECT *ptable;
	const SORTORDER_SET *psorts;
	
	if (0 == pproptags->count) {
		return ecInvalidParam;
	}
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	for (i=0; i<pproptags->count; i++) {
		type = PROP_TYPE(pproptags->pproptag[i]);
		if (type & 0x1000) {
			if (type & 0x2000) {
				if (ropGetContentsTable !=
					table_object_get_rop_id(ptable)) {
					return ecNotSupported;
				}
				type &= (~0x2000);
			}
		}
		switch (type) {
		case PT_SHORT:
		case PT_LONG:
		case PROPVAL_TYPE_FLOAT:
		case PROPVAL_TYPE_DOUBLE:
		case PROPVAL_TYPE_CURRENCY:
		case PROPVAL_TYPE_FLOATINGTIME:
		case PROPVAL_TYPE_BYTE:
		case PT_OBJECT:
		case PROPVAL_TYPE_LONGLONG:
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
		case PROPVAL_TYPE_FILETIME:
		case PROPVAL_TYPE_GUID:
		case PROPVAL_TYPE_SVREID:
		case PROPVAL_TYPE_RESTRICTION:
		case PROPVAL_TYPE_RULE:
		case PROPVAL_TYPE_BINARY:
		case PT_MV_SHORT:
		case PT_MV_LONG:
		case PROPVAL_TYPE_LONGLONG_ARRAY:
		case PROPVAL_TYPE_STRING_ARRAY:
		case PROPVAL_TYPE_WSTRING_ARRAY:
		case PROPVAL_TYPE_GUID_ARRAY:
		case PROPVAL_TYPE_BINARY_ARRAY:
			break;
		case PT_UNSPECIFIED:
		case PROPVAL_TYPE_ERROR:
		default:
			return ecInvalidParam;
		}
	}
	psorts = table_object_get_sorts(ptable);
	if (NULL != psorts) {
		if (FALSE == oxctable_verify_columns_and_sorts(
			pproptags, psorts)) {
			return ecNotSupported;
		}
	}
	if (FALSE == table_object_set_columns(ptable, pproptags)) {
		return ecMAPIOOM;
	}
	*ptable_status = TABLE_STATUS_COMPLETE;
	return ecSuccess;
}

uint32_t rop_sorttable(uint8_t table_flags,
	const SORTORDER_SET *psort_criteria, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i, j;
	BOOL b_max;
	uint16_t type;
	int object_type;
	BOOL b_multi_inst;
	uint32_t tmp_proptag;
	TABLE_OBJECT *ptable;
	const PROPTAG_ARRAY *pcolumns;
	
	if (psort_criteria->count > MAXIMUM_SORT_COUNT) {
		return ecTooComplex;
	}
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (table_object_get_rop_id(ptable) != ropGetContentsTable)
		return ecNotSupported;
	b_max = FALSE;
	b_multi_inst = FALSE;
	for (i=0; i<psort_criteria->ccategories; i++) {
		for (j=i+1; j<psort_criteria->count; j++) {
			if (psort_criteria->psort[i].propid ==
				psort_criteria->psort[j].propid &&
				psort_criteria->psort[i].type ==
				psort_criteria->psort[j].type) {
				return ecInvalidParam;
			}
		}
	}
	for (i=0; i<psort_criteria->count; i++) {
		tmp_proptag = PROP_TAG(psort_criteria->psort[i].type, psort_criteria->psort[i].propid);
		if (PROP_TAG_DEPTH == tmp_proptag ||
			PROP_TAG_INSTID == tmp_proptag ||
			PROP_TAG_INSTANCENUM == tmp_proptag ||
			PROP_TAG_CONTENTCOUNT == tmp_proptag ||
			PROP_TAG_CONTENTUNREADCOUNT == tmp_proptag) {
			return ecInvalidParam;
		}	
		switch (psort_criteria->psort[i].table_sort) {
		case TABLE_SORT_ASCEND:
		case TABLE_SORT_DESCEND:
			break;
		case TABLE_SORT_MAXIMUM_CATEGORY:
		case TABLE_SORT_MINIMUM_CATEGORY:
			if (0 == psort_criteria->ccategories ||
				psort_criteria->ccategories != i) {
				return ecInvalidParam;
			}
			break;
		default:
			return ecInvalidParam;
		}
		type = psort_criteria->psort[i].type;
		if (type & 0x1000) {
			/* we do not support multivalue property
				without multivalue instances */
			if (0 == (type & 0x2000)) {
				return ecNotSupported;
			}
			type &= ~0x2000;
			/* MUST NOT contain more than one multivalue property! */
			if (TRUE == b_multi_inst) {
				return ecInvalidParam;
			}
			b_multi_inst = TRUE;
		}
		switch (type) {
		case PT_SHORT:
		case PT_LONG:
		case PROPVAL_TYPE_FLOAT:
		case PROPVAL_TYPE_DOUBLE:
		case PROPVAL_TYPE_CURRENCY:
		case PROPVAL_TYPE_FLOATINGTIME:
		case PROPVAL_TYPE_BYTE:
		case PT_OBJECT:
		case PROPVAL_TYPE_LONGLONG:
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
		case PROPVAL_TYPE_FILETIME:
		case PROPVAL_TYPE_GUID:
		case PROPVAL_TYPE_SVREID:
		case PROPVAL_TYPE_RESTRICTION:
		case PROPVAL_TYPE_RULE:
		case PROPVAL_TYPE_BINARY:
		case PT_MV_SHORT:
		case PT_MV_LONG:
		case PROPVAL_TYPE_LONGLONG_ARRAY:
		case PROPVAL_TYPE_STRING_ARRAY:
		case PROPVAL_TYPE_WSTRING_ARRAY:
		case PROPVAL_TYPE_GUID_ARRAY:
		case PROPVAL_TYPE_BINARY_ARRAY:
			break;
		case PT_UNSPECIFIED:
		case PROPVAL_TYPE_ERROR:
		default:
			return ecInvalidParam;
		}
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psort_criteria->psort[i].table_sort ||
			TABLE_SORT_MINIMUM_CATEGORY ==
			psort_criteria->psort[i].table_sort) {
			if (TRUE == b_max || i != psort_criteria->ccategories) {
				return ecInvalidParam;
			}
			b_max = TRUE;
		}
	}
	pcolumns = table_object_get_columns(ptable);
	if (TRUE == b_multi_inst && NULL != pcolumns) {
		if (FALSE == oxctable_verify_columns_and_sorts(
			pcolumns, psort_criteria)) {
			return ecNotSupported;
		}
	}
	if (FALSE == table_object_set_sorts(ptable, psort_criteria)) {
		return ecMAPIOOM;
	}
	*ptable_status = TABLE_STATUS_COMPLETE;
	table_object_unload(ptable);
	/* MS-OXCTABL 3.2.5.3 */
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	return ecSuccess;
}

uint32_t rop_restrict(uint8_t res_flags,
	const RESTRICTION *pres, uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	switch (table_object_get_rop_id(ptable)) {
	case ropGetHierarchyTable:
	case ropGetContentsTable:
	case ropGetRulesTable:
		break;
	default:
		return ecNotSupported;
	}
	if (NULL != pres) {
		if (FALSE == common_util_convert_restriction(
			TRUE, (RESTRICTION*)pres)) {
			return ecError;
		}
	}
	if (FALSE == table_object_set_restriction(ptable, pres)) {
		return ecMAPIOOM;
	}
	*ptable_status = TABLE_STATUS_COMPLETE;
	table_object_unload(ptable);
	/* MS-OXCTABL 3.2.5.4 */
	table_object_clear_bookmarks(ptable);
	table_object_clear_position(ptable);
	return ecSuccess;
}

uint32_t rop_queryrows(uint8_t flags,
	uint8_t forward_read, uint16_t row_count,
	uint8_t *pseek_pos, uint16_t *pcount, EXT_PUSH *pext,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	BOOL b_forward;
	int object_type;
	TARRAY_SET tmp_set;
	TABLE_OBJECT *ptable;
	PROPERTY_ROW tmp_row;
	uint32_t last_offset;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (0 == forward_read) {
		b_forward = FALSE;
	} else {
		b_forward = TRUE;
	}
	if (table_object_get_rop_id(ptable)
		== ropGetContentsTable &&
		row_count > MAXIMUM_CONTENT_ROWS) {
		row_count = MAXIMUM_CONTENT_ROWS;
	}
	if (FALSE == table_object_query_rows(ptable,
		b_forward, row_count, &tmp_set)) {
		return ecError;
	}
	if (0 == tmp_set.count) {
		*pcount = 0;
	} else {
		for (i=0; i<tmp_set.count; i++) {
			if (FALSE == common_util_propvals_to_row(tmp_set.pparray[i],
				table_object_get_columns(ptable), &tmp_row)) {
				return ecMAPIOOM;
			}
			last_offset = pext->offset;
			if (EXT_ERR_SUCCESS != ext_buffer_push_property_row(
				pext, table_object_get_columns(ptable), &tmp_row)) {
				pext->offset = last_offset;
				break;
			}
		}
		if (0 == i) {
			return ecBufferTooSmall;
		}
		*pcount = i;
	}
	if (0 == (QUERY_ROWS_FLAGS_NOADVANCE & flags)) {
		table_object_seek_current(ptable, b_forward, *pcount);
	}
	*pseek_pos = SEEK_POS_CURRENT;
	if (TRUE == b_forward) {
		if (table_object_get_position(ptable) >=
			table_object_get_total(ptable)) {
			*pseek_pos = SEEK_POS_END;	
		}
	} else {
		if (0 == table_object_get_position(ptable)) {
			*pseek_pos = SEEK_POS_BEGIN;
		}
	}
	return ecSuccess;
}

uint32_t rop_abort(uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	return ecUnableToAbort;
}

uint32_t rop_getstatus(uint8_t *ptable_status,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	*ptable_status = TABLE_STATUS_COMPLETE;
	return ecSuccess;
}

uint32_t rop_queryposition(uint32_t *pnumerator,
	uint32_t *pdenominator, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	*pnumerator = table_object_get_position(ptable);
	*pdenominator = table_object_get_total(ptable);
	return ecSuccess;
}

uint32_t rop_seekrow(uint8_t seek_pos,
	int32_t offset, uint8_t want_moved_count,
	uint8_t *phas_soughtless, int32_t *poffset_sought,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	int32_t original_position;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	switch (seek_pos) {
	case SEEK_POS_BEGIN:
		if (offset < 0) {
			return ecInvalidParam;
		}
		original_position = 0;
		if (offset > table_object_get_total(ptable)) {
			*phas_soughtless = 1;
		} else {
			*phas_soughtless = 0;
		}
		table_object_set_position(ptable, offset);
		break;
	case SEEK_POS_END:
		if (offset > 0) {
			return ecInvalidParam;
		}
		original_position = table_object_get_total(ptable);
		if (table_object_get_total(ptable) + offset < 0) {
			*phas_soughtless = 1;
			table_object_set_position(ptable, 0);
		} else {
			*phas_soughtless = 0;
			table_object_set_position(ptable,
				table_object_get_total(ptable) + offset);
		}
		break;
	case SEEK_POS_CURRENT:
		original_position = table_object_get_position(ptable);
		if (original_position + offset < 0) {
			*phas_soughtless = 1;
			table_object_set_position(ptable, 0);
		} else {
			if (original_position + offset >
				table_object_get_total(ptable)) {
				*phas_soughtless = 1;
			} else {
				*phas_soughtless = 0;
			}
			table_object_set_position(ptable,
				original_position + offset);
		}
		break;
	default:
		return ecInvalidParam;
	}
	*poffset_sought = table_object_get_position(ptable)
									- original_position;
	return ecSuccess;
}

uint32_t rop_seekrowbookmark(const BINARY *pbookmark, 
	int32_t offset, uint8_t want_moved_count,
	uint8_t *prow_invisible, uint8_t *phas_soughtless,
	uint32_t *poffset_sought, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	int object_type;
	TABLE_OBJECT *ptable;
	
	if (pbookmark->cb != sizeof(uint32_t)) {
		return ecInvalidBookmark;
	}
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	switch (table_object_get_rop_id(ptable)) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_loaded(ptable)) {
		return ecInvalidBookmark;
	}
	if (FALSE == table_object_retrieve_bookmark(
		ptable, *(uint32_t*)pbookmark->pb, &b_exist)) {
		return ecInvalidBookmark;
	}
	if (FALSE == b_exist) {
		*prow_invisible = 1;
	} else {
		*prow_invisible = 0;
	}
	return rop_seekrow(SEEK_POS_CURRENT, offset, want_moved_count,
			phas_soughtless, poffset_sought, plogmap, logon_id, hin);
}

uint32_t rop_seekrowfractional(uint32_t numerator,
	uint32_t denominator, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int object_type;
	uint32_t position;
	TABLE_OBJECT *ptable;
	
	if (0 == denominator) {
		return ecInvalidBookmark;
	}
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	position = numerator * table_object_get_total(ptable) / denominator;
	table_object_set_position(ptable, position);
	return ecSuccess;
}

uint32_t rop_createbookmark(BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	switch (table_object_get_rop_id(ptable)) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	pbookmark->cb = sizeof(uint32_t);
	pbookmark->pb = common_util_alloc(sizeof(uint32_t));
	if (NULL == pbookmark->pb) {
		return ecMAPIOOM;
	}
	if (FALSE == table_object_create_bookmark(
		ptable, (uint32_t*)pbookmark->pb)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_querycolumnsall(PROPTAG_ARRAY *pproptags,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (FALSE == table_object_get_all_columns(ptable, pproptags)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_findrow(uint8_t flags, const RESTRICTION *pres,
	uint8_t seek_pos, const BINARY *pbookmark,
	uint8_t *pbookmark_invisible, PROPERTY_ROW **pprow,
	PROPTAG_ARRAY **ppcolumns, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	BOOL b_forward;
	uint32_t result;
	int object_type;
	int32_t position;
	TABLE_OBJECT *ptable;
	uint8_t has_soughtless;
	uint32_t offset_sought;
	TPROPVAL_ARRAY propvals;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	switch (table_object_get_rop_id(ptable)) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
	case ropGetRulesTable:
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (flags & FIND_ROW_FLAG_BACKWARD) {
		b_forward = FALSE;
	} else {
		b_forward = TRUE;
	}
	*pbookmark_invisible = 0;
	switch (seek_pos) {
	case SEEK_POS_CUSTOM:
		if (table_object_get_rop_id(ptable) == ropGetRulesTable)
			return ecNotSupported;
		if (pbookmark->cb != sizeof(uint32_t)) {
			return ecInvalidBookmark;
		}
		result = rop_seekrowbookmark(pbookmark, 0, 0, pbookmark_invisible,
				&has_soughtless, &offset_sought, plogmap, logon_id, hin);
		if (result != ecSuccess)
			return result;
		break;
	case SEEK_POS_BEGIN:
		table_object_set_position(ptable, 0);
		break;
	case SEEK_POS_END:
		table_object_set_position(ptable,
			table_object_get_total(ptable));
		break;
	case SEEK_POS_CURRENT:
		break;
	default:
		return ecInvalidParam;
	}
	if (NULL != pres) {
		if (FALSE == common_util_convert_restriction(
			TRUE, (RESTRICTION*)pres)) {
			return ecError;
		}
	}
	if (FALSE == table_object_match_row(ptable,
		b_forward, pres, &position, &propvals)) {
		return ecError;
	}
	*ppcolumns = (PROPTAG_ARRAY*)table_object_get_columns(ptable);
	if (position < 0) {
		return ecNotFound;
	}
	table_object_set_position(ptable, position);
	*pprow = common_util_alloc(sizeof(PROPERTY_ROW));
	if (NULL == *pprow) {
		return ecMAPIOOM;
	}
	if (FALSE == common_util_propvals_to_row(
		&propvals, *ppcolumns, *pprow)) {
		return ecMAPIOOM;
	}
	return ecSuccess;
}

uint32_t rop_freebookmark(const BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	if (pbookmark->cb != sizeof(uint32_t)) {
		return ecInvalidBookmark;
	}
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	switch (table_object_get_rop_id(ptable)) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	table_object_remove_bookmark(ptable, *(uint32_t*)pbookmark->pb);
	return ecSuccess;
}

uint32_t rop_resettable(void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap, logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	table_object_reset(ptable);
	return ecSuccess;
}

uint32_t rop_expandrow(uint16_t max_count,
	uint64_t category_id, uint32_t *pexpanded_count,
	uint16_t *pcount, EXT_PUSH *pext, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	int i;
	BOOL b_found;
	int object_type;
	int32_t position;
	TARRAY_SET tmp_set;
	PROPERTY_ROW tmp_row;
	uint32_t last_offset;
	TABLE_OBJECT *ptable;
	uint32_t old_position;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (table_object_get_rop_id(ptable) != ropGetContentsTable)
		return ecNotSupported;
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (FALSE == table_object_expand(ptable, category_id,
		&b_found, &position, pexpanded_count)) {
		return ecError;
	}
	if (FALSE == b_found) {
		return ecNotFound;
	} else if (position < 0) {
		return ecNotCollapsed;
	}
	if (0 == *pexpanded_count || 0 == max_count) {
		*pcount = 0;
		return ecSuccess;
	}
	if (max_count > *pexpanded_count) {
		max_count = *pexpanded_count;
	}
	old_position = table_object_get_position(ptable);
	table_object_set_position(ptable, position + 1);
	if (FALSE == table_object_query_rows(ptable, TRUE, max_count, &tmp_set)) {
		table_object_set_position(ptable, old_position);
		return ecError;
	}
	table_object_set_position(ptable, old_position);
	for (i=0; i<tmp_set.count; i++) {
		if (FALSE == common_util_propvals_to_row(tmp_set.pparray[i],
			table_object_get_columns(ptable), &tmp_row)) {
			return ecMAPIOOM;
		}
		last_offset = pext->offset;
		if (EXT_ERR_SUCCESS != ext_buffer_push_property_row(
			pext, table_object_get_columns(ptable), &tmp_row)) {
			pext->offset = last_offset;
			break;
		}
	}
	*pcount = i;
	return ecSuccess;
}

uint32_t rop_collapserow(uint64_t category_id,
	uint32_t *pcollapsed_count, void *plogmap,
	uint8_t logon_id, uint32_t hin)
{
	BOOL b_found;
	int object_type;
	int32_t position;
	TABLE_OBJECT *ptable;
	uint32_t table_position;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (table_object_get_rop_id(ptable) != ropGetContentsTable)
		return ecNotSupported;
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	if (FALSE == table_object_collapse(ptable, category_id,
		&b_found, &position, pcollapsed_count)) {
		return ecError;
	}
	if (FALSE == b_found) {
		return ecNotFound;
	} else if (position < 0) {
		return ecNotExpanded;
	} else if (0 == *pcollapsed_count) {
		return ecSuccess;
	}
	table_position = table_object_get_position(ptable);
	if (table_position > position) {
		table_position -= *pcollapsed_count;
		table_object_set_position(ptable, table_position);	
	}
	return ecSuccess;
}

uint32_t rop_getcollapsestate(uint64_t row_id,
	uint32_t row_instance, BINARY *pcollapse_state,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (ropGetContentsTable !=
		table_object_get_rop_id(ptable)) {
		return ecNotSupported;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	pcollapse_state->cb = sizeof(uint32_t);
	pcollapse_state->pb = common_util_alloc(sizeof(uint32_t));
	if (NULL == pcollapse_state->pb) {
		return ecMAPIOOM;
	}
	if (FALSE == table_object_store_state(ptable, row_id,
		row_instance, (uint32_t*)pcollapse_state->pb)) {
		return ecError;
	}
	return ecSuccess;
}

uint32_t rop_setcollapsestate(
	const BINARY *pcollapse_state, BINARY *pbookmark,
	void *plogmap, uint8_t logon_id, uint32_t hin)
{
	int object_type;
	TABLE_OBJECT *ptable;
	
	ptable = rop_processor_get_object(plogmap,
				logon_id, hin, &object_type);
	if (NULL == ptable) {
		return ecNullObject;
	}
	if (OBJECT_TYPE_TABLE != object_type) {
		return ecNotSupported;
	}
	if (ropGetContentsTable !=
		table_object_get_rop_id(ptable)) {
		return ecNotSupported;
	}
	if (sizeof(uint32_t) != pcollapse_state->cb) {
		return ecInvalidParam;
	}
	if (NULL == table_object_get_columns(ptable)) {
		return ecNullObject;
	}
	if (FALSE == table_object_check_to_load(ptable)) {
		return ecError;
	}
	pbookmark->cb = sizeof(uint32_t);
	pbookmark->pb = common_util_alloc(sizeof(uint32_t));
	if (NULL == pbookmark->pb) {
		return ecMAPIOOM;
	}
	if (FALSE == table_object_restore_state(
		ptable, *(uint32_t*)pcollapse_state->pb,
		(uint32_t*)pbookmark->pb)) {
		return ecError;
	}
	return ecSuccess;
}

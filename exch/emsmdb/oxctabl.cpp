// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstring>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/safeint.hpp>
#include "common_util.h"
#include "emsmdb_interface.h"
#include "exmdb_client.h"
#include "processor_types.h"
#include "rop_funcs.hpp"
#include "rop_ids.hpp"
#include "rop_processor.h"
#include "table_object.h"
#define MAXIMUM_CONTENT_ROWS				127

static BOOL oxctable_verify_columns_and_sorts(
	const PROPTAG_ARRAY *pcolumns,
	const SORTORDER_SET *psort_criteria)
{
	int i;
	uint32_t proptag;
	
	proptag = 0;
	for (i=0; i<psort_criteria->count; i++) {
		if (!(psort_criteria->psort[i].type & MV_INSTANCE))
			continue;
		if (!(psort_criteria->psort[i].type & MV_FLAG))
			return FALSE;
		proptag = PROP_TAG(psort_criteria->psort[i].type, psort_criteria->psort[i].propid);
		break;
	}
	for (i = 0; i < pcolumns->count; ++i)
		if (pcolumns->pproptag[i] & MV_INSTANCE)
			if (proptag != pcolumns->pproptag[i])
				return FALSE;
	return TRUE;
}

static inline bool table_acceptable_type(uint16_t type)
{
	switch (type) {
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_CURRENCY:
	case PT_APPTIME:
	case PT_BOOLEAN:
	case PT_OBJECT:
	case PT_I8:
	case PT_STRING8:
	case PT_UNICODE:
	case PT_SYSTIME:
	case PT_CLSID:
	case PT_SVREID:
	case PT_SRESTRICTION:
	case PT_ACTIONS:
	case PT_BINARY:
	case PT_MV_SHORT:
	case PT_MV_LONG:
	case PT_MV_FLOAT:
	case PT_MV_DOUBLE:
	case PT_MV_APPTIME:
	case PT_MV_CURRENCY:
	case PT_MV_I8:
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
	case PT_MV_SYSTIME:
	case PT_MV_CLSID:
	case PT_MV_BINARY:
		return true;
	default:
		return false;
	}
}

ec_error_t rop_setcolumns(uint8_t table_flags, const PROPTAG_ARRAY *pproptags,
    uint8_t *ptable_status, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	int i;
	uint16_t type;
	ems_objtype object_type;
	
	if (pproptags->count == 0)
		return ecInvalidParam;
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	for (i=0; i<pproptags->count; i++) {
		type = PROP_TYPE(pproptags->pproptag[i]);
		if ((type & MVI_FLAG) == MVI_FLAG) {
				if (ropGetContentsTable != ptable->rop_id)
					return ecNotSupported;
				type &= ~MV_INSTANCE;
		}
		if (!table_acceptable_type(type))
			return ecInvalidParam;
	}
	auto psorts = ptable->get_sorts();
	if (psorts != nullptr && !oxctable_verify_columns_and_sorts(pproptags, psorts))
		return ecNotSupported;
	if (!ptable->set_columns(pproptags))
		return ecServerOOM;
	*ptable_status = TBLSTAT_COMPLETE;
	return ecSuccess;
}

ec_error_t rop_sorttable(uint8_t table_flags, const SORTORDER_SET *psort_criteria,
    uint8_t *ptable_status, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_max;
	uint16_t type;
	ems_objtype object_type;
	BOOL b_multi_inst;
	uint32_t tmp_proptag;
	
	if (psort_criteria->count > MAXIMUM_SORT_COUNT)
		return ecTooComplex;
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ptable->rop_id != ropGetContentsTable)
		return ecNotSupported;
	b_max = FALSE;
	b_multi_inst = FALSE;
	for (unsigned int i = 0; i < psort_criteria->count; ++i) {
		tmp_proptag = PROP_TAG(psort_criteria->psort[i].type, psort_criteria->psort[i].propid);
		if (tmp_proptag == PR_DEPTH || tmp_proptag == PidTagInstID ||
		    tmp_proptag == PidTagInstanceNum ||
		    tmp_proptag == PR_CONTENT_COUNT ||
		    tmp_proptag == PR_CONTENT_UNREAD)
			return ecInvalidParam;
		switch (psort_criteria->psort[i].table_sort) {
		case TABLE_SORT_ASCEND:
		case TABLE_SORT_DESCEND:
			break;
		case TABLE_SORT_MAXIMUM_CATEGORY:
		case TABLE_SORT_MINIMUM_CATEGORY:
			if (psort_criteria->ccategories == 0 ||
			    psort_criteria->ccategories != i)
				return ecInvalidParam;
			break;
		default:
			return ecInvalidParam;
		}
		type = psort_criteria->psort[i].type;
		if (type & MV_FLAG) {
			/* we do not support multivalue property
				without multivalue instances */
			if (!(type & MV_INSTANCE))
				return ecNotSupported;
			type &= ~MV_INSTANCE;
			/* MUST NOT contain more than one multivalue property! */
			if (b_multi_inst)
				return ecInvalidParam;
			b_multi_inst = TRUE;
		}
		if (!table_acceptable_type(type))
			return ecInvalidParam;
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psort_criteria->psort[i].table_sort ||
			TABLE_SORT_MINIMUM_CATEGORY ==
			psort_criteria->psort[i].table_sort) {
			if (b_max || i != psort_criteria->ccategories)
				return ecInvalidParam;
			b_max = TRUE;
		}
	}
	auto pcolumns = ptable->get_columns();
	if (b_multi_inst && pcolumns != nullptr && 
	    !oxctable_verify_columns_and_sorts(pcolumns, psort_criteria))
		return ecNotSupported;
	if (!ptable->set_sorts(psort_criteria))
		return ecServerOOM;
	*ptable_status = TBLSTAT_COMPLETE;
	ptable->unload();
	/* MS-OXCTABL 3.2.5.3 */
	ptable->clear_bookmarks();
	ptable->clear_position();
	return ecSuccess;
}

ec_error_t rop_restrict(uint8_t res_flags, RESTRICTION *pres,
    uint8_t *ptable_status, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	switch (ptable->rop_id) {
	case ropGetHierarchyTable:
	case ropGetContentsTable:
	case ropGetRulesTable:
		break;
	default:
		return ecNotSupported;
	}
	if (pres != nullptr && !common_util_convert_restriction(TRUE, pres))
		return ecError;
	if (!ptable->set_restriction(pres))
		return ecServerOOM;
	*ptable_status = TBLSTAT_COMPLETE;
	ptable->unload();
	/* MS-OXCTABL 3.2.5.4 */
	ptable->clear_bookmarks();
	ptable->clear_position();
	return ecSuccess;
}

ec_error_t rop_queryrows(uint8_t flags, uint8_t forward_read, uint16_t row_count,
    uint8_t *pseek_pos, uint16_t *pcount, EXT_PUSH *pext, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	auto &ext = *pext;
	ems_objtype object_type;
	TARRAY_SET tmp_set;
	PROPERTY_ROW tmp_row;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	BOOL b_forward = forward_read == 0 ? false : TRUE;
	if (ptable->rop_id == ropGetContentsTable &&
	    row_count > MAXIMUM_CONTENT_ROWS)
		row_count = MAXIMUM_CONTENT_ROWS;
	if (!ptable->query_rows(b_forward, row_count, &tmp_set))
		return ecError;
	if (0 == tmp_set.count) {
		*pcount = 0;
	} else {
		size_t i;
		for (i=0; i<tmp_set.count; i++) {
			if (!common_util_propvals_to_row(tmp_set.pparray[i],
			    ptable->get_columns(), &tmp_row))
				return ecServerOOM;
			uint32_t last_offset = ext.m_offset;
			if (pext->p_proprow(*ptable->get_columns(), tmp_row) != EXT_ERR_SUCCESS) {
				ext.m_offset = last_offset;
				break;
			}
		}
		if (i == 0)
			return ecBufferTooSmall;
		*pcount = i;
	}
	if (!(flags & QUERY_ROWS_FLAGS_NOADVANCE))
		ptable->seek_current(b_forward, *pcount);
	*pseek_pos = BOOKMARK_CURRENT;
	if (b_forward) {
		if (ptable->get_position() >= ptable->get_total())
			*pseek_pos = BOOKMARK_END;
	} else {
		if (ptable->get_position() == 0)
			*pseek_pos = BOOKMARK_BEGINNING;
	}
	return ecSuccess;
}

ec_error_t rop_abort(uint8_t *ptable_status, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	return ecUnableToAbort;
}

ec_error_t rop_getstatus(uint8_t *ptable_status, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	*ptable_status = TBLSTAT_COMPLETE;
	return ecSuccess;
}

ec_error_t rop_queryposition(uint32_t *pnumerator, uint32_t *pdenominator,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	*pnumerator = ptable->get_position();
	*pdenominator = ptable->get_total();
	return ecSuccess;
}

ec_error_t rop_seekrow(uint8_t seek_pos, int32_t offset, uint8_t want_moved_count,
    uint8_t *phas_soughtless, int32_t *poffset_sought, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	uint32_t original_position;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	int8_t clamped = 0;
	switch (seek_pos) {
	case BOOKMARK_BEGINNING:
		if (offset < 0)
			return ecInvalidParam;
		original_position = 0;
		clamped = static_cast<uint32_t>(offset) > ptable->get_total();
		ptable->set_position(offset);
		break;
	case BOOKMARK_END:
		if (offset > 0)
			return ecInvalidParam;
		original_position = ptable->get_total();
		ptable->set_position(safe_add_s(original_position, offset, &clamped));
		break;
	case BOOKMARK_CURRENT: {
		original_position = ptable->get_position();
		auto newpos = safe_add_s(original_position, offset, &clamped);
		clamped = newpos > ptable->get_total();
		ptable->set_position(newpos);
		break;
	}
	default:
		return ecInvalidParam;
	}
	*phas_soughtless = !!clamped;
	*poffset_sought = ptable->get_position() - original_position;
	return ecSuccess;
}

ec_error_t rop_seekrowbookmark(const BINARY *pbookmark, int32_t offset,
    uint8_t want_moved_count, uint8_t *prow_invisible, uint8_t *phas_soughtless,
    uint32_t *poffset_sought, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_exist;
	ems_objtype object_type;
	
	if (pbookmark->cb != sizeof(uint32_t))
		return ecInvalidBookmark;
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	switch (ptable->rop_id) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->is_loaded())
		return ecInvalidBookmark;
	uint32_t bm = 0;
	memcpy(&bm, pbookmark->pb, sizeof(bm));
	if (!ptable->retrieve_bookmark(bm, &b_exist))
		return ecInvalidBookmark;
	*prow_invisible = !b_exist;
	return rop_seekrow(BOOKMARK_CURRENT, offset, want_moved_count,
	       phas_soughtless, reinterpret_cast<int32_t *>(poffset_sought), plogmap, logon_id, hin);
}

ec_error_t rop_seekrowfractional(uint32_t numerator, uint32_t denominator,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	if (denominator == 0)
		return ecInvalidBookmark;
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	auto position = numerator * ptable->get_total() / denominator;
	ptable->set_position(position);
	return ecSuccess;
}

ec_error_t rop_createbookmark(BINARY *pbookmark, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	switch (ptable->rop_id) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	pbookmark->cb = sizeof(uint32_t);
	pbookmark->pv = cu_alloc<uint32_t>();
	if (pbookmark->pb == nullptr)
		return ecServerOOM;
	if (!ptable->create_bookmark(static_cast<uint32_t *>(pbookmark->pv)))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_querycolumnsall(PROPTAG_ARRAY *pproptags, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (!ptable->load())
		return ecError;
	if (!ptable->get_all_columns(pproptags))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_findrow(uint8_t flags, RESTRICTION *pres, uint8_t seek_pos,
    const BINARY *pbookmark, uint8_t *pbookmark_invisible, PROPERTY_ROW **pprow,
    PROPTAG_ARRAY **ppcolumns, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	int32_t position;
	uint8_t has_soughtless;
	uint32_t offset_sought;
	TPROPVAL_ARRAY propvals;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	switch (ptable->rop_id) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
	case ropGetRulesTable:
		break;
	default:
		return ecNotSupported;
	}
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	BOOL b_forward = (flags & FIND_ROW_FLAG_BACKWARD) ? false : TRUE;
	*pbookmark_invisible = 0;
	switch (seek_pos) {
	case BOOKMARK_CUSTOM: {
		if (ptable->rop_id == ropGetRulesTable)
			return ecNotSupported;
		if (pbookmark->cb != sizeof(uint32_t))
			return ecInvalidBookmark;
		auto result = rop_seekrowbookmark(pbookmark, 0, 0, pbookmark_invisible,
				&has_soughtless, &offset_sought, plogmap, logon_id, hin);
		if (result != ecSuccess)
			return result;
		break;
	}
	case BOOKMARK_BEGINNING:
		ptable->set_position(0);
		break;
	case BOOKMARK_END:
		ptable->set_position(ptable->get_total());
		break;
	case BOOKMARK_CURRENT:
		break;
	default:
		return ecInvalidParam;
	}
	if (pres != nullptr && !common_util_convert_restriction(TRUE, pres))
		return ecError;
	if (!ptable->match_row(b_forward, pres, &position, &propvals))
		return ecError;
	*ppcolumns = deconst(ptable->get_columns());
	if (position < 0)
		return ecNotFound;
	ptable->set_position(position);
	*pprow = cu_alloc<PROPERTY_ROW>();
	if (*pprow == nullptr)
		return ecServerOOM;
	if (!common_util_propvals_to_row(&propvals, *ppcolumns, *pprow))
		return ecServerOOM;
	return ecSuccess;
}

ec_error_t rop_freebookmark(const BINARY *pbookmark, LOGMAP *plogmap,
    uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	if (pbookmark->cb != sizeof(uint32_t))
		return ecInvalidBookmark;
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	switch (ptable->rop_id) {
	case ropGetContentsTable:
	case ropGetHierarchyTable:
		break;
	default:
		return ecNotSupported;
	}
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	uint32_t bm = 0;
	memcpy(&bm, pbookmark->pb, sizeof(bm));
	ptable->remove_bookmark(bm);
	return ecSuccess;
}

ec_error_t rop_resettable(LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	ptable->reset();
	return ecSuccess;
}

ec_error_t rop_expandrow(uint16_t max_count, uint64_t category_id,
    uint32_t *pexpanded_count, uint16_t *pcount, EXT_PUSH *pext,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	auto &ext = *pext;
	size_t i;
	BOOL b_found;
	ems_objtype object_type;
	int32_t position;
	TARRAY_SET tmp_set;
	PROPERTY_ROW tmp_row;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ptable->rop_id != ropGetContentsTable)
		return ecNotSupported;
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	if (!ptable->expand(category_id, &b_found, &position, pexpanded_count))
		return ecError;
	if (!b_found)
		return ecNotFound;
	else if (position < 0)
		return ecNotCollapsed;
	if (0 == *pexpanded_count || 0 == max_count) {
		*pcount = 0;
		return ecSuccess;
	}
	if (max_count > *pexpanded_count)
		max_count = *pexpanded_count;
	auto old_position = ptable->get_position();
	ptable->set_position(position + 1);
	if (!ptable->query_rows(TRUE, max_count, &tmp_set)) {
		ptable->set_position(old_position);
		return ecError;
	}
	ptable->set_position(old_position);
	for (i = 0; i < tmp_set.count; ++i) {
		if (!common_util_propvals_to_row(tmp_set.pparray[i],
		    ptable->get_columns(), &tmp_row))
			return ecServerOOM;
		uint32_t last_offset = ext.m_offset;
		if (pext->p_proprow(*ptable->get_columns(), tmp_row) != EXT_ERR_SUCCESS) {
			ext.m_offset = last_offset;
			break;
		}
	}
	*pcount = i;
	return ecSuccess;
}

ec_error_t rop_collapserow(uint64_t category_id, uint32_t *pcollapsed_count,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	BOOL b_found;
	ems_objtype object_type;
	int32_t position;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ptable->rop_id != ropGetContentsTable)
		return ecNotSupported;
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	if (!ptable->collapse(category_id, &b_found, &position, pcollapsed_count))
		return ecError;
	if (!b_found)
		return ecNotFound;
	else if (position < 0)
		return ecNotExpanded;
	else if (*pcollapsed_count == 0)
		return ecSuccess;
	auto table_position = ptable->get_position();
	if (table_position > static_cast<uint32_t>(position)) {
		table_position -= *pcollapsed_count;
		ptable->set_position(table_position);	
	}
	return ecSuccess;
}

ec_error_t rop_getcollapsestate(uint64_t row_id, uint32_t row_instance,
    BINARY *pcollapse_state, LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ropGetContentsTable != ptable->rop_id)
		return ecNotSupported;
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	pcollapse_state->cb = sizeof(uint32_t);
	pcollapse_state->pv = cu_alloc<uint32_t>();
	if (pcollapse_state->pv == nullptr)
		return ecServerOOM;
	if (!ptable->store_state(row_id, row_instance,
	    static_cast<uint32_t *>(pcollapse_state->pv)))
		return ecError;
	return ecSuccess;
}

ec_error_t rop_setcollapsestate(const BINARY *pcollapse_state, BINARY *pbookmark,
    LOGMAP *plogmap, uint8_t logon_id, uint32_t hin)
{
	ems_objtype object_type;
	
	auto ptable = rop_proc_get_obj<table_object>(plogmap, logon_id, hin, &object_type);
	if (ptable == nullptr)
		return ecNullObject;
	if (object_type != ems_objtype::table)
		return ecNotSupported;
	if (ropGetContentsTable != ptable->rop_id)
		return ecNotSupported;
	if (pcollapse_state->cb != sizeof(uint32_t))
		return ecInvalidParam;
	if (ptable->get_columns() == nullptr)
		return ecNullObject;
	if (!ptable->load())
		return ecError;
	pbookmark->cb = sizeof(uint32_t);
	pbookmark->pv = cu_alloc<uint32_t>();
	if (pbookmark->pv == nullptr)
		return ecServerOOM;
	if (!ptable->restore_state(*static_cast<uint32_t *>(pcollapse_state->pv),
	    static_cast<uint32_t *>(pbookmark->pv)))
		return ecError;
	return ecSuccess;
}

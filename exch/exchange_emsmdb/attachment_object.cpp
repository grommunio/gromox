// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "attachment_object.h"
#include <gromox/proptag_array.hpp>
#include "exmdb_client.h"
#include "logon_object.h"
#include "common_util.h"
#include <gromox/rop_util.hpp>
#include <cstdlib>
#include <cstring>

std::unique_ptr<ATTACHMENT_OBJECT> attachment_object_create(MESSAGE_OBJECT *pparent,
	uint32_t attachment_num, uint8_t open_flags)
{
	std::unique_ptr<ATTACHMENT_OBJECT> pattachment;
	try {
		pattachment = std::make_unique<ATTACHMENT_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pattachment->pparent = pparent;
	pattachment->open_flags = open_flags;
	if (ATTACHMENT_NUM_INVALID == attachment_num) {
		if (!exmdb_client_create_attachment_instance(pparent->plogon->get_dir(),
		    pparent->instance_id, &pattachment->instance_id,
		    &pattachment->attachment_num))
			return NULL;
		if (0 == pattachment->instance_id &&
			ATTACHMENT_NUM_INVALID != pattachment->attachment_num) {
			return NULL;	
		}
		pattachment->b_new = TRUE;
	} else {
		if (!exmdb_client_load_attachment_instance(pparent->plogon->get_dir(),
		    pparent->instance_id, attachment_num, &pattachment->instance_id))
			return NULL;
		pattachment->attachment_num = attachment_num;
	}
	double_list_init(&pattachment->stream_list);
	return pattachment;
}

uint32_t attachment_object_get_attachment_num(
	ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->attachment_num;
}

uint32_t attachment_object_get_instance_id(
	ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->instance_id;
}

BOOL attachment_object_init_attachment(
	ATTACHMENT_OBJECT *pattachment)
{
	void *pvalue;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	
	if (FALSE == pattachment->b_new) {
		return FALSE;
	}
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5);
	if (NULL == propvals.ppropval) {
		return FALSE;
	}
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_ATTACHNUMBER;
	propvals.ppropval[propvals.count].pvalue = &pattachment->attachment_num;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag = PROP_TAG_RENDERINGPOSITION;
	propvals.ppropval[propvals.count].pvalue = cu_alloc<uint32_t>();
	if (NULL == propvals.ppropval[propvals.count].pvalue) {
		return FALSE;
	}
	*(uint32_t*)propvals.ppropval[propvals.count].pvalue = 0xFFFFFFFF;
	propvals.count ++;
	
	pvalue = cu_alloc<uint64_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	
	propvals.ppropval[propvals.count].proptag = PR_CREATION_TIME;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	propvals.ppropval[propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	return exmdb_client_set_instance_properties(pattachment->pparent->plogon->get_dir(),
	       pattachment->instance_id, &propvals, &problems);
}

ATTACHMENT_OBJECT::~ATTACHMENT_OBJECT()
{
	auto pattachment = this;
	DOUBLE_LIST_NODE *pnode;
	
	if (0 != pattachment->instance_id) {
		exmdb_client_unload_instance(pattachment->pparent->plogon->get_dir(),
			pattachment->instance_id);
	}
	while ((pnode = double_list_pop_front(&pattachment->stream_list)) != nullptr)
		free(pnode);
	double_list_free(&pattachment->stream_list);
}

uint32_t attachment_object_get_tag_access(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->pparent->tag_access;
}

uint8_t attachment_object_get_open_flags(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->open_flags;
}

void attachment_object_set_open_flags(
	ATTACHMENT_OBJECT *pattachment, uint8_t open_flags)
{
	pattachment->open_flags = open_flags;
}

uint32_t attachment_object_get_cpid(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->pparent->cpid;
}

gxerr_t attachment_object_save(ATTACHMENT_OBJECT *pattachment)
{
	uint64_t nt_time;
	PROBLEM_ARRAY tmp_problems;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (FALSE == pattachment->b_touched) {
		return GXERR_SUCCESS;
	}
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = &tmp_propval;
	if (FALSE == attachment_object_flush_streams(pattachment)) {
		return GXERR_CALL_FAILED;
	}
	tmp_propval.proptag = PR_LAST_MODIFICATION_TIME;
	nt_time = rop_util_current_nttime();
	tmp_propval.pvalue = &nt_time;
	if (FALSE == attachment_object_set_properties(
		pattachment, &tmp_propvals, &tmp_problems)) {
		return GXERR_CALL_FAILED;	
	}
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client_flush_instance(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, NULL, &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	pattachment->b_new = FALSE;
	pattachment->b_touched = FALSE;
	pattachment->pparent->b_touched = TRUE;
	proptag_array_append(pattachment->pparent->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return GXERR_SUCCESS;
}

BOOL attachment_object_append_stream_object(
	ATTACHMENT_OBJECT *pattachment, STREAM_OBJECT *pstream)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pattachment->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pattachment->stream_list, pnode)) {
		if (pnode->pdata == pstream) {
			return TRUE;
		}
	}
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		return FALSE;
	}
	pnode->pdata = pstream;
	double_list_append_as_tail(&pattachment->stream_list, pnode);
	pattachment->b_touched = TRUE;
	return TRUE;
}

/* cablled when stream object is released */
BOOL attachment_object_commit_stream_object(
	ATTACHMENT_OBJECT *pattachment, STREAM_OBJECT *pstream)
{
	uint32_t result;
	DOUBLE_LIST_NODE *pnode;
	TAGGED_PROPVAL tmp_propval;
	
	for (pnode=double_list_get_head(&pattachment->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pattachment->stream_list, pnode)) {
		if (pnode->pdata == pstream) {
			double_list_remove(&pattachment->stream_list, pnode);
			tmp_propval.proptag = stream_object_get_proptag(pstream);
			tmp_propval.pvalue = stream_object_get_content(pstream);
			if (!exmdb_client_set_instance_property(pattachment->pparent->plogon->get_dir(),
			    pattachment->instance_id, &tmp_propval, &result))
				return FALSE;
			return TRUE;
		}
	}
	return TRUE;
}

BOOL attachment_object_flush_streams(ATTACHMENT_OBJECT *pattachment)
{
	uint32_t result;
	STREAM_OBJECT *pstream;
	DOUBLE_LIST_NODE *pnode;
	TAGGED_PROPVAL tmp_propval;
	
	while ((pnode = double_list_pop_front(&pattachment->stream_list)) != nullptr) {
		pstream = static_cast<STREAM_OBJECT *>(pnode->pdata);
		tmp_propval.proptag = stream_object_get_proptag(pstream);
		tmp_propval.pvalue = stream_object_get_content(pstream);
		if (!exmdb_client_set_instance_property(pattachment->pparent->plogon->get_dir(),
		    pattachment->instance_id, &tmp_propval, &result)) {
			double_list_insert_as_head(&pattachment->stream_list, pnode);
			return FALSE;
		}
		free(pnode);
	}
	return TRUE;
	
}

BOOL attachment_object_get_all_proptags(
	ATTACHMENT_OBJECT *pattachment, PROPTAG_ARRAY *pproptags)
{
	int nodes_num;
	uint32_t proptag;
	DOUBLE_LIST_NODE *pnode;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client_get_instance_all_proptags(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_proptags))
		return FALSE;	
	nodes_num = double_list_get_nodes_num(&pattachment->stream_list);
	nodes_num ++;
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + nodes_num);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	for (pnode=double_list_get_head(&pattachment->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pattachment->stream_list, pnode)) {
		proptag = stream_object_get_proptag(static_cast<STREAM_OBJECT *>(pnode->pdata));
		if (common_util_index_proptags(pproptags, proptag) < 0) {
			pproptags->pproptag[pproptags->count] = proptag;
			pproptags->count ++;
		}
	}
	pproptags->pproptag[pproptags->count++] = PR_ACCESS_LEVEL;
	return TRUE;
}

BOOL attachment_object_check_readonly_property(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT && proptag != PR_ATTACH_DATA_OBJ)
		return TRUE;
	switch (proptag) {
	case PROP_TAG_MID:
	case PR_ACCESS_LEVEL:
	case PROP_TAG_INCONFLICT:
	case PR_OBJECT_TYPE:
	case PR_RECORD_KEY:
	case PR_STORE_ENTRYID:
	case PR_STORE_RECORD_KEY:
		return TRUE;
	case PROP_TAG_ATTACHSIZE:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
		if (TRUE == pattachment->b_new) {
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static BOOL attachment_object_get_calculated_property(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag, void **ppvalue)
{
	
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pattachment->pparent->tag_access;
		return TRUE;
	case PR_ACCESS_LEVEL:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*static_cast<uint32_t *>(*ppvalue) =
			(pattachment->open_flags & OPEN_MODE_FLAG_READWRITE) ?
			ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	case PR_OBJECT_TYPE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = OBJECT_ATTACHMENT;
		return TRUE;
	case PR_STORE_RECORD_KEY:
		*ppvalue = common_util_guid_to_binary(
					logon_object_get_mailbox_guid(
					pattachment->pparent->plogon));
		return TRUE;
	}
	return FALSE;
}

static void* attachment_object_get_stream_property_value(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pattachment->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pattachment->stream_list, pnode)) {
		auto so = static_cast<STREAM_OBJECT *>(pnode->pdata);
		if (stream_object_get_proptag(so) == proptag)
			return stream_object_get_content(so);
	}
	return NULL;
}

BOOL attachment_object_get_properties(
	ATTACHMENT_OBJECT *pattachment, uint32_t size_limit,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	static const uint32_t err_code = ecError;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		auto &pv = ppropvals->ppropval[ppropvals->count];
		if (TRUE == attachment_object_get_calculated_property(
			pattachment, pproptags->pproptag[i], &pvalue)) {
			if (NULL != pvalue) {
				pv.proptag = pproptags->pproptag[i];
				pv.pvalue = pvalue;
			} else {
				pv.proptag = CHANGE_PROP_TYPE(pproptags->pproptag[i], PT_ERROR);
				pv.pvalue = deconst(&err_code);
			}
			ppropvals->count ++;
			continue;
		}
		pvalue = attachment_object_get_stream_property_value(
						pattachment, pproptags->pproptag[i]);
		if (NULL != pvalue) {
			pv.proptag = pproptags->pproptag[i];
			pv.pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] = pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_get_instance_properties(pattachment->pparent->plogon->get_dir(),
	    size_limit, pattachment->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

static BOOL attachment_object_check_stream_property(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag)
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pattachment->stream_list); NULL!=pnode;
		pnode=double_list_get_after(&pattachment->stream_list, pnode)) {
		if (stream_object_get_proptag(static_cast<STREAM_OBJECT *>(pnode->pdata)) == proptag)
			return TRUE;
	}
	return FALSE;
}

BOOL attachment_object_set_properties(ATTACHMENT_OBJECT *pattachment,
	const TPROPVAL_ARRAY *ppropvals, PROBLEM_ARRAY *pproblems)
{
	int i, j;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	uint16_t *poriginal_indices;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	poriginal_indices = cu_alloc<uint16_t>(ppropvals->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (TRUE == attachment_object_check_readonly_property(
			pattachment, ppropvals->ppropval[i].proptag) ||
			TRUE == attachment_object_check_stream_property(
			pattachment, ppropvals->ppropval[i].proptag)) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
							ppropvals->ppropval[i].proptag;
			pproblems->pproblem[pproblems->count].err = ecAccessDenied;
			pproblems->count ++;
			continue;
		}
		tmp_propvals.ppropval[tmp_propvals.count] =
								ppropvals->ppropval[i];
		poriginal_indices[tmp_propvals.count] = i;
		tmp_propvals.count ++;
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (!exmdb_client_set_instance_properties(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		pattachment->b_touched = TRUE;
		return TRUE;
	}
	for (i=0; i<tmp_problems.count; i++) {
		tmp_problems.pproblem[i].index =
			poriginal_indices[tmp_problems.pproblem[i].index];
	}
	memcpy(pproblems->pproblem + pproblems->count,
		tmp_problems.pproblem, tmp_problems.count*
		sizeof(PROPERTY_PROBLEM));
	pproblems->count += tmp_problems.count;
	qsort(pproblems->pproblem, pproblems->count,
		sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	for (i=0; i<ppropvals->count; i++) {
		for (j=0; j<pproblems->count; j++) {
			if (i == pproblems->pproblem[j].index) {
				break;
			}
		}
		if (j >= pproblems->count) {
			pattachment->b_touched = TRUE;
			break;
		}
	}
	return TRUE;
}

BOOL attachment_object_remove_properties(ATTACHMENT_OBJECT *pattachment,
	const PROPTAG_ARRAY *pproptags, PROBLEM_ARRAY *pproblems)
{
	int i, j;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	uint16_t *poriginal_indices;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (NULL == pproblems->pproblem) {
		return FALSE;
	}
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	poriginal_indices = cu_alloc<uint16_t>(pproptags->count);
	if (NULL == poriginal_indices) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == attachment_object_check_readonly_property(
			pattachment, pproptags->pproptag[i]) ||
			TRUE == attachment_object_check_stream_property(
			pattachment, pproptags->pproptag[i])) {
			pproblems->pproblem[pproblems->count].index = i;
			pproblems->pproblem[pproblems->count].proptag =
									pproptags->pproptag[i];
			pproblems->pproblem[pproblems->count].err = ecAccessDenied;
			pproblems->count ++;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
								pproptags->pproptag[i];
		poriginal_indices[tmp_proptags.count] = i;
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client_remove_instance_properties(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		pattachment->b_touched = TRUE;
		return TRUE;
	}
	for (i=0; i<tmp_problems.count; i++) {
		tmp_problems.pproblem[i].index =
			poriginal_indices[tmp_problems.pproblem[i].index];
	}
	memcpy(pproblems->pproblem + pproblems->count,
		tmp_problems.pproblem, tmp_problems.count*
		sizeof(PROPERTY_PROBLEM));
	pproblems->count += tmp_problems.count;
	qsort(pproblems->pproblem, pproblems->count,
		sizeof(PROPERTY_PROBLEM), common_util_problem_compare);
	for (i=0; i<pproptags->count; i++) {
		for (j=0; j<pproblems->count; j++) {
			if (i == pproblems->pproblem[j].index) {
				break;
			}
		}
		if (j >= pproblems->count) {
			pattachment->b_touched = TRUE;
			break;
		}
	}
	return TRUE;
}

BOOL attachment_object_copy_properties(
	ATTACHMENT_OBJECT *pattachment, ATTACHMENT_OBJECT *pattachment_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force,
	BOOL *pb_cycle, PROBLEM_ARRAY *pproblems)
{
	int i;
	ATTACHMENT_CONTENT attctnt;
	
	if (!exmdb_client_check_instance_cycle(pattachment->pparent->plogon->get_dir(),
	    pattachment_src->instance_id, pattachment->instance_id, pb_cycle))
		return FALSE;	
	if (TRUE == *pb_cycle) {
		return TRUE;
	}
	if (FALSE == attachment_object_flush_streams(pattachment_src)) {
		return FALSE;
	}
	if (!exmdb_client_read_attachment_instance(pattachment_src->pparent->plogon->get_dir(),
	    pattachment_src->instance_id, &attctnt))
		return FALSE;
	common_util_remove_propvals(&attctnt.proplist, PROP_TAG_ATTACHNUMBER);
	i = 0;
	while (i < attctnt.proplist.count) {
		if (common_util_index_proptags(pexcluded_proptags,
			attctnt.proplist.ppropval[i].proptag) >= 0) {
			common_util_remove_propvals(&attctnt.proplist,
					attctnt.proplist.ppropval[i].proptag);
			continue;
		}
		i ++;
	}
	if (common_util_index_proptags(pexcluded_proptags, PR_ATTACH_DATA_OBJ) >= 0)
		attctnt.pembedded = NULL;
	if (!exmdb_client_write_attachment_instance(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &attctnt, b_force, pproblems))
		return FALSE;	
	pattachment->b_touched = TRUE;
	return TRUE;
}

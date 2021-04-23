// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include "attachment_object.h"
#include <gromox/proptag_array.hpp>
#include "exmdb_client.h"
#include "store_object.h"
#include "common_util.h"
#include <gromox/rop_util.hpp>
#include <cstdlib>
#include <cstring>

std::unique_ptr<ATTACHMENT_OBJECT> attachment_object_create(
	MESSAGE_OBJECT *pparent, uint32_t attachment_num)
{
	std::unique_ptr<ATTACHMENT_OBJECT> pattachment;
	try {
		pattachment = std::make_unique<ATTACHMENT_OBJECT>();
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pattachment->pparent = pparent;
	pattachment->b_writable = pparent->b_writable;
	if (ATTACHMENT_NUM_INVALID == attachment_num) {
		if (!exmdb_client::create_attachment_instance(
			store_object_get_dir(pparent->pstore), pparent->instance_id,
			&pattachment->instance_id, &pattachment->attachment_num)) {
			return NULL;
		}
		if (0 == pattachment->instance_id &&
			ATTACHMENT_NUM_INVALID != pattachment->attachment_num) {
			return NULL;	
		}
		pattachment->b_new = TRUE;
	} else {
		if (!exmdb_client::load_attachment_instance(
			store_object_get_dir(pparent->pstore),
			pparent->instance_id, attachment_num,
			&pattachment->instance_id)) {
			return NULL;
		}
		pattachment->attachment_num = attachment_num;
	}
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

BOOL attachment_object_init_attachment(ATTACHMENT_OBJECT *pattachment)
{
	void *pvalue;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	if (!pattachment->b_new)
		return FALSE;
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5);
	if (NULL == propvals.ppropval) {
		return FALSE;
	}
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_ATTACHNUMBER;
	propvals.ppropval[propvals.count].pvalue =
					&pattachment->attachment_num;
	propvals.count ++;
	
	propvals.ppropval[propvals.count].proptag =
					PROP_TAG_RENDERINGPOSITION;
	propvals.ppropval[propvals.count].pvalue = cu_alloc<uint32_t>();
	if (NULL == propvals.ppropval[propvals.count].pvalue) {
		return FALSE;
	}
	*(uint32_t*)propvals.ppropval[propvals.count].pvalue =
												0xFFFFFFFF;
	propvals.count ++;
	
	pvalue = cu_alloc<uint64_t>();
	if (NULL == pvalue) {
		return FALSE;
	}
	*(uint64_t*)pvalue = rop_util_current_nttime();
	
	propvals.ppropval[propvals.count].proptag =
							PROP_TAG_CREATIONTIME;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	propvals.ppropval[propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	propvals.ppropval[propvals.count].pvalue = pvalue;
	propvals.count ++;
	
	return exmdb_client::set_instance_properties(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment->instance_id, &propvals, &problems);
}

ATTACHMENT_OBJECT::~ATTACHMENT_OBJECT()
{
	auto pattachment = this;
	if (0 != pattachment->instance_id) {
		exmdb_client::unload_instance(
			store_object_get_dir(
			pattachment->pparent->pstore),
			pattachment->instance_id);
	}
}

uint32_t attachment_object_get_tag_access(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->pparent->tag_access;
}

gxerr_t attachment_object_save(ATTACHMENT_OBJECT *pattachment)
{
	uint64_t nt_time;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (FALSE == pattachment->b_writable ||
		FALSE == pattachment->b_touched) {
		return GXERR_SUCCESS;
	}
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = &tmp_propval;
	tmp_propval.proptag = PR_LAST_MODIFICATION_TIME;
	nt_time = rop_util_current_nttime();
	tmp_propval.pvalue = &nt_time;
	if (FALSE == attachment_object_set_properties(
		pattachment, &tmp_propvals)) {
		return GXERR_CALL_FAILED;
	}
	gxerr_t e_result = GXERR_CALL_FAILED;
	if (!exmdb_client::flush_instance(store_object_get_dir(pattachment->pparent->pstore),
	    pattachment->instance_id, nullptr, &e_result) || e_result != GXERR_SUCCESS)
		return e_result;
	pattachment->b_new = FALSE;
	pattachment->b_touched = FALSE;
	pattachment->pparent->b_touched = TRUE;
	proptag_array_append(pattachment->pparent->pchanged_proptags,
									PROP_TAG_MESSAGEATTACHMENTS);
	return GXERR_SUCCESS;
}

BOOL attachment_object_get_all_proptags(
	ATTACHMENT_OBJECT *pattachment, PROPTAG_ARRAY *pproptags)
{
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_instance_all_proptags(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment->instance_id, &tmp_proptags)) {
		return FALSE;	
	}
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 5);
	if (NULL == pproptags->pproptag) {
		return FALSE;
	}
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESS;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_ACCESSLEVEL;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PR_OBJECT_TYPE;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STORERECORDKEY;
	pproptags->count ++;
	pproptags->pproptag[pproptags->count] = PROP_TAG_STOREENTRYID;
	pproptags->count ++;
	return TRUE;
}

static BOOL attachment_object_check_readonly_property(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT && proptag != PR_ATTACH_DATA_OBJ)
		return TRUE;
	switch (proptag) {
	case PROP_TAG_MID:
	case PROP_TAG_ACCESSLEVEL:
	case PROP_TAG_INCONFLICT:
	case PR_OBJECT_TYPE:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_STOREENTRYID:
	case PROP_TAG_STORERECORDKEY:
		return TRUE;
	case PROP_TAG_ATTACHSIZE:
	case PROP_TAG_CREATIONTIME:
	case PR_LAST_MODIFICATION_TIME:
		if (pattachment->b_new)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

static BOOL attachment_object_get_calculated_property(
	ATTACHMENT_OBJECT *pattachment, uint32_t proptag,
	void **ppvalue)
{
	switch (proptag) {
	case PROP_TAG_ACCESS:
		*ppvalue = &pattachment->pparent->tag_access;
		return TRUE;
	case PROP_TAG_ACCESSLEVEL:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*static_cast<uint32_t *>(*ppvalue) = pattachment->b_writable ?
			ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	case PR_OBJECT_TYPE:
		*ppvalue = cu_alloc<uint32_t>();
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)(*ppvalue) = OBJECT_ATTACHMENT;
		return TRUE;
	case PROP_TAG_STORERECORDKEY:
		*ppvalue = common_util_guid_to_binary(
					store_object_get_mailbox_guid(
					pattachment->pparent->pstore));
		return TRUE;
	case PROP_TAG_STOREENTRYID:
		*ppvalue = common_util_to_store_entryid(
					pattachment->pparent->pstore);
		if (NULL == *ppvalue) {
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

BOOL attachment_object_get_properties(ATTACHMENT_OBJECT *pattachment,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
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
		if (TRUE == attachment_object_get_calculated_property(
			pattachment, pproptags->pproptag[i], &pvalue)) {
			if (NULL == pvalue) {
				return FALSE;
			}
			ppropvals->ppropval[ppropvals->count].proptag =
										pproptags->pproptag[i];
			ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
			ppropvals->count ++;
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] = pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client::get_instance_properties(
		store_object_get_dir(pattachment->pparent->pstore),
		0, pattachment->instance_id, &tmp_proptags,
		&tmp_propvals)) {
		return FALSE;	
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

BOOL attachment_object_set_properties(ATTACHMENT_OBJECT *pattachment,
	const TPROPVAL_ARRAY *ppropvals)
{
	int i;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (NULL == tmp_propvals.ppropval) {
		return FALSE;
	}
	for (i=0; i<ppropvals->count; i++) {
		if (TRUE == attachment_object_check_readonly_property(
			pattachment, ppropvals->ppropval[i].proptag)) {
			continue;
		}
		tmp_propvals.ppropval[tmp_propvals.count] =
							ppropvals->ppropval[i];
		tmp_propvals.count ++;
	}
	if (0 == tmp_propvals.count) {
		return TRUE;
	}
	if (!exmdb_client::set_instance_properties(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment->instance_id, &tmp_propvals, &tmp_problems)) {
		return FALSE;	
	}
	if (tmp_problems.count < tmp_propvals.count) {
		pattachment->b_touched = TRUE;
	}
	return TRUE;
}

BOOL attachment_object_remove_properties(ATTACHMENT_OBJECT *pattachment,
	const PROPTAG_ARRAY *pproptags)
{
	int i;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (NULL == tmp_proptags.pproptag) {
		return FALSE;
	}
	for (i=0; i<pproptags->count; i++) {
		if (TRUE == attachment_object_check_readonly_property(
			pattachment, pproptags->pproptag[i])) {
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count] =
								pproptags->pproptag[i];
		tmp_proptags.count ++;
	}
	if (0 == tmp_proptags.count) {
		return TRUE;
	}
	if (!exmdb_client::remove_instance_properties(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment->instance_id, &tmp_proptags,
		&tmp_problems)) {
		return FALSE;	
	}
	if (tmp_problems.count < tmp_proptags.count) {
		pattachment->b_touched = TRUE;
	}
	return TRUE;
}

BOOL attachment_object_copy_properties(
	ATTACHMENT_OBJECT *pattachment, ATTACHMENT_OBJECT *pattachment_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force, BOOL *pb_cycle)
{
	int i;
	PROBLEM_ARRAY tmp_problems;
	ATTACHMENT_CONTENT attctnt;
	
	if (!exmdb_client::check_instance_cycle(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment_src->instance_id, pattachment->instance_id,
		pb_cycle)) {
		return FALSE;	
	}
	if (*pb_cycle)
		return TRUE;
	if (!exmdb_client::read_attachment_instance(
		store_object_get_dir(pattachment_src->pparent->pstore),
		pattachment_src->instance_id, &attctnt)) {
		return FALSE;
	}
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
	if (!exmdb_client::write_attachment_instance(
		store_object_get_dir(pattachment->pparent->pstore),
		pattachment->instance_id, &attctnt, b_force,
		&tmp_problems)) {
		return FALSE;	
	}
	pattachment->b_touched = TRUE;
	return TRUE;
}

STORE_OBJECT* attachment_object_get_store(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->pparent->pstore;
}

BOOL attachment_object_check_writable(ATTACHMENT_OBJECT *pattachment)
{
	return pattachment->b_writable;
}

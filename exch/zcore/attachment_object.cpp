// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <climits>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "exmdb_client.h"
#include "objects.hpp"
#include "store_object.h"

static constexpr uint32_t indet_rendering_pos = UINT32_MAX;

std::unique_ptr<attachment_object> attachment_object::create(message_object *pparent, uint32_t attachment_num)
{
	std::unique_ptr<attachment_object> pattachment;
	try {
		pattachment.reset(new attachment_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pattachment->pparent = pparent;
	pattachment->b_writable = pparent->b_writable;
	if (ATTACHMENT_NUM_INVALID == attachment_num) {
		if (!exmdb_client::create_attachment_instance(pparent->pstore->get_dir(),
		    pparent->instance_id, &pattachment->instance_id,
		    &pattachment->attachment_num))
			return NULL;
		if (0 == pattachment->instance_id &&
		    pattachment->attachment_num != ATTACHMENT_NUM_INVALID)
			return NULL;	
		pattachment->b_new = TRUE;
	} else {
		if (!exmdb_client::load_attachment_instance(pparent->pstore->get_dir(),
		    pparent->instance_id, attachment_num, &pattachment->instance_id))
			return NULL;
		pattachment->attachment_num = attachment_num;
	}
	return pattachment;
}

BOOL attachment_object::init_attachment()
{
	auto pattachment = this;
	void *pvalue;
	PROBLEM_ARRAY problems;
	TPROPVAL_ARRAY propvals;
	
	if (!pattachment->b_new)
		return FALSE;
	propvals.count = 0;
	propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(5);
	if (propvals.ppropval == nullptr)
		return FALSE;
	
	propvals.ppropval[propvals.count].proptag = PR_ATTACH_NUM;
	propvals.ppropval[propvals.count++].pvalue = &pattachment->attachment_num;
	propvals.ppropval[propvals.count].proptag = PR_RENDERING_POSITION;
	propvals.ppropval[propvals.count].pvalue = cu_alloc<uint32_t>();
	if (propvals.ppropval[propvals.count].pvalue == nullptr)
		return FALSE;
	*static_cast<uint32_t *>(propvals.ppropval[propvals.count++].pvalue) = indet_rendering_pos;
	pvalue = cu_alloc<uint64_t>();
	if (pvalue == nullptr)
		return FALSE;
	*static_cast<uint64_t *>(pvalue) = rop_util_current_nttime();
	
	propvals.ppropval[propvals.count].proptag = PR_CREATION_TIME;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	propvals.ppropval[propvals.count].proptag = PR_LAST_MODIFICATION_TIME;
	propvals.ppropval[propvals.count++].pvalue = pvalue;
	return exmdb_client::set_instance_properties(pattachment->pparent->pstore->get_dir(),
	       pattachment->instance_id, &propvals, &problems);
}

attachment_object::~attachment_object()
{
	auto pattachment = this;
	if (instance_id != 0)
		exmdb_client::unload_instance(pattachment->pparent->pstore->get_dir(),
			pattachment->instance_id);
}

ec_error_t attachment_object::save()
{
	auto pattachment = this;
	uint64_t nt_time;
	TAGGED_PROPVAL tmp_propval;
	TPROPVAL_ARRAY tmp_propvals;
	
	if (!pattachment->b_writable || !pattachment->b_touched)
		return ecSuccess;
	tmp_propvals.count = 1;
	tmp_propvals.ppropval = &tmp_propval;
	tmp_propval.proptag = PR_LAST_MODIFICATION_TIME;
	nt_time = rop_util_current_nttime();
	tmp_propval.pvalue = &nt_time;
	if (!set_properties(&tmp_propvals))
		return ecError;
	ec_error_t e_result = ecError;
	if (!exmdb_client::flush_instance(pattachment->pparent->pstore->get_dir(),
	    pattachment->instance_id, nullptr, &e_result) || e_result != ecSuccess)
		return e_result;
	pattachment->b_new = FALSE;
	pattachment->b_touched = FALSE;
	pattachment->pparent->b_touched = TRUE;
	proptag_array_append(pattachment->pparent->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return ecSuccess;
}

BOOL attachment_object::get_all_proptags(PROPTAG_ARRAY *pproptags)
{
	auto pattachment = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client::get_instance_all_proptags(pattachment->pparent->pstore->get_dir(),
	    pattachment->instance_id, &tmp_proptags))
		return FALSE;	
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + 5);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	pproptags->pproptag[pproptags->count++] = PR_ACCESS;
	pproptags->pproptag[pproptags->count++] = PR_ACCESS_LEVEL;
	pproptags->pproptag[pproptags->count++] = PR_OBJECT_TYPE;
	pproptags->pproptag[pproptags->count++] = PR_STORE_RECORD_KEY;
	pproptags->pproptag[pproptags->count++] = PR_STORE_ENTRYID;
	return TRUE;
}

static BOOL aobj_is_readonly_prop(const attachment_object *pattachment,
    uint32_t proptag)
{
	if (PROP_TYPE(proptag) == PT_OBJECT && proptag != PR_ATTACH_DATA_OBJ)
		return TRUE;
	switch (proptag) {
	case PidTagMid:
	case PR_ACCESS_LEVEL:
	case PR_IN_CONFLICT:
	case PR_OBJECT_TYPE:
	case PR_RECORD_KEY:
	case PR_STORE_ENTRYID:
	case PR_STORE_RECORD_KEY:
		return TRUE;
	case PR_ATTACH_SIZE:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
		if (pattachment->b_new)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

static BOOL attachment_object_get_calculated_property(attachment_object *pattachment,
     uint32_t proptag, void **ppvalue)
{
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = &pattachment->pparent->tag_access;
		return TRUE;
	case PR_ACCESS_LEVEL:
		*ppvalue = cu_alloc<uint32_t>();
		if (*ppvalue == nullptr)
			return FALSE;
		*static_cast<uint32_t *>(*ppvalue) = pattachment->b_writable ?
			ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_ATTACH);
		return TRUE;
	}
	case PR_STORE_RECORD_KEY:
		*ppvalue = common_util_guid_to_binary(pattachment->pparent->pstore->mailbox_guid);
		return TRUE;
	case PR_STORE_ENTRYID:
		*ppvalue = common_util_to_store_entryid(
					pattachment->pparent->pstore);
		if (*ppvalue == nullptr)
			return FALSE;
		return TRUE;
	}
	return FALSE;
}

BOOL attachment_object::get_properties(const PROPTAG_ARRAY *pproptags,
    TPROPVAL_ARRAY *ppropvals)
{
	auto pattachment = this;
	PROPTAG_ARRAY tmp_proptags;
	TPROPVAL_ARRAY tmp_propvals;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (attachment_object_get_calculated_property(pattachment, tag, &pvalue)) {
			if (pvalue == nullptr)
				return FALSE;
			ppropvals->emplace_back(tag, pvalue);
			continue;
		}
		tmp_proptags.pproptag[tmp_proptags.count++] = tag;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client::get_instance_properties(pattachment->pparent->pstore->get_dir(),
	    0, pattachment->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count == 0)
		return TRUE;
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

BOOL attachment_object::set_properties(const TPROPVAL_ARRAY *ppropvals)
{
	auto pattachment = this;
	PROBLEM_ARRAY tmp_problems;
	TPROPVAL_ARRAY tmp_propvals;
	
	tmp_propvals.count = 0;
	tmp_propvals.ppropval = cu_alloc<TAGGED_PROPVAL>(ppropvals->count);
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (aobj_is_readonly_prop(pattachment, pv.proptag))
			continue;
		tmp_propvals.ppropval[tmp_propvals.count++] = pv;
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	if (!exmdb_client::set_instance_properties(pattachment->pparent->pstore->get_dir(),
	    pattachment->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count < tmp_propvals.count)
		pattachment->b_touched = TRUE;
	return TRUE;
}

BOOL attachment_object::remove_properties(const PROPTAG_ARRAY *pproptags)
{
	auto pattachment = this;
	PROBLEM_ARRAY tmp_problems;
	PROPTAG_ARRAY tmp_proptags;
	
	tmp_proptags.count = 0;
	tmp_proptags.pproptag = cu_alloc<uint32_t>(pproptags->count);
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (aobj_is_readonly_prop(pattachment, tag))
			continue;
		tmp_proptags.pproptag[tmp_proptags.count++] = tag;
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	if (!exmdb_client::remove_instance_properties(pattachment->pparent->pstore->get_dir(),
	    pattachment->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (tmp_problems.count < tmp_proptags.count)
		pattachment->b_touched = TRUE;
	return TRUE;
}

BOOL attachment_object::copy_properties(attachment_object *pattachment_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force, BOOL *pb_cycle)
{
	auto pattachment = this;
	int i;
	PROBLEM_ARRAY tmp_problems;
	ATTACHMENT_CONTENT attctnt;
	
	if (!exmdb_client::check_instance_cycle(pattachment->pparent->pstore->get_dir(),
	    pattachment_src->instance_id, pattachment->instance_id, pb_cycle))
		return FALSE;	
	if (*pb_cycle)
		return TRUE;
	if (!exmdb_client::read_attachment_instance(pattachment_src->pparent->pstore->get_dir(),
	    pattachment_src->instance_id, &attctnt))
		return FALSE;
	common_util_remove_propvals(&attctnt.proplist, PR_ATTACH_NUM);
	i = 0;
	while (i < attctnt.proplist.count) {
		if (pexcluded_proptags->has(attctnt.proplist.ppropval[i].proptag)) {
			common_util_remove_propvals(&attctnt.proplist,
					attctnt.proplist.ppropval[i].proptag);
			continue;
		}
		i ++;
	}
	if (pexcluded_proptags->has(PR_ATTACH_DATA_OBJ))
		attctnt.pembedded = NULL;
	if (!exmdb_client::write_attachment_instance(pattachment->pparent->pstore->get_dir(),
	    pattachment->instance_id, &attctnt, b_force, &tmp_problems))
		return FALSE;	
	pattachment->b_touched = TRUE;
	return TRUE;
}

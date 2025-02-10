// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2024 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/rop_util.hpp>
#include "attachment_object.hpp"
#include "common_util.hpp"
#include "exmdb_client.hpp"
#include "logon_object.hpp"
#include "message_object.hpp"
#include "stream_object.hpp"

using namespace gromox;

static constexpr uint32_t indet_rendering_pos = UINT32_MAX;

std::unique_ptr<attachment_object> attachment_object::create(message_object *pparent,
	uint32_t attachment_num, uint8_t open_flags)
{
	std::unique_ptr<attachment_object> pattachment;
	try {
		pattachment.reset(new attachment_object);
	} catch (const std::bad_alloc &) {
		return NULL;
	}
	pattachment->pparent = pparent;
	pattachment->open_flags = open_flags;
	auto dir = pparent->plogon->get_dir();
	if (ATTACHMENT_NUM_INVALID == attachment_num) {
		if (!exmdb_client->create_attachment_instance(dir,
		    pparent->instance_id, &pattachment->instance_id,
		    &pattachment->attachment_num))
			return NULL;
		if (pattachment->instance_id == 0 &&
		    pattachment->attachment_num != ATTACHMENT_NUM_INVALID)
			return NULL;	
		pattachment->b_new = TRUE;
	} else {
		if (!exmdb_client->load_attachment_instance(dir,
		    pparent->instance_id, attachment_num, &pattachment->instance_id))
			return NULL;
		pattachment->attachment_num = attachment_num;
	}
	return pattachment;
}

BOOL attachment_object::init_attachment()
{
	auto pattachment = this;
	if (!pattachment->b_new)
		return FALSE;
	uint32_t rendpos = indet_rendering_pos;
	auto modtime = rop_util_current_nttime();
	const TAGGED_PROPVAL propbuf[] = {
		{PR_ATTACH_NUM, &pattachment->attachment_num},
		{PR_RENDERING_POSITION, &rendpos},
		{PR_CREATION_TIME, &modtime},
		{PR_LAST_MODIFICATION_TIME, &modtime},
	};
	const TPROPVAL_ARRAY propvals = {std::size(propbuf), deconst(propbuf)};
	PROBLEM_ARRAY problems;
	return exmdb_client->set_instance_properties(pattachment->pparent->plogon->get_dir(),
	       pattachment->instance_id, &propvals, &problems);
}

attachment_object::~attachment_object()
{
	auto pattachment = this;
	if (pattachment->instance_id != 0)
		exmdb_client->unload_instance(pattachment->pparent->plogon->get_dir(),
			pattachment->instance_id);
}

void attachment_object::set_open_flags(uint8_t f)
{
	open_flags = f;
}

ec_error_t attachment_object::save()
{
	auto pattachment = this;
	
	if (!b_touched && !b_new)
		return ecSuccess;
	if (!flush_streams())
		return ecRpcFailed;

	auto nt_time = rop_util_current_nttime();
	const TAGGED_PROPVAL propbuf[] = {{PR_LAST_MODIFICATION_TIME, &nt_time}};
	const TPROPVAL_ARRAY tmp_propvals = {std::size(propbuf), deconst(propbuf)};
	PROBLEM_ARRAY tmp_problems;
	if (!set_properties(&tmp_propvals, &tmp_problems))
		return ecRpcFailed;

	ec_error_t e_result = ecRpcFailed;
	if (!exmdb_client->flush_instance(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &e_result) || e_result != ecSuccess)
		return e_result;
	pattachment->b_new = FALSE;
	pattachment->b_touched = FALSE;
	pattachment->pparent->b_touched = TRUE;
	proptag_array_append(pattachment->pparent->pchanged_proptags, PR_MESSAGE_ATTACHMENTS);
	return ecSuccess;
}

BOOL attachment_object::append_stream_object(stream_object *pstream) try
{
	auto pattachment = this;
	for (auto so : stream_list)
		if (so == pstream)
			return TRUE;
	stream_list.push_back(pstream);
	pattachment->b_touched = TRUE;
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

/* called when stream object is released */
BOOL attachment_object::commit_stream_object(stream_object *pstream)
{
	auto pattachment = this;
	uint32_t result;
	TAGGED_PROPVAL tmp_propval;

	for (auto it = stream_list.begin(); it != stream_list.end(); ) {
		if (*it != pstream) {
			++it;
			continue;
		}
		it = stream_list.erase(it);
		tmp_propval.proptag = pstream->get_proptag();
		tmp_propval.pvalue  = deconst(pstream->get_content());
		return exmdb_client->set_instance_property(pattachment->pparent->plogon->get_dir(),
		       pattachment->instance_id, &tmp_propval, &result) ? TRUE : false;
	}
	return TRUE;
}

BOOL attachment_object::flush_streams()
{
	auto pattachment = this;
	uint32_t result;
	TAGGED_PROPVAL tmp_propval;
	
	while (stream_list.size() > 0) {
		auto pstream = stream_list.front();
		tmp_propval.proptag = pstream->get_proptag();
		tmp_propval.pvalue  = deconst(pstream->get_content());
		if (!exmdb_client->set_instance_property(pattachment->pparent->plogon->get_dir(),
		    pattachment->instance_id, &tmp_propval, &result))
			return FALSE;
		stream_list.erase(stream_list.begin());
	}
	return TRUE;
	
}

BOOL attachment_object::get_all_proptags(PROPTAG_ARRAY *pproptags) const
{
	auto pattachment = this;
	PROPTAG_ARRAY tmp_proptags;
	
	if (!exmdb_client->get_instance_all_proptags(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_proptags))
		return FALSE;	
	auto nodes_num = stream_list.size() + 1;
	pproptags->count = tmp_proptags.count;
	pproptags->pproptag = cu_alloc<uint32_t>(tmp_proptags.count + nodes_num);
	if (pproptags->pproptag == nullptr)
		return FALSE;
	memcpy(pproptags->pproptag, tmp_proptags.pproptag,
				sizeof(uint32_t)*tmp_proptags.count);
	for (auto so : stream_list) {
		auto proptag = so->get_proptag();
		if (!pproptags->has(proptag))
			pproptags->emplace_back(proptag);
	}
	pproptags->emplace_back(PR_ACCESS_LEVEL);
	return TRUE;
}

bool attachment_object::is_readonly_prop(uint32_t proptag) const
{
	auto pattachment = this;
	if (PROP_TYPE(proptag) == PT_OBJECT && proptag != PR_ATTACH_DATA_OBJ)
		return true;
	switch (proptag) {
	case PidTagMid:
	case PR_ACCESS_LEVEL:
	case PR_IN_CONFLICT:
	case PR_OBJECT_TYPE:
	case PR_RECORD_KEY:
	case PR_STORE_ENTRYID:
	case PR_STORE_RECORD_KEY:
		return true;
	case PR_ATTACH_SIZE:
	case PR_CREATION_TIME:
	case PR_LAST_MODIFICATION_TIME:
		return !pattachment->b_new;
	}
	return FALSE;
}

static BOOL attachment_object_get_calculated_property(const attachment_object *pattachment,
    uint32_t proptag, void **ppvalue)
{
	switch (proptag) {
	case PR_ACCESS:
		*ppvalue = deconst(&pattachment->pparent->tag_access);
		return TRUE;
	case PR_ACCESS_LEVEL: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (*ppvalue == nullptr)
			return FALSE;
		*v = (pattachment->open_flags & MAPI_MODIFY) ?
		     ACCESS_LEVEL_MODIFY : ACCESS_LEVEL_READ_ONLY;
		return TRUE;
	}
	case PR_OBJECT_TYPE: {
		auto v = cu_alloc<uint32_t>();
		*ppvalue = v;
		if (v == nullptr)
			return FALSE;
		*v = static_cast<uint32_t>(MAPI_ATTACH);
		return TRUE;
	}
	case PR_STORE_RECORD_KEY:
		*ppvalue = common_util_guid_to_binary(pattachment->pparent->plogon->mailbox_guid);
		return TRUE;
	}
	return FALSE;
}

static const void *attachment_object_get_stream_property_value(const attachment_object *at,
    uint32_t proptag)
{
	for (auto so : at->stream_list)
		if (so->get_proptag() == proptag)
			return so->get_content();
	return NULL;
}

BOOL attachment_object::get_properties(uint32_t size_limit,
    const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals) const
{
	auto pattachment = this;
	static const uint32_t err_code = ecError;
	
	ppropvals->ppropval = cu_alloc<TAGGED_PROPVAL>(pproptags->count);
	if (ppropvals->ppropval == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	ppropvals->count = 0;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		void *pvalue = nullptr;
		const auto tag = pproptags->pproptag[i];
		if (attachment_object_get_calculated_property(pattachment, tag, &pvalue)) {
			if (pvalue != nullptr)
				ppropvals->emplace_back(tag, pvalue);
			else
				ppropvals->emplace_back(CHANGE_PROP_TYPE(tag, PT_ERROR), &err_code);
			continue;
		}
		pvalue = deconst(attachment_object_get_stream_property_value(pattachment, tag));
		if (NULL != pvalue) {
			ppropvals->emplace_back(tag, pvalue);
			continue;
		}
		tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	TPROPVAL_ARRAY tmp_propvals;
	if (!exmdb_client->get_instance_properties(pattachment->pparent->plogon->get_dir(),
	    size_limit, pattachment->instance_id, &tmp_proptags, &tmp_propvals))
		return FALSE;	
	if (tmp_propvals.count == 0)
		return TRUE;
	memcpy(ppropvals->ppropval + ppropvals->count,
		tmp_propvals.ppropval,
		sizeof(TAGGED_PROPVAL)*tmp_propvals.count);
	ppropvals->count += tmp_propvals.count;
	return TRUE;	
}

static bool ao_has_open_streams(attachment_object *at, uint32_t proptag)
{
	for (auto so : at->stream_list)
		if (so->get_proptag() == proptag)
			return true;
	return false;
}

BOOL attachment_object::set_properties(const TPROPVAL_ARRAY *ppropvals,
    PROBLEM_ARRAY *pproblems) try
{
	auto pattachment = this;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(ppropvals->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	TPROPVAL_ARRAY tmp_propvals = {0, cu_alloc<TAGGED_PROPVAL>(ppropvals->count)};
	if (tmp_propvals.ppropval == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		const auto &pv = ppropvals->ppropval[i];
		if (is_readonly_prop(pv.proptag) ||
		    ao_has_open_streams(pattachment, pv.proptag)) {
			pproblems->emplace_back(i, pv.proptag, ecAccessDenied);
			continue;
		}
		tmp_propvals.ppropval[tmp_propvals.count++] = pv;
		poriginal_indices.push_back(i);
	}
	if (tmp_propvals.count == 0)
		return TRUE;
	PROBLEM_ARRAY tmp_problems;
	if (!exmdb_client->set_instance_properties(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_propvals, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		pattachment->b_touched = TRUE;
		return TRUE;
	}
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	for (unsigned int i = 0; i < ppropvals->count; ++i) {
		if (!pproblems->have_index(i)) {
			pattachment->b_touched = TRUE;
			break;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1669: ENOMEM");
	return false;
}

BOOL attachment_object::remove_properties(const PROPTAG_ARRAY *pproptags,
    PROBLEM_ARRAY *pproblems) try
{
	auto pattachment = this;
	
	pproblems->count = 0;
	pproblems->pproblem = cu_alloc<PROPERTY_PROBLEM>(pproptags->count);
	if (pproblems->pproblem == nullptr)
		return FALSE;
	PROPTAG_ARRAY tmp_proptags = {0, cu_alloc<uint32_t>(pproptags->count)};
	if (tmp_proptags.pproptag == nullptr)
		return FALSE;
	std::vector<uint16_t> poriginal_indices;
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		const auto tag = pproptags->pproptag[i];
		if (is_readonly_prop(tag) ||
		    ao_has_open_streams(pattachment, tag)) {
			pproblems->emplace_back(i, tag, ecAccessDenied);
			continue;
		}
		poriginal_indices.push_back(i);
		tmp_proptags.emplace_back(tag);
	}
	if (tmp_proptags.count == 0)
		return TRUE;
	PROBLEM_ARRAY tmp_problems;
	if (!exmdb_client->remove_instance_properties(pattachment->pparent->plogon->get_dir(),
	    pattachment->instance_id, &tmp_proptags, &tmp_problems))
		return FALSE;	
	if (0 == tmp_problems.count) {
		pattachment->b_touched = TRUE;
		return TRUE;
	}
	tmp_problems.transform(poriginal_indices);
	*pproblems += std::move(tmp_problems);
	for (unsigned int i = 0; i < pproptags->count; ++i) {
		if (!pproblems->have_index(i)) {
			pattachment->b_touched = TRUE;
			break;
		}
	}
	return TRUE;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1670: ENOMEM");
	return false;
}

BOOL attachment_object::copy_properties(attachment_object *pattachment_src,
	const PROPTAG_ARRAY *pexcluded_proptags, BOOL b_force,
	BOOL *pb_cycle, PROBLEM_ARRAY *pproblems)
{
	auto pattachment = this;
	int i;
	ATTACHMENT_CONTENT attctnt;
	
	auto dstdir = pparent->plogon->get_dir();
	if (!exmdb_client->is_descendant_instance(dstdir,
	    pattachment_src->instance_id, pattachment->instance_id, pb_cycle))
		return FALSE;	
	if (*pb_cycle)
		return TRUE;
	if (!pattachment_src->flush_streams())
		return FALSE;
	if (!exmdb_client->read_attachment_instance(pattachment_src->pparent->plogon->get_dir(),
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
	if (!exmdb_client->write_attachment_instance(dstdir,
	    pattachment->instance_id, &attctnt, b_force, pproblems))
		return FALSE;	
	pattachment->b_touched = TRUE;
	return TRUE;
}

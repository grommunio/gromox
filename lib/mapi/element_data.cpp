// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <gromox/eid_array.hpp>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/propval.hpp>

using namespace gromox;

ATTACHMENT_CONTENT* attachment_content_init()
{
	auto pattachment = me_alloc<ATTACHMENT_CONTENT>();
	if (NULL == pattachment) {
		return NULL;
	}
	if (!tpropval_array_init_internal(&pattachment->proplist)) {
		free(pattachment);
		return NULL;
	}
	pattachment->pembedded = NULL;
	return pattachment;
}

void attachment_content_set_embedded_internal(ATTACHMENT_CONTENT *pattachment,
    MESSAGE_CONTENT *pembedded)
{
	if (NULL != pattachment->pembedded) {
		message_content_free(pattachment->pembedded);
	}
	pattachment->pembedded = pembedded;
}

void attachment_content_free(ATTACHMENT_CONTENT *pattachment)
{
	if (NULL != pattachment->pembedded) {
		message_content_free(pattachment->pembedded);
	}
	tpropval_array_free_internal(&pattachment->proplist);
	free(pattachment);
}

ATTACHMENT_CONTENT* attachment_content_dup(
	ATTACHMENT_CONTENT *pattachment)
{
	int i;
	ATTACHMENT_CONTENT *pattachment1;
	
	pattachment1 = attachment_content_init();
	if (NULL == pattachment1) {
		return NULL;
	}
	for (i=0; i<pattachment->proplist.count; i++) {
		if (pattachment1->proplist.set(pattachment->proplist.ppropval[i]) != 0) {
			attachment_content_free(pattachment1);
			return NULL;
		}
	}
	if (NULL != pattachment->pembedded) {
		pattachment1->pembedded =
			message_content_dup(pattachment->pembedded);
		if (NULL == pattachment1->pembedded) {
			attachment_content_free(pattachment1);
			return NULL;
		}
	}
	return pattachment1;
}

ATTACHMENT_LIST* attachment_list_init()
{
	auto plist = me_alloc<ATTACHMENT_LIST>();
	if (NULL == plist) {
		return NULL;
	}
	plist->count = 0;
	auto count = strange_roundup(plist->count, SR_GROW_ATTACHMENT_CONTENT);
	plist->pplist = me_alloc<ATTACHMENT_CONTENT *>(count);
	if (NULL == plist->pplist) {
		free(plist);
		return NULL;
	}
	return plist;
}

void attachment_list_free(ATTACHMENT_LIST *plist)
{
	int i;
	
	for (i=0; i<plist->count; i++) {
		attachment_content_free(plist->pplist[i]);
	}
	free(plist->pplist);
	free(plist);
}

void attachment_list_remove(ATTACHMENT_LIST *plist, uint16_t index)
{
	ATTACHMENT_CONTENT *pattachment;
	
	if (index >= plist->count) {
		return;
	}
	pattachment = plist->pplist[index];
	plist->count --;
	if (index != plist->count) {
		memmove(plist->pplist + index, plist->pplist +
			index + 1, sizeof(void*)*(plist->count - index));
	}
	attachment_content_free(pattachment);
}

BOOL attachment_list_append_internal(ATTACHMENT_LIST *plist,
	ATTACHMENT_CONTENT *pattachment)
{
	if (plist->count >= 0x8000) {
		return FALSE;
	}
	auto count = strange_roundup(plist->count, SR_GROW_ATTACHMENT_CONTENT);
	if (plist->count + 1U >= count) {
		count += SR_GROW_ATTACHMENT_CONTENT;
		auto pplist = re_alloc<ATTACHMENT_CONTENT *>(plist->pplist, count);
		if (NULL == pplist) {
			return FALSE;
		}
		plist->pplist = pplist;
	}
	plist->pplist[plist->count++] = pattachment;
	return TRUE;
}

ATTACHMENT_LIST* attachment_list_dup(ATTACHMENT_LIST *plist)
{
	int i;
	ATTACHMENT_LIST *plist1;
	ATTACHMENT_CONTENT *pattachment;
	
	plist1 = attachment_list_init();
	if (NULL == plist1) {
		return NULL;
	}
	for (i=0; i<plist->count; i++) {
		pattachment = attachment_content_dup(plist->pplist[i]);
		if (NULL == pattachment) {
			attachment_list_free(plist1);
			return NULL;
		}
		if (!attachment_list_append_internal(plist1, pattachment)) {
			attachment_content_free(pattachment);
			attachment_list_free(plist1);
			return NULL;
		}
	}
	return plist1;
}

FOLDER_CONTENT::FOLDER_CONTENT()
{
	if (!tpropval_array_init_internal(&proplist))
		throw std::bad_alloc();
}

FOLDER_CONTENT::FOLDER_CONTENT(FOLDER_CONTENT &&o) noexcept :
	proplist(std::move(o.proplist)), fldmsgs(std::move(o.fldmsgs)),
	psubflds(std::move(o.psubflds))
{
	o.proplist = {}; // TPROPVAL_ARRAY yet without move
	o.fldmsgs = {}; // FOLDER_MESSAGES yet without move
}

std::unique_ptr<FOLDER_CONTENT> folder_content_init() try
{
	return std::make_unique<FOLDER_CONTENT>();
} catch (const std::bad_alloc &) {
	return nullptr;
}

BOOL FOLDER_CONTENT::append_subfolder_internal(FOLDER_CONTENT &&psubfld) try
{
	auto pfldctnt = this;
	pfldctnt->psubflds.push_back(std::move(psubfld));
	return TRUE;
} catch (const std::bad_alloc &) {
	return false;
}

FOLDER_CONTENT::~FOLDER_CONTENT()
{
	auto pfldctnt = this;
	tpropval_array_free_internal(&pfldctnt->proplist);
	if (NULL != pfldctnt->fldmsgs.pfai_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pfai_msglst);
	}
	if (NULL != pfldctnt->fldmsgs.pnormal_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pnormal_msglst);
	}
}

void FOLDER_CONTENT::append_failist_internal(EID_ARRAY *plist)
{
	auto pfldctnt = this;
	if (NULL != pfldctnt->fldmsgs.pfai_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pfai_msglst);
	}
	pfldctnt->fldmsgs.pfai_msglst = plist;
}

void FOLDER_CONTENT::append_normallist_internal(EID_ARRAY *plist)
{
	auto pfldctnt = this;
	if (NULL != pfldctnt->fldmsgs.pnormal_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pnormal_msglst);
	}
	pfldctnt->fldmsgs.pnormal_msglst = plist;
}

BOOL message_content_init_internal(MESSAGE_CONTENT *pmsgctnt)
{
	if (!tpropval_array_init_internal(&pmsgctnt->proplist))
		return FALSE;
	pmsgctnt->children.prcpts = NULL;
	pmsgctnt->children.pattachments = NULL;
	return TRUE;
}

MESSAGE_CONTENT* message_content_init()
{
	auto pmsgctnt = me_alloc<MESSAGE_CONTENT>();
	if (NULL == pmsgctnt) {
		return NULL;
	}
	if (!message_content_init_internal(pmsgctnt)) {
		free(pmsgctnt);
		return nullptr;
	}
	return pmsgctnt;
}

TPROPVAL_ARRAY* message_content_get_proplist(MESSAGE_CONTENT *pmsgctnt)
{
	return &pmsgctnt->proplist;
}

void message_content_set_rcpts_internal(
	MESSAGE_CONTENT *pmsgctnt, TARRAY_SET *prcpts)
{
	if (NULL != pmsgctnt->children.prcpts) {
		tarray_set_free(pmsgctnt->children.prcpts);
	}
	pmsgctnt->children.prcpts = prcpts;
}

void message_content_set_attachments_internal(
	MESSAGE_CONTENT *pmsgctnt, ATTACHMENT_LIST *pattachments)
{
	if (NULL != pmsgctnt->children.pattachments) {
		attachment_list_free(pmsgctnt->children.pattachments);
	}
	pmsgctnt->children.pattachments = pattachments;
}

void message_content_free_internal(MESSAGE_CONTENT *pmsgctnt)
{	
	tpropval_array_free_internal(&pmsgctnt->proplist);
	if (NULL != pmsgctnt->children.prcpts) {
		tarray_set_free(pmsgctnt->children.prcpts);
	}
	if (NULL != pmsgctnt->children.pattachments) {
		attachment_list_free(pmsgctnt->children.pattachments);
	}
}

void message_content_free(MESSAGE_CONTENT *pmsgctnt)
{
	message_content_free_internal(pmsgctnt);
	free(pmsgctnt);
}

MESSAGE_CONTENT *message_content_dup(const MESSAGE_CONTENT *pmsgctnt)
{
	int i;
	MESSAGE_CONTENT *pmsgctnt1;
	
	pmsgctnt1 = message_content_init();
	if (NULL == pmsgctnt1) {
		return NULL;
	}
	for (i=0; i<pmsgctnt->proplist.count; i++) {
		if (pmsgctnt1->proplist.set(pmsgctnt->proplist.ppropval[i]) != 0) {
			message_content_free(pmsgctnt1);
			return NULL;
		}
	}
	if (NULL != pmsgctnt->children.prcpts) {
		pmsgctnt1->children.prcpts = pmsgctnt->children.prcpts->dup();
		if (NULL == pmsgctnt1->children.prcpts) {
			message_content_free(pmsgctnt1);
			return NULL;
		}
	}
	if (NULL != pmsgctnt->children.pattachments) {
		pmsgctnt1->children.pattachments =
			attachment_list_dup(pmsgctnt->children.pattachments);
		if (NULL == pmsgctnt1->children.pattachments) {
			message_content_free(pmsgctnt1);
			return NULL;
		}
	}
	return pmsgctnt1;
}

property_groupinfo::property_groupinfo(uint32_t gid) :
	group_id(gid)
{
	auto z = strange_roundup(0, SR_GROW_PROPTAG_ARRAY);
	pgroups = me_alloc<PROPTAG_ARRAY>(z);
	if (pgroups == nullptr)
		throw std::bad_alloc();
}

property_groupinfo::property_groupinfo(property_groupinfo &&o) noexcept :
	group_id(o.group_id), reserved(o.reserved), count(o.count),
	pgroups(std::move(o.pgroups))
{
	o.pgroups = nullptr;
}

bool property_groupinfo::append_internal(PROPTAG_ARRAY *pgroup)
{
	auto pgpinfo = this;
	/* allocate like proptag_array.cpp does */
	auto z = strange_roundup(pgpinfo->count, SR_GROW_PROPTAG_ARRAY);
	if (pgpinfo->count + 1 >= z) {
		z += SR_GROW_PROPTAG_ARRAY;
		auto list = re_alloc<PROPTAG_ARRAY>(pgpinfo->pgroups, z);
		if (list == nullptr)
			return FALSE;
		pgpinfo->pgroups = list;
	}
	pgpinfo->pgroups[pgpinfo->count].count = pgroup->count;
	pgpinfo->pgroups[pgpinfo->count++].pproptag = pgroup->pproptag;
	free(pgroup);
	return TRUE;
}

bool property_groupinfo::get_partial_index(uint32_t proptag,
    uint32_t *pindex) const
{
	auto pgpinfo = this;
	for (size_t i = 0; i < pgpinfo->count; ++i)
		for (size_t j = 0; j < pgpinfo->pgroups[i].count; ++j)
			if (proptag == pgpinfo->pgroups[i].pproptag[j]) {
				*pindex = i;
				return true;
			}
	return false;
}

property_groupinfo::~property_groupinfo()
{
	auto pgpinfo = this;
	for (size_t i = 0; i < pgpinfo->count; ++i)
		proptag_array_free_internal(pgpinfo->pgroups + i);
	free(pgpinfo->pgroups);
}

PROPERTY_XNAME::PROPERTY_XNAME(const PROPERTY_NAME &o) :
	kind(o.kind), lid(o.lid), guid(o.guid)
{
	if (o.kind == MNID_STRING && o.pname != nullptr)
		name = o.pname;
}

PROPERTY_XNAME::operator PROPERTY_NAME() const
{
	PROPERTY_NAME z;
	z.kind = kind;
	z.guid = guid;
	z.lid = lid;
	z.pname = const_cast<char *>(name.c_str());
	return z;
}

size_t PROPTAG_ARRAY::indexof(uint32_t tag) const
{
	for (size_t i = 0; i < count; ++i)
		if (pproptag[i] == tag)
			return i;
	return npos;
}

PROBLEM_ARRAY &PROBLEM_ARRAY::operator+=(PROBLEM_ARRAY &&other)
{
	std::move(other.pproblem, other.pproblem + other.count, pproblem + count);
	count += other.count;
	other.count = 0;
	std::sort(pproblem, pproblem + count);
	return *this;
}

void PROBLEM_ARRAY::transform(const uint16_t *orig_indices)
{
	for (size_t i = 0; i < count; ++i)
		pproblem[i].index = orig_indices[pproblem[i].index];
}

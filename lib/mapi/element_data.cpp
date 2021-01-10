// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <gromox/mapidefs.h>
#include <gromox/proptag_array.hpp>
#include <gromox/tpropval_array.hpp>
#include <gromox/element_data.hpp>
#include <gromox/tarray_set.hpp>
#include <gromox/eid_array.hpp>
#include <gromox/propval.hpp>
#include <gromox/idset.hpp>
#include <cstdlib>
#include <cstring>

ATTACHMENT_CONTENT* attachment_content_init()
{
	auto pattachment = static_cast<ATTACHMENT_CONTENT *>(malloc(sizeof(ATTACHMENT_CONTENT)));
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
		if (!tpropval_array_set_propval(&pattachment1->proplist,
		    pattachment->proplist.ppropval + i)) {
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
	auto plist = static_cast<ATTACHMENT_LIST *>(malloc(sizeof(ATTACHMENT_LIST)));
	if (NULL == plist) {
		return NULL;
	}
	plist->count = 0;
	plist->pplist = static_cast<ATTACHMENT_CONTENT **>(malloc(20 * sizeof(ATTACHMENT_CONTENT *)));
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
	uint16_t count;
	ATTACHMENT_CONTENT **pplist;
	
	if (plist->count >= 0x8000) {
		return FALSE;
	}
	count = (plist->count / 20 + 1) * 20;
	if (plist->count + 1 >= count) {
		count += 20;
		pplist = static_cast<ATTACHMENT_CONTENT **>(realloc(plist->pplist, count * sizeof(ATTACHMENT_CONTENT *)));
		if (NULL == pplist) {
			return FALSE;
		}
		plist->pplist = pplist;
	}
	plist->pplist[plist->count] = pattachment;
	plist->count ++;
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
		if (FALSE == attachment_list_append_internal(
			plist1, pattachment)) {
			attachment_content_free(pattachment);
			attachment_list_free(plist1);
			return NULL;
		}
	}
	return plist1;
}

FOLDER_CONTENT* folder_content_init()
{
	auto pfldctnt = static_cast<FOLDER_CONTENT *>(malloc(sizeof(FOLDER_CONTENT)));
	if (NULL == pfldctnt) {
		return NULL;
	}
	if (!tpropval_array_init_internal(&pfldctnt->proplist)) {
		free(pfldctnt);
		return NULL;
	}
	pfldctnt->fldmsgs.pfai_msglst = NULL;
	pfldctnt->fldmsgs.pnormal_msglst = NULL;
	pfldctnt->count = 0;
	pfldctnt->psubflds = static_cast<FOLDER_CONTENT *>(malloc(10 * sizeof(FOLDER_CONTENT)));
	if (NULL == pfldctnt->psubflds) {
		tpropval_array_free_internal(&pfldctnt->proplist);
		free(pfldctnt);
		return NULL;
	}
	return pfldctnt;
}

BOOL folder_content_append_subfolder_internal(
	FOLDER_CONTENT *pfldctnt, FOLDER_CONTENT *psubfld)
{
	int count;
	FOLDER_CONTENT *psubflds;
	
	count = (pfldctnt->count / 10 + 1) * 10;
	if (pfldctnt->count + 1 >= count) {
		count += 10;
		psubflds = static_cast<FOLDER_CONTENT *>(realloc(pfldctnt->psubflds, count * sizeof(FOLDER_CONTENT)));
		if (NULL == psubflds) {
			return FALSE;
		}
		pfldctnt->psubflds = psubflds;
	}
	memcpy(pfldctnt->psubflds + pfldctnt->count,
				psubfld, sizeof(FOLDER_CONTENT));
	pfldctnt->count ++;
	free(psubfld);
	return TRUE;
}

static void folder_content_free_internal(FOLDER_CONTENT *pfldctnt)
{
	int i;
	
	tpropval_array_free_internal(&pfldctnt->proplist);
	if (NULL != pfldctnt->fldmsgs.pfai_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pfai_msglst);
	}
	if (NULL != pfldctnt->fldmsgs.pnormal_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pnormal_msglst);
	}
	for (i=0; i<pfldctnt->count; i++) {
		folder_content_free_internal(pfldctnt->psubflds + i);
	}
	free(pfldctnt->psubflds);
}

void folder_content_free(FOLDER_CONTENT *pfldctnt)
{
	folder_content_free_internal(pfldctnt);
	free(pfldctnt);
}

TPROPVAL_ARRAY* folder_content_get_proplist(FOLDER_CONTENT *pfldctnt)
{
	return &pfldctnt->proplist;
}

void folder_content_append_failist_internal(
	FOLDER_CONTENT *pfldctnt, EID_ARRAY *plist)
{
	if (NULL != pfldctnt->fldmsgs.pfai_msglst) {
		eid_array_free(pfldctnt->fldmsgs.pfai_msglst);
	}
	pfldctnt->fldmsgs.pfai_msglst = plist;
}

void folder_content_append_normallist_internal(
	FOLDER_CONTENT *pfldctnt, EID_ARRAY *plist)
{
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
	auto pmsgctnt = static_cast<MESSAGE_CONTENT *>(malloc(sizeof(MESSAGE_CONTENT)));
	if (NULL == pmsgctnt) {
		return NULL;
	}
	if (FALSE == message_content_init_internal(pmsgctnt)) {
		free(pmsgctnt);
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

uint32_t message_content_get_size(const MESSAGE_CONTENT *pmsgctnt)
{
	int i, j;
	uint32_t message_size;
	TAGGED_PROPVAL *ppropval;
	ATTACHMENT_CONTENT *pattachment;
	
	message_size = 0;
	for (i=0; i<pmsgctnt->proplist.count; i++) {
		ppropval = pmsgctnt->proplist.ppropval + i;
		message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
	}
	if (NULL != pmsgctnt->children.prcpts) {
		for (i=0; i<pmsgctnt->children.prcpts->count; i++) {
			for (j=0; j<pmsgctnt->children.prcpts->pparray[i]->count; j++) {
				ppropval = pmsgctnt->children.prcpts->pparray[i]->ppropval + j;
				message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
			}
		}
	}
	if (NULL != pmsgctnt->children.pattachments) {
		for (i=0; i<pmsgctnt->children.pattachments->count; i++) {
			pattachment = pmsgctnt->children.pattachments->pplist[i];
			for (j=0; j<pattachment->proplist.count; j++) {
				ppropval = pattachment->proplist.ppropval + j;
				message_size += propval_size(PROP_TYPE(ppropval->proptag), ppropval->pvalue);
			}
			if (NULL != pattachment->pembedded) {
				message_size += message_content_get_size(
								pattachment->pembedded);
			}
		}
	}
	return message_size;
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
		if (!tpropval_array_set_propval(&pmsgctnt1->proplist,
		    pmsgctnt->proplist.ppropval + i)) {
			message_content_free(pmsgctnt1);
			return NULL;
		}
	}
	if (NULL != pmsgctnt->children.prcpts) {
		pmsgctnt1->children.prcpts =
			tarray_set_dup(pmsgctnt->children.prcpts);
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

BOOL property_groupinfo_init_internal(
	PROPERTY_GROUPINFO *pgpinfo, uint32_t group_id)
{
	pgpinfo->group_id = group_id;
	pgpinfo->reserved = 0;
	pgpinfo->count = 0;
	pgpinfo->pgroups = static_cast<PROPTAG_ARRAY *>(malloc(sizeof(PROPTAG_ARRAY) * 20));
	if (NULL == pgpinfo->pgroups) {
		return FALSE;
	}
	return TRUE;
}

PROPERTY_GROUPINFO* property_groupinfo_init(uint32_t group_id)
{
	auto pgpinfo = static_cast<PROPERTY_GROUPINFO *>(malloc(sizeof(PROPERTY_GROUPINFO)));
	if (NULL == pgpinfo) {
		return NULL;
	}
	if (FALSE == property_groupinfo_init_internal(pgpinfo, group_id)) {
		free(pgpinfo);
		return NULL;
	}
	return pgpinfo;
}

BOOL property_groupinfo_append_internal(
	PROPERTY_GROUPINFO *pgpinfo, PROPTAG_ARRAY *pgroup)
{
	uint32_t count;
	PROPTAG_ARRAY *pgroups;
	
	count = (pgpinfo->count / 20 + 1) * 20;
	if (pgpinfo->count + 1 >= count) {
		count += 20;
		pgroups = static_cast<PROPTAG_ARRAY *>(realloc(pgpinfo->pgroups, sizeof(PROPTAG_ARRAY) * count));
		if (NULL == pgroups) {
			return FALSE;
		}
		pgpinfo->pgroups = pgroups;
	}
	pgpinfo->pgroups[pgpinfo->count].count = pgroup->count;
	pgpinfo->pgroups[pgpinfo->count].pproptag = pgroup->pproptag;
	free(pgroup);
	pgpinfo->count ++;
	return TRUE;
}

BOOL property_groupinfo_get_partial_index(PROPERTY_GROUPINFO *pgpinfo,
	uint32_t proptag, uint32_t *pindex)
{
	int i, j;
	
	for (i=0; i<pgpinfo->count; i++) {
		for (j=0; j<pgpinfo->pgroups[i].count; j++) {
			if (proptag == pgpinfo->pgroups[i].pproptag[j]) {
				*pindex = i;
				return TRUE;
			}
		}
	}
	return FALSE;
}

void property_groupinfo_free_internal(PROPERTY_GROUPINFO *pgpinfo)
{
	int i;
	
	for (i=0; i<pgpinfo->count; i++) {
		proptag_array_free_internal(pgpinfo->pgroups + i);
	}
	free(pgpinfo->pgroups);
}

void property_groupinfo_free(PROPERTY_GROUPINFO *pgpinfo)
{
	property_groupinfo_free_internal(pgpinfo);
	free(pgpinfo);
}

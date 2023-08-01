// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/propval.hpp>
#include <gromox/rule_actions.hpp>

using namespace gromox;

static STORE_ENTRYID* store_entryid_dup(STORE_ENTRYID *peid)
{
	auto pstore = me_alloc<STORE_ENTRYID>();
	if (NULL == pstore) {
		return NULL;
	}
	*pstore = *peid;
	pstore->pserver_name = strdup(peid->pserver_name);
	if (NULL == pstore->pserver_name) {
		free(pstore);
		return NULL;
	}
	pstore->pmailbox_dn = strdup(peid->pmailbox_dn);
	if (NULL == pstore->pmailbox_dn) {
		free(pstore->pserver_name);
		free(pstore);
		return NULL;
	}
	return pstore;
}

static void store_entryid_free(STORE_ENTRYID *peid)
{
	free(peid->pmailbox_dn);
	free(peid->pserver_name);
	free(peid);
}

static MOVECOPY_ACTION* movecopy_action_dup(const MOVECOPY_ACTION *paction)
{
	auto pmovecopy = me_alloc<MOVECOPY_ACTION>();
	if (NULL == pmovecopy) {
		return NULL;
	}
	pmovecopy->same_store = paction->same_store;
	if (NULL != paction->pstore_eid) {
		pmovecopy->pstore_eid = store_entryid_dup(paction->pstore_eid);
		if (NULL == pmovecopy->pstore_eid) {
			free(pmovecopy);
			return NULL;
		}
	} else {
		pmovecopy->pstore_eid = NULL;
	}
	
	if (1 == paction->same_store) {
		pmovecopy->pfolder_eid =
			propval_dup(PT_SVREID, paction->pfolder_eid);
	} else {
		pmovecopy->pfolder_eid =
			propval_dup(PT_BINARY, paction->pfolder_eid);
	}
	if (NULL == pmovecopy->pfolder_eid) {
		if (NULL != pmovecopy->pstore_eid) {
			store_entryid_free(pmovecopy->pstore_eid);
		}
		free(pmovecopy);
		return NULL;
	}
	return pmovecopy;
}

static void movecopy_action_free(MOVECOPY_ACTION *paction)
{
	if (NULL != paction->pstore_eid) {
		store_entryid_free(paction->pstore_eid);
	}
	if (1 == paction->same_store) {
		propval_free(PT_SVREID, paction->pfolder_eid);
	} else {
		propval_free(PT_BINARY, paction->pfolder_eid);
	}
	free(paction);
}

static REPLY_ACTION* reply_action_dup(const REPLY_ACTION *paction)
{
	auto preply = me_alloc<REPLY_ACTION>();
	if (NULL == preply) {
		return NULL;
	}
	preply->template_folder_id = paction->template_folder_id;
	preply->template_message_id = paction->template_message_id;
	memcpy(&preply->template_guid, &paction->template_guid, sizeof(GUID));
	return preply;
}

static void reply_action_free(REPLY_ACTION *paction)
{
	free(paction);
}

static BOOL recipient_block_dup_internal(
	const RECIPIENT_BLOCK *pblock, RECIPIENT_BLOCK *precipient)
{
	int i;
	
	if (0 == pblock->count) {
		return FALSE;
	}
	precipient->reserved = pblock->reserved;
	precipient->count = pblock->count;
	precipient->ppropval = me_alloc<TAGGED_PROPVAL>(pblock->count);
	if (NULL == pblock->ppropval) {
		return FALSE;
	}
	for (i=0; i<pblock->count; i++) {
		precipient->ppropval[i].proptag = pblock->ppropval[i].proptag;
		precipient->ppropval[i].pvalue = propval_dup(PROP_TYPE(pblock->ppropval[i].proptag),
								pblock->ppropval[i].pvalue);
		if (NULL == precipient->ppropval[i].pvalue) {
			for (i-=1; i>=0; i--) {
				propval_free(PROP_TYPE(precipient->ppropval[i].proptag),
					precipient->ppropval[i].pvalue);
			}
			free(precipient->ppropval);
			return FALSE;
		}
	}
	return TRUE;
}

static void recipient_block_free_internal(RECIPIENT_BLOCK *pblock)
{
	int i;
	
	for (i=0; i<pblock->count; i++) {
		propval_free(PROP_TYPE(pblock->ppropval[i].proptag),
								pblock->ppropval[i].pvalue);
	}
	free(pblock->ppropval);
}

static FORWARDDELEGATE_ACTION* forwarddelegate_action_dup(
	const FORWARDDELEGATE_ACTION *paction)
{
	int i;
	
	if (0 == paction->count) {
		return NULL;
	}
	auto pblock = me_alloc<FORWARDDELEGATE_ACTION>();
	if (NULL == pblock) {
		return NULL;
	}
	pblock->count = paction->count;
	pblock->pblock = me_alloc<RECIPIENT_BLOCK>(pblock->count);
	if (NULL == pblock->pblock) {
		free(pblock);
		return NULL;
	}
	for (i=0; i<paction->count; i++) {
		if (recipient_block_dup_internal(&paction->pblock[i], &pblock->pblock[i]))
			continue;
		for (i -= 1; i >= 0; i--) {
			recipient_block_free_internal(
				pblock->pblock + i);
		}
		free(pblock->pblock);
		free(pblock);
		return NULL;
	}
	return pblock;
}

static void forwarddelegate_action_free(FORWARDDELEGATE_ACTION *paction)
{
	int i;
	
	for (i=0; i<paction->count; i++) {
		recipient_block_free_internal(paction->pblock + i);
	}
	free(paction->pblock);
	free(paction);
}

static BOOL action_block_dup_internal(
	const ACTION_BLOCK *paction, ACTION_BLOCK *pblock)
{
	uint16_t tmp_len;
	
	pblock->length = paction->length;
	pblock->type = paction->type;
	pblock->flavor = paction->flavor;
	pblock->flags = paction->flags;
	switch (paction->type) {
	case OP_MOVE:
	case OP_COPY:
		pblock->pdata = movecopy_action_dup(static_cast<MOVECOPY_ACTION *>(paction->pdata));
		if (NULL == pblock->pdata) {
			return FALSE;
		}
		return TRUE;
	case OP_REPLY:
	case OP_OOF_REPLY:
		pblock->pdata = reply_action_dup(static_cast<REPLY_ACTION *>(paction->pdata));
		if (NULL == pblock->pdata) {
			return FALSE;
		}
		return TRUE;
	case OP_DEFER_ACTION:
		tmp_len = paction->length - sizeof(uint8_t) -
					sizeof(uint32_t) - sizeof(uint32_t);
		pblock->pdata = malloc(tmp_len);
		if (NULL == pblock->pdata) {
			return FALSE;
		}
		memcpy(pblock->pdata, paction->pdata, tmp_len); 
		return TRUE;
	case OP_BOUNCE:
		pblock->pdata = me_alloc<uint32_t>();
		if (NULL == pblock->pdata) {
			return FALSE;
		}
		*static_cast<uint32_t *>(pblock->pdata) = *static_cast<uint32_t *>(paction->pdata);
		return TRUE;
	case OP_FORWARD:
	case OP_DELEGATE:
		pblock->pdata = forwarddelegate_action_dup(static_cast<FORWARDDELEGATE_ACTION *>(paction->pdata));
		if (NULL == pblock->pdata) {
			return FALSE;
		}
		return TRUE;
	case OP_TAG: {
		pblock->pdata = me_alloc<TAGGED_PROPVAL>();
		auto s = static_cast<TAGGED_PROPVAL *>(paction->pdata);
		auto d = static_cast<TAGGED_PROPVAL *>(pblock->pdata);
		if (d == nullptr)
			return FALSE;
		d->proptag = s->proptag;
		d->pvalue = propval_dup(PROP_TYPE(s->proptag), s->pvalue);
		if (d->pvalue == nullptr) {
			free(pblock->pdata);
			return FALSE;
		}
		return TRUE;
	}
	case OP_DELETE:
	case OP_MARK_AS_READ:
		pblock->pdata = NULL;
		return TRUE;
	}
	return FALSE;
}

static void action_block_free_internal(ACTION_BLOCK *paction)
{
	switch (paction->type) {
	case OP_MOVE:
	case OP_COPY:
		movecopy_action_free(static_cast<MOVECOPY_ACTION *>(paction->pdata));
		break;
	case OP_REPLY:
	case OP_OOF_REPLY:
		reply_action_free(static_cast<REPLY_ACTION *>(paction->pdata));
		break;
	case OP_DEFER_ACTION:
	case OP_BOUNCE:
		free(paction->pdata);
		break;
	case OP_FORWARD:
	case OP_DELEGATE:
		forwarddelegate_action_free(static_cast<FORWARDDELEGATE_ACTION *>(paction->pdata));
		break;
	case OP_TAG: {
		auto p = static_cast<TAGGED_PROPVAL *>(paction->pdata);
		propval_free(PROP_TYPE(p->proptag), p->pvalue);
		free(p);
		break;
	}
	case OP_DELETE:
	case OP_MARK_AS_READ:
		break;
	}
}

RULE_ACTIONS* rule_actions_dup(const RULE_ACTIONS *prule)
{
	int i;
	
	if (0 == prule->count) {
		return NULL;
	}
	auto paction = me_alloc<RULE_ACTIONS>();
	if (NULL == paction) {
		return NULL;
	}
	paction->count = prule->count;
	paction->pblock = me_alloc<ACTION_BLOCK>(paction->count);
	if (NULL == paction->pblock) {
		free(paction);
		return NULL;
	}
	for (i=0; i<prule->count; i++) {
		if (action_block_dup_internal(&prule->pblock[i], &paction->pblock[i]))
			continue;
		for (i -= 1; i >= 0; i--) {
			action_block_free_internal(paction->pblock + i);
		}
		free(paction->pblock);
		free(paction);
		return NULL;
	}
	return paction;
}

void rule_actions_free(RULE_ACTIONS *prule)
{
	int i;
	
	for (i=0; i<prule->count; i++) {
		action_block_free_internal(prule->pblock + i);
	}
	free(prule->pblock);
	free(prule);
}


static uint32_t movecopy_action_size(const MOVECOPY_ACTION *r)
{
	uint32_t size;
	
	size = sizeof(uint8_t) + sizeof(uint16_t);
	if (NULL != r->pstore_eid) {
		size += 62 + strlen(r->pstore_eid->pserver_name) +
						strlen(r->pstore_eid->pmailbox_dn);
	}
	
	if (0 == r->same_store) {
		size += sizeof(uint16_t) + 21;
	} else {
		size += sizeof(uint16_t) + static_cast<BINARY *>(r->pfolder_eid)->cb;
	}
	return size;
}

static uint32_t reply_action_size(const REPLY_ACTION *r)
{
	return sizeof(uint64_t) + sizeof(uint64_t) + 16;
}

static uint32_t recipient_block_size(const RECIPIENT_BLOCK *r)
{
	int i;
	uint32_t size;
	
	size = sizeof(uint8_t) + sizeof(uint32_t);
	for (i=0; i<r->count; i++) {
		size += propval_size(PROP_TYPE(r->ppropval[i].proptag),
					r->ppropval[i].pvalue) + sizeof(uint32_t);
	}
	return size;
}

static uint32_t forwarddelegate_action_size(
	const FORWARDDELEGATE_ACTION *r)
{
	int i;
	uint32_t size;
	
	size = sizeof(uint16_t);
	for (i=0; i<r->count; i++) {
		size += recipient_block_size(r->pblock + i);
	}
	return size;
}

static uint32_t action_block_size(const ACTION_BLOCK *r)
{
	uint32_t size;
	
	size = sizeof(uint16_t) + sizeof(uint8_t) + 
			sizeof(uint32_t) + sizeof(uint32_t);
	switch (r->type) {
	case OP_MOVE:
	case OP_COPY:
		size += movecopy_action_size(static_cast<MOVECOPY_ACTION *>(r->pdata));
		break;
	case OP_REPLY:
	case OP_OOF_REPLY:
		size += reply_action_size(static_cast<REPLY_ACTION *>(r->pdata));
		break;
	case OP_DEFER_ACTION:
		size += r->length - sizeof(uint8_t) - 
				sizeof(uint32_t) - sizeof(uint32_t);
		break;
	case OP_BOUNCE:
		size += sizeof(uint32_t);
		break;
	case OP_FORWARD:
	case OP_DELEGATE:
		size += forwarddelegate_action_size(static_cast<FORWARDDELEGATE_ACTION *>(r->pdata));
		break;
	case OP_TAG: {
		auto p = static_cast<TAGGED_PROPVAL *>(r->pdata);
		size += sizeof(uint32_t) + propval_size(PROP_TYPE(p->proptag), p->pvalue);
	}
	}
	return size;
}

uint32_t rule_actions_size(const RULE_ACTIONS *r)
{
	int i;
	uint32_t size;
	
	size = sizeof(uint16_t);
	for (i=0; i<r->count; i++) {
		size += action_block_size(r->pblock + i);
	}
	return size;
}

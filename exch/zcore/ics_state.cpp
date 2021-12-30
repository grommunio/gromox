// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <memory>
#include "common_util.h"
#include <gromox/ext_buffer.hpp>
#include "ics_state.h"
#include <gromox/rop_util.hpp>
#include <gromox/idset.hpp>
#include <cstdlib>
#include <cstring>

static void ics_state_clear(ICS_STATE *pstate)
{
	if (NULL != pstate->pgiven) {
		idset_free(pstate->pgiven);
		pstate->pgiven = NULL;
	}
	if (NULL != pstate->pseen) {
		idset_free(pstate->pseen);
		pstate->pseen = NULL;
	}
	if (NULL != pstate->pseen_fai) {
		idset_free(pstate->pseen_fai);
		pstate->pseen_fai = NULL;
	}
	if (NULL != pstate->pread) {
		idset_free(pstate->pread);
		pstate->pread = NULL;
	}
}

static BOOL ics_state_init(ICS_STATE *pstate)
{
	pstate->pgiven = idset_init(TRUE, REPL_TYPE_ID);
	if (NULL == pstate->pgiven) {
		return FALSE;
	}
	pstate->pseen = idset_init(TRUE, REPL_TYPE_ID);
	if (NULL == pstate->pseen) {
		return FALSE;
	}
	if (ICS_TYPE_CONTENTS == pstate->type) {
		pstate->pseen_fai = idset_init(TRUE, REPL_TYPE_ID);
		if (NULL == pstate->pseen_fai) {
			return FALSE;
		}
		pstate->pread = idset_init(TRUE, REPL_TYPE_ID);
		if (NULL == pstate->pread) {
			return FALSE;
		}
	}
	return TRUE;
}

ICS_STATE* ics_state_create(uint8_t type)
{
	auto pstate = me_alloc<ICS_STATE>();
	if (NULL == pstate) {
		return NULL;
	}
	memset(pstate, 0, sizeof(ICS_STATE));
	pstate->type = type;
	if (FALSE == ics_state_init(pstate)) {
		ics_state_clear(pstate);
		free(pstate);
		return NULL;
	}
	return pstate;
}

void ics_state_free(ICS_STATE *pstate)
{
	ics_state_clear(pstate);
	free(pstate);
}

BINARY* ics_state_serialize(ICS_STATE *pstate)
{
	struct mdel {
		inline void operator()(BINARY *x) { rop_util_free_binary(x); }
		inline void operator()(TPROPVAL_ARRAY *x) { tpropval_array_free(x); }
	};
	EXT_PUSH ext_push;
	static constexpr uint8_t bin_buff[8]{};
	static constexpr BINARY fake_bin = {gromox::arsizeof(bin_buff), {deconst(bin_buff)}};
	
	if (ICS_TYPE_CONTENTS == pstate->type) {
		if (pstate->pgiven->check_empty() &&
		    pstate->pseen->check_empty() &&
		    pstate->pseen_fai->check_empty() &&
		    pstate->pread->check_empty())
			return deconst(&fake_bin);
	} else {
		if (pstate->pgiven->check_empty() &&
		    pstate->pseen->check_empty())
			return deconst(&fake_bin);
	}
	std::unique_ptr<TPROPVAL_ARRAY, mdel> pproplist(tpropval_array_init());
	if (NULL == pproplist) {
		return NULL;
	}
	std::unique_ptr<BINARY, mdel> ser(pstate->pgiven->serialize());
	if (ser == nullptr || pproplist->set(MetaTagIdsetGiven1, ser.get()) != 0)
		return NULL;
	ser.reset(pstate->pseen->serialize());
	if (ser == nullptr || pproplist->set(MetaTagCnsetSeen, ser.get()) != 0)
		return NULL;
	ser.reset();
	
	if (ICS_TYPE_CONTENTS == pstate->type) {
		decltype(ser) s(pstate->pseen_fai->serialize());
		if (s == nullptr || pproplist->set(MetaTagCnsetSeenFAI, s.get()) != 0)
			return NULL;
	}
	
	if (ICS_TYPE_CONTENTS == pstate->type &&
	    !pstate->pread->check_empty()) {
		decltype(ser) s(pstate->pread->serialize());
		if (s == nullptr || pproplist->set(MetaTagCnsetRead, s.get()) != 0)
			return NULL;
	}
	if (!ext_push.init(nullptr, 0, 0) ||
	    ext_push.p_tpropval_a(pproplist.get()) != EXT_ERR_SUCCESS)
		return NULL;
	pproplist.reset();
	auto pbin = cu_alloc<BINARY>();
	pbin->cb = ext_push.m_offset;
	pbin->pv = common_util_alloc(pbin->cb);
	if (pbin->pv == nullptr) {
		return NULL;
	}
	memcpy(pbin->pv, ext_push.m_udata, pbin->cb);
	return pbin;
}

BOOL ics_state_deserialize(ICS_STATE *pstate, const BINARY *pbin)
{
	int i;
	IDSET *pset;
	EXT_PULL ext_pull;
	TPROPVAL_ARRAY propvals;
	
	ics_state_clear(pstate);
	ics_state_init(pstate);
	if (pbin->cb <= 16) {
		return TRUE;
	}
	ext_pull.init(pbin->pb, pbin->cb, common_util_alloc, 0);
	if (ext_pull.g_tpropval_a(&propvals) != EXT_ERR_SUCCESS)
		return FALSE;	
	for (i=0; i<propvals.count; i++) {
		switch (propvals.ppropval[i].proptag) {
		case MetaTagIdsetGiven1:
			pset = idset_init(FALSE, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
			    !pset->convert()) {
				idset_free(pset);
				return FALSE;
			}
			idset_free(pstate->pgiven);
			pstate->pgiven = pset;
			break;
		case MetaTagCnsetSeen:
			pset = idset_init(FALSE, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
			    !pset->convert()) {
				idset_free(pset);
				return FALSE;
			}
			idset_free(pstate->pseen);
			pstate->pseen = pset;
			break;
		case MetaTagCnsetSeenFAI:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				pset = idset_init(FALSE, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
				    !pset->convert()) {
					idset_free(pset);
					return FALSE;
				}
				idset_free(pstate->pseen_fai);
				pstate->pseen_fai = pset;
			}
			break;
		case MetaTagCnsetRead:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				pset = idset_init(FALSE, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
				    !pset->convert()) {
					idset_free(pset);
					return FALSE;
				}
				idset_free(pstate->pread);
				pstate->pread = pset;
			}
			break;
		}
	}
	return TRUE;
}

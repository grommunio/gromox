// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <gromox/ext_buffer.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include "common_util.h"
#include "ics_state.h"

static void ics_state_clear(ICS_STATE *pstate)
{
	pstate->pgiven.reset();
	pstate->pseen.reset();
	pstate->pseen_fai.reset();
	pstate->pread.reset();
}

static BOOL ics_state_init(ICS_STATE *pstate)
{
	pstate->pgiven = idset::create(true, REPL_TYPE_ID);
	if (NULL == pstate->pgiven) {
		return FALSE;
	}
	pstate->pseen = idset::create(true, REPL_TYPE_ID);
	if (NULL == pstate->pseen) {
		return FALSE;
	}
	if (ICS_TYPE_CONTENTS == pstate->type) {
		pstate->pseen_fai = idset::create(true, REPL_TYPE_ID);
		if (NULL == pstate->pseen_fai) {
			return FALSE;
		}
		pstate->pread = idset::create(true, REPL_TYPE_ID);
		if (NULL == pstate->pread) {
			return FALSE;
		}
	}
	return TRUE;
}

std::unique_ptr<ics_state> ics_state::create(uint8_t type) try
{
	auto pstate = std::make_unique<ics_state>(type);
	if (!ics_state_init(pstate.get()))
		return NULL;
	return pstate;
} catch (const std::bad_alloc &) {
	return nullptr;
}

std::shared_ptr<ics_state> ics_state::create_shared(uint8_t type) try
{
	auto pstate = std::make_shared<ics_state>(type);
	if (!ics_state_init(pstate.get()))
		return NULL;
	return pstate;
} catch (const std::bad_alloc &) {
	return nullptr;
}

BINARY *ics_state::serialize()
{
	struct mdel {
		void operator()(BINARY *x) const { rop_util_free_binary(x); }
		void operator()(TPROPVAL_ARRAY *x) const { tpropval_array_free(x); }
	};
	EXT_PUSH ext_push;
	static constexpr uint8_t bin_buff[8]{};
	static constexpr BINARY fake_bin = {std::size(bin_buff), {deconst(bin_buff)}};
	auto pstate = this;
	
	if (ICS_TYPE_CONTENTS == pstate->type) {
		if (pstate->pgiven->empty() && pstate->pseen->empty() &&
		    pstate->pseen_fai->empty() && pstate->pread->empty())
			return deconst(&fake_bin);
	} else {
		if (pstate->pgiven->empty() && pstate->pseen->empty())
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
	    !pstate->pread->empty()) {
		decltype(ser) s(pstate->pread->serialize());
		if (s == nullptr || pproplist->set(MetaTagCnsetRead, s.get()) != 0)
			return NULL;
	}
	if (!ext_push.init(nullptr, 0, 0) ||
	    ext_push.p_tpropval_a(*pproplist) != EXT_ERR_SUCCESS)
		return NULL;
	pproplist.reset();
	auto pbin = cu_alloc<BINARY>();
	if (pbin == nullptr)
		return nullptr;
	pbin->cb = ext_push.m_offset;
	pbin->pv = common_util_alloc(pbin->cb);
	if (pbin->pv == nullptr) {
		return NULL;
	}
	memcpy(pbin->pv, ext_push.m_udata, pbin->cb);
	return pbin;
}

BOOL ics_state::deserialize(const BINARY *pbin)
{
	auto pstate = this;
	int i;
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
		case MetaTagIdsetGiven1: {
			auto pset = idset::create(false, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
			    !pset->convert()) {
				return FALSE;
			}
			pstate->pgiven = std::move(pset);
			break;
		}
		case MetaTagCnsetSeen: {
			auto pset = idset::create(false, REPL_TYPE_ID);
			if (NULL == pset) {
				return FALSE;
			}
			if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
			    !pset->convert()) {
				return FALSE;
			}
			pstate->pseen = std::move(pset);
			break;
		}
		case MetaTagCnsetSeenFAI:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				auto pset = idset::create(false, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
				    !pset->convert()) {
					return FALSE;
				}
				pstate->pseen_fai = std::move(pset);
			}
			break;
		case MetaTagCnsetRead:
			if (ICS_TYPE_CONTENTS == pstate->type) {
				auto pset = idset::create(false, REPL_TYPE_ID);
				if (NULL == pset) {
					return FALSE;
				}
				if (!pset->deserialize(static_cast<BINARY *>(propvals.ppropval[i].pvalue)) ||
				    !pset->convert()) {
					return FALSE;
				}
				pstate->pread = std::move(pset);
			}
			break;
		}
	}
	return TRUE;
}

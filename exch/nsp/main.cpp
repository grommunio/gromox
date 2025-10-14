// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <libHX/string.h>
#include <gromox/ab_tree.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "common_util.hpp"
#include "nsp_interface.hpp"
#include "nsp_ndr.hpp"

using namespace gromox;
DECLARE_PROC_API(nsp, );

static int exchange_nsp_dispatch(unsigned int op, const GUID *obj, uint64_t handle, void *in, void **out, ec_error_t *);
static void exchange_nsp_unbind(uint64_t handle);

static DCERPC_ENDPOINT *ep_6001, *ep_6004;

static constexpr cfg_directive nsp_cfg_defaults[] = {
	{"cache_interval", "5min", CFG_TIME, "1s", "1d"},
	{"hash_table_size", "3000", CFG_SIZE, "1"},
	{"nsp_trace", "0"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static bool exch_nsp_reload(std::shared_ptr<CONFIG_FILE> cfg)
{
	if (cfg == nullptr)
		cfg = config_file_initd("exchange_nsp.cfg", get_config_path(),
		      nsp_cfg_defaults);
	if (cfg == nullptr) {
		mlog(LV_ERR, "nsp: config_file_initd exchange_nsp.cfg: %s",
		        strerror(errno));
		return false;
	}
	g_nsp_trace = cfg->get_ll("nsp_trace");
	return true;
}

static constexpr DCERPC_INTERFACE interface = {
	"exchangeNSP",
	/* {f5cc5a18-4264-101a-8c59-08002b2f8426} */
	{0xf5cc5a18, 0x4264, 0x101a, {0x8c, 0x59}, {0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26}},
	56, exchange_nsp_ndr_pull, exchange_nsp_dispatch, exchange_nsp_ndr_push,
	exchange_nsp_unbind,
};

BOOL PROC_exchange_nsp(enum plugin_op reason, const struct dlfuncs &ppdata)
{
	const char *org_name;
	int cache_interval;
	char temp_buff[45];
	
	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_PROC_API(ppdata);
		textmaps_init();
		/* get the plugin name from system api */
		auto pfile = config_file_initd("exchange_nsp.cfg",
		             get_config_path(), nsp_cfg_defaults);
		if (NULL == pfile) {
			mlog(LV_ERR, "nsp: config_file_initd exchange_nsp.cfg: %s", strerror(errno));
			return FALSE;
		}
		if (!exch_nsp_reload(pfile))
			return false;
		org_name = pfile->get_value("X500_ORG_NAME");
		mlog(LV_INFO, "nsp: x500 org name is \"%s\"", org_name);
		cache_interval = pfile->get_ll("cache_interval");
		HX_unit_seconds(temp_buff, std::size(temp_buff), cache_interval, 0);
		mlog(LV_INFO, "nsp: address book tree item"
				" cache interval is %s", temp_buff);
		ab_tree::AB.init(org_name, cache_interval);

		query_service2("exmdb_client_get_named_propids", get_named_propids);
		query_service2("exmdb_client_get_store_properties", get_store_properties);
		if (get_named_propids == nullptr || get_store_properties == nullptr)
			return false;
#define regsvr(n) register_service(#n, n)
		if (!regsvr(nsp_interface_bind) ||
		    !regsvr(nsp_interface_compare_mids) ||
		    !regsvr(nsp_interface_dntomid) ||
		    !regsvr(nsp_interface_get_matches) ||
		    !regsvr(nsp_interface_get_proplist) ||
		    !regsvr(nsp_interface_get_props) ||
		    !regsvr(nsp_interface_get_specialtable) ||
		    !regsvr(nsp_interface_get_templateinfo) ||
		    !regsvr(nsp_interface_mod_linkatt) ||
		    !regsvr(nsp_interface_mod_props) ||
		    !regsvr(nsp_interface_query_columns) ||
		    !regsvr(nsp_interface_query_rows) ||
		    !regsvr(nsp_interface_resolve_namesw) ||
		    !regsvr(nsp_interface_resort_restriction) ||
		    !regsvr(nsp_interface_seek_entries) ||
		    !regsvr(nsp_interface_unbind) ||
		    !regsvr(nsp_interface_update_stat)) {
			return false;
		}
#undef regsvr

		ep_6001 = register_endpoint("*", 6001);
		if (ep_6001 == nullptr) {
			mlog(LV_ERR, "nsp: failed to register endpoint with port 6001");
			return FALSE;
		}
		ep_6004 = register_endpoint("*", 6004);
		if (ep_6004 == nullptr) {
			mlog(LV_ERR, "nsp: failed to register endpoint with port 6004");
			return FALSE;
		}
		if (!register_interface(ep_6001, &interface) ||
		    !register_interface(ep_6004, &interface)) {
			mlog(LV_ERR, "nsp: failed to register interface");
			return FALSE;
		}
		if (0 != common_util_run()) {
			mlog(LV_ERR, "nsp: failed to run common util");
			return FALSE;
		}
		if (!ab_tree::AB.run()) {
			mlog(LV_ERR, "nsp: failed to run address book tree");
			return FALSE;
		}
		nsp_interface_init();
		return TRUE;
	}
	case PLUGIN_FREE:
		ab_tree::AB.stop();
		unregister_interface(ep_6004, &interface);
		unregister_interface(ep_6001, &interface);
		return TRUE;
	case PLUGIN_RELOAD:
		exch_nsp_reload(nullptr);
		ab_tree::AB.invalidate_cache();
		return TRUE;
	default:
		return TRUE;
	}
}

static int exchange_nsp_dispatch(unsigned int opnum, const GUID *pobject,
    uint64_t handle, void *pin, void **ppout, ec_error_t *ecode)
{
	switch (opnum) {
	case nspiBind: {
		auto in  = static_cast<const NSPIBIND_IN *>(pin);
		auto out = ndr_stack_anew<NSPIBIND_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->pserver_guid = in->pserver_guid;
		out->result = nsp_interface_bind(handle, in->flags, &in->stat,
		              in->pserver_guid, &out->handle);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiUnbind: {
		auto in  = static_cast<const NSPIUNBIND_IN *>(pin);
		auto out = ndr_stack_anew<NSPIUNBIND_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->handle = in->handle;
		out->result = nsp_interface_unbind(&out->handle, in->reserved);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiUpdateStat: {
		auto in  = static_cast<const NSPIUPDATESTAT_IN *>(pin);
		auto out = ndr_stack_anew<NSPIUPDATESTAT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->stat = in->stat;
		out->pdelta = in->pdelta;
		out->result = nsp_interface_update_stat(in->handle,
		              in->reserved, &out->stat, out->pdelta);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiQueryRows: {
		auto in  = static_cast<const NSPIQUERYROWS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIQUERYROWS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->stat = in->stat;
		out->result = nsp_interface_query_rows(in->handle, in->flags,
		              &out->stat, in->table_count, in->ptable, in->count,
		              in->pproptags, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiSeekEntries: {
		auto in  = static_cast<const NSPISEEKENTRIES_IN *>(pin);
		auto out = ndr_stack_anew<NSPISEEKENTRIES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->stat = in->stat;
		out->result = nsp_interface_seek_entries(in->handle,
		              in->reserved, &out->stat, &in->target, in->ptable,
		              in->pproptags, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiGetMatches: {
		auto in  = static_cast<const NSPIGETMATCHES_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETMATCHES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->stat = in->stat;
		out->result = nsp_interface_get_matches(in->handle,
		              in->reserved1, &out->stat, in->ptable,
		              in->reserved2, in->pfilter, in->ppropname,
		              in->requested, &out->poutmids, in->pproptags,
		              &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiResortRestriction: {
		auto in  = static_cast<const NSPIRESORTRESTRICTION_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESORTRESTRICTION_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->stat = in->stat;
		out->poutmids = in->poutmids;
		out->result = nsp_interface_resort_restriction(in->handle,
		              in->reserved, &out->stat, &in->inmids,
		              &out->poutmids);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiDNToMId: {
		auto in  = static_cast<const NSPIDNTOMID_IN *>(pin);
		auto out = ndr_stack_anew<NSPIDNTOMID_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_dntomid(in->handle, in->reserved,
		              &in->names, &out->poutmids);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiGetPropList: {
		auto in  = static_cast<const NSPIGETPROPLIST_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETPROPLIST_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_proplist(in->handle, in->flags,
		              in->mid, static_cast<cpid_t>(in->codepage),
		              &out->pproptags);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiGetProps: {
		auto in  = static_cast<const NSPIGETPROPS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETPROPS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_props(in->handle, in->flags,
		              &in->stat, in->pproptags, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiCompareMIds: {
		auto in  = static_cast<const NSPICOMPAREMIDS_IN *>(pin);
		auto out = ndr_stack_anew<NSPICOMPAREMIDS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_compare_mids(in->handle,
		              in->reserved, &in->stat, in->mid1, in->mid2,
		              &out->cmp);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiModProps: {
		auto in  = static_cast<const NSPIMODPROPS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIMODPROPS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_mod_props(in->handle, in->reserved,
		              &in->stat, in->pproptags, &in->row);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiGetSpecialTable: {
		auto in  = static_cast<const NSPIGETSPECIALTABLE_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETSPECIALTABLE_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->version = in->version;
		out->result = nsp_interface_get_specialtable(in->handle,
		              in->flags, &in->stat, &out->version, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiGetTemplateInfo: {
		auto in  = static_cast<const NSPIGETTEMPLATEINFO_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETTEMPLATEINFO_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_templateinfo(in->handle,
		              in->flags, in->type, in->pdn,
		              static_cast<cpid_t>(in->codepage),
		              in->locale_id, &out->pdata);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiModLinkAtt: {
		auto in  = static_cast<const NSPIMODLINKATT_IN *>(pin);
		auto out = ndr_stack_anew<NSPIMODLINKATT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_mod_linkatt(in->handle, in->flags,
		              in->proptag, in->mid, &in->entry_ids);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiQueryColumns: {
		auto in  = static_cast<const NSPIQUERYCOLUMNS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIQUERYCOLUMNS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_query_columns(in->handle,
		              in->reserved, in->flags, &out->pcolumns);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiResolveNames: {
		auto in  = static_cast<const NSPIRESOLVENAMES_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESOLVENAMES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		auto tags = in->pproptags;
		out->result = nsp_interface_resolve_names(in->handle,
		              in->reserved, &in->stat, tags, &in->strs,
		              &out->pmids, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case nspiResolveNamesW: {
		auto in  = static_cast<const NSPIRESOLVENAMESW_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESOLVENAMESW_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		auto tags = in->pproptags;
		out->result = nsp_interface_resolve_namesw(in->handle,
		              in->reserved, &in->stat, tags, &in->strs,
		              &out->pmids, &out->prows);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static void exchange_nsp_unbind(uint64_t handle)
{
	nsp_interface_unbind_rpc_handle(handle);
}

// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include "nsp_ndr.h"
#include "ab_tree.h"
#include "common_util.h"
#include <gromox/proc_common.h>
#include <gromox/ndr_stack.hpp>
#include <gromox/config_file.hpp>
#include "nsp_interface.h"
#include <cstring>
#include <cstdio>

static int exchange_nsp_ndr_pull(int opnum, NDR_PULL* pndr, void **ppin);

static int exchange_nsp_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout);
static int exchange_nsp_ndr_push(int opnum, NDR_PUSH *pndr, void *pout);
static void exchange_nsp_unbind(uint64_t handle);

DECLARE_API();

static BOOL proc_exchange_nsp(int reason, void **ppdata)
{
	BOOL b_check;
	const char *org_name;
	int table_size;
	int max_item_num;
	void *pendpoint1;
	void *pendpoint2;
	int cache_interval;
	char temp_buff[45];
	char file_name[256];
	char temp_path[256], *psearch;
	DCERPC_INTERFACE interface;
	
	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		/* get the plugin name from system api */
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(temp_path, get_config_path());
		if (NULL == pfile) {
			printf("[exchange_nsp]: config_file_initd %s: %s\n",
			       temp_path, strerror(errno));
			return FALSE;
		}
		org_name = config_file_get_value(pfile, "X500_ORG_NAME");
		if (NULL == org_name) {
			org_name = "Gromox default";
		}
		printf("[exchange_nsp]: x500 org name is \"%s\"\n", org_name);
		auto str_value = config_file_get_value(pfile, "HASH_TABLE_SIZE");
		if (NULL == str_value) {
			table_size = 3000;
			config_file_set_value(pfile, "HASH_TABLE_SIZE", "3000");
		} else {
			table_size = atoi(str_value);
			if (table_size <= 0) {
				table_size = 3000;
				config_file_set_value(pfile, "HASH_TABLE_SIZE", "3000");
			}
		}
		printf("[exchange_nsp]: hash table size is %d\n", table_size);
		str_value = config_file_get_value(pfile, "CACHE_INTERVAL");
		if (NULL == str_value) {
			cache_interval = 300;
			config_file_set_value(pfile, "CACHE_INTERVAL", "5minutes");
		} else {
			cache_interval = atoitvl(str_value);
			if (cache_interval > 24*3600 || cache_interval < 60) {
				cache_interval = 300;
				config_file_set_value(pfile, "CACHE_INTERVAL", "5minutes");
			}
		}
		itvltoa(cache_interval, temp_buff);
		printf("[exchange_nsp]: address book tree item"
				" cache interval is %s\n", temp_buff);
		str_value = config_file_get_value(pfile, "MAX_ITEM_NUM");
		if (NULL == str_value) {
			max_item_num = 100000;
			config_file_set_value(pfile, "MAX_ITEM_NUM", "100000");
		} else {
			max_item_num = atoi(str_value);
			if (max_item_num <= 0) {
				max_item_num = 100000;
				config_file_set_value(pfile, "MAX_ITEM_NUM", "100000");
			}
		}
		printf("[exchange_nsp]: maximum item number is %d\n", max_item_num);
		str_value = config_file_get_value(pfile, "SESSION_CHECK");
		if (NULL != str_value && (0 == strcasecmp(str_value,
			"ON") || 0 == strcasecmp(str_value, "TRUE"))) {
			b_check = TRUE;
			printf("[exchange_nsp]: bind session will be checked\n");
		} else {
			b_check = FALSE;
		}
		ab_tree_init(org_name, table_size, cache_interval, max_item_num);
		pendpoint1 = register_endpoint("*", 6001);
		if (NULL == pendpoint1) {
			printf("[exchange_nsp]: failed to register endpoint with port 6001\n");
			return FALSE;
		}
		pendpoint2 = register_endpoint("*", 6004);
		if (NULL == pendpoint2) {
			printf("[exchange_nsp]: failed to register endpoint with port 6004\n");
			return FALSE;
		}
		strcpy(interface.name, "exchangeNSP");
		guid_from_string(&interface.uuid, "f5cc5a18-4264-101a-8c59-08002b2f8426");
		interface.version = 56;
		interface.ndr_pull = exchange_nsp_ndr_pull;
		interface.dispatch = exchange_nsp_dispatch;
		interface.ndr_push = exchange_nsp_ndr_push;
		interface.unbind = exchange_nsp_unbind;
		interface.reclaim = NULL;
		if (FALSE == register_interface(pendpoint1, &interface) ||
			FALSE == register_interface(pendpoint2, &interface)) {
			printf("[exchange_nsp]: failed to register interface\n");
			return FALSE;
		}
		if (0 != common_util_run()) {
			printf("[exchange_nsp]: failed to run common util\n");
			return FALSE;
		}
		if (0 != ab_tree_run()) {
			printf("[exchange_nsp]: failed to run address book tree\n");
			return FALSE;
		}
		nsp_interface_init(b_check);
		if (0 != nsp_interface_run()) {
			printf("[exchange_nsp]: failed to run nsp interface\n");
			return FALSE;
		}
		printf("[exchange_nsp]: plugin is loaded into system\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		ab_tree_stop();
		ab_tree_free();
		return TRUE;
	}
	return false;
}
PROC_ENTRY(proc_exchange_nsp);

static int exchange_nsp_ndr_pull(int opnum, NDR_PULL* pndr, void **ppin)
{
	
	switch (opnum) {
	case 0:
		*ppin = ndr_stack_anew<NSPIBIND_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspibind(pndr, static_cast<NSPIBIND_IN *>(*ppin));
	case 1:
		*ppin = ndr_stack_anew<NSPIUNBIND_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiunbind(pndr, static_cast<NSPIUNBIND_IN *>(*ppin));
	case 2:
		*ppin = ndr_stack_anew<NSPIUPDATESTAT_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiupdatestat(pndr, static_cast<NSPIUPDATESTAT_IN *>(*ppin));
	case 3:
		*ppin = ndr_stack_anew<NSPIQUERYROWS_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiqueryrows(pndr, static_cast<NSPIQUERYROWS_IN *>(*ppin));
	case 4:
		*ppin = ndr_stack_anew<NSPISEEKENTRIES_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiseekentries(pndr, static_cast<NSPISEEKENTRIES_IN *>(*ppin));
	case 5:
		*ppin = ndr_stack_anew<NSPIGETMATCHES_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspigetmatches(pndr, static_cast<NSPIGETMATCHES_IN *>(*ppin));
	case 6:
		*ppin = ndr_stack_anew<NSPIRESORTRESTRICTION_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiresortrestriction(pndr, static_cast<NSPIRESORTRESTRICTION_IN *>(*ppin));
	case 7:
		*ppin = ndr_stack_anew<NSPIDNTOMID_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspidntomid(pndr, static_cast<NSPIDNTOMID_IN *>(*ppin));
	case 8:
		*ppin = ndr_stack_anew<NSPIGETPROPLIST_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspigetproplist(pndr, static_cast<NSPIGETPROPLIST_IN *>(*ppin));
	case 9:
		*ppin = ndr_stack_anew<NSPIGETPROPS_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspigetprops(pndr, static_cast<NSPIGETPROPS_IN *>(*ppin));
	case 10:
		*ppin = ndr_stack_anew<NSPICOMPAREMIDS_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspicomparemids(pndr, static_cast<NSPICOMPAREMIDS_IN *>(*ppin));
	case 11:
		*ppin = ndr_stack_anew<NSPIMODPROPS_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspimodprops(pndr, static_cast<NSPIMODPROPS_IN *>(*ppin));
	case 12:
		*ppin = ndr_stack_anew<NSPIGETSPECIALTABLE_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspigetspecialtable(pndr, static_cast<NSPIGETSPECIALTABLE_IN *>(*ppin));
	case 13:
		*ppin = ndr_stack_anew<NSPIGETTEMPLATEINFO_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspigettemplateinfo(pndr, static_cast<NSPIGETTEMPLATEINFO_IN *>(*ppin));
	case 14:
		*ppin = ndr_stack_anew<NSPIMODLINKATT_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspimodlinkatt(pndr, static_cast<NSPIMODLINKATT_IN *>(*ppin));
	case 16:
		*ppin = ndr_stack_anew<NSPIQUERYCOLUMNS_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiquerycolumns(pndr, static_cast<NSPIQUERYCOLUMNS_IN *>(*ppin));
	case 19:
		*ppin = ndr_stack_anew<NSPIRESOLVENAMES_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiresolvenames(pndr, static_cast<NSPIRESOLVENAMES_IN *>(*ppin));
	case 20:
		*ppin = ndr_stack_anew<NSPIRESOLVENAMESW_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return nsp_ndr_pull_nspiresolvenamesw(pndr, static_cast<NSPIRESOLVENAMESW_IN *>(*ppin));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static int exchange_nsp_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	
	switch (opnum) {
	case 0: {
		auto in  = static_cast<NSPIBIND_IN *>(pin);
		auto out = ndr_stack_anew<NSPIBIND_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_bind(handle, in->flags, &in->stat,
		              in->pserver_guid, &out->handle);
		out->pserver_guid = in->pserver_guid;
		return DISPATCH_SUCCESS;
	}
	case 1: {
		auto in  = static_cast<NSPIUNBIND_IN *>(pin);
		auto out = ndr_stack_anew<NSPIUNBIND_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_unbind(&in->handle, in->reserved);
		out->handle = in->handle;
		return DISPATCH_SUCCESS;
	}
	case 2: {
		auto in  = static_cast<NSPIUPDATESTAT_IN *>(pin);
		auto out = ndr_stack_anew<NSPIUPDATESTAT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_update_stat(in->handle,
		              in->reserved, &in->stat, in->pdelta);
		out->stat = in->stat;
		out->pdelta = in->pdelta;
		return DISPATCH_SUCCESS;
	}
	case 3: {
		auto in  = static_cast<NSPIQUERYROWS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIQUERYROWS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_query_rows(in->handle, in->flags,
		              &in->stat, in->table_count, in->ptable, in->count,
		              in->pproptags, &out->prows);
		out->stat = in->stat;
		return DISPATCH_SUCCESS;
	}
	case 4: {
		auto in  = static_cast<NSPISEEKENTRIES_IN *>(pin);
		auto out = ndr_stack_anew<NSPISEEKENTRIES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_seek_entries(in->handle,
		              in->reserved, &in->stat, &in->target, in->ptable,
		              in->pproptags, &out->prows);
		out->stat = in->stat;
		return DISPATCH_SUCCESS;
	}
	case 5: {
		auto in  = static_cast<NSPIGETMATCHES_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETMATCHES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_matches(in->handle,
		              in->reserved1, &in->stat, in->preserved,
		              in->reserved2, in->pfilter, in->ppropname,
		              in->requested, &out->poutmids, in->pproptags,
		              &out->prows);
		out->stat = in->stat;
		return DISPATCH_SUCCESS;
	}
	case 6: {
		auto in  = static_cast<NSPIRESORTRESTRICTION_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESORTRESTRICTION_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_resort_restriction(in->handle,
		              in->reserved, &in->stat, &in->inmids,
		              &in->poutmids);
		out->stat = in->stat;
		out->poutmids = in->poutmids;
		return DISPATCH_SUCCESS;
	}
	case 7: {
		auto in  = static_cast<NSPIDNTOMID_IN *>(pin);
		auto out = ndr_stack_anew<NSPIDNTOMID_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_dntomid(in->handle, in->reserved,
		              &in->names, &out->poutmids);
		return DISPATCH_SUCCESS;
	}
	case 8: {
		auto in  = static_cast<NSPIGETPROPLIST_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETPROPLIST_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_proplist(in->handle, in->flags,
		              in->mid, in->codepage, &out->pproptags);
		return DISPATCH_SUCCESS;
	}
	case 9: {
		auto in  = static_cast<NSPIGETPROPS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETPROPS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_props(in->handle, in->flags,
		              &in->stat, in->pproptags, &out->prows);
		return DISPATCH_SUCCESS;
	}
	case 10: {
		auto in  = static_cast<NSPICOMPAREMIDS_IN *>(pin);
		auto out = ndr_stack_anew<NSPICOMPAREMIDS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result1 = nsp_interface_compare_mids(in->handle,
		               in->reserved, &in->stat, in->mid1, in->mid2,
		               &out->result);
		return DISPATCH_SUCCESS;
	}
	case 11: {
		auto in  = static_cast<NSPIMODPROPS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIMODPROPS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_mod_props(in->handle, in->reserved,
		              &in->stat, in->pproptags, &in->row);
		return DISPATCH_SUCCESS;
	}
	case 12: {
		auto in  = static_cast<NSPIGETSPECIALTABLE_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETSPECIALTABLE_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_specialtable(in->handle,
		              in->flags, &in->stat, &in->version, &out->prows);
		out->version = in->version;
		return DISPATCH_SUCCESS;
	}
	case 13: {
		auto in  = static_cast<NSPIGETTEMPLATEINFO_IN *>(pin);
		auto out = ndr_stack_anew<NSPIGETTEMPLATEINFO_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_get_templateinfo(in->handle,
		              in->flags, in->type, in->pdn, in->codepage,
		              in->locale_id, &out->pdata);
		return DISPATCH_SUCCESS;
	}
	case 14: {
		auto in  = static_cast<NSPIMODLINKATT_IN *>(pin);
		auto out = ndr_stack_anew<NSPIMODLINKATT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_mod_linkatt(in->handle, in->flags,
		              in->proptag, in->mid, &in->entry_ids);
		return DISPATCH_SUCCESS;
	}
	case 16: {
		auto in  = static_cast<NSPIQUERYCOLUMNS_IN *>(pin);
		auto out = ndr_stack_anew<NSPIQUERYCOLUMNS_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_query_columns(in->handle,
		              in->reserved, in->flags, &out->pcolumns);
		return DISPATCH_SUCCESS;
	}
	case 19: {
		auto in  = static_cast<NSPIRESOLVENAMES_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESOLVENAMES_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_resolve_names(in->handle,
		              in->reserved, &in->stat, in->pproptags, &in->strs,
		              &out->pmids, &out->prows);
		return DISPATCH_SUCCESS;
	}
	case 20: {
		auto in  = static_cast<NSPIRESOLVENAMESW_IN *>(pin);
		auto out = ndr_stack_anew<NSPIRESOLVENAMESW_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = nsp_interface_resolve_namesw(in->handle,
		              in->reserved, &in->stat, in->pproptags, &in->strs,
		              &out->pmids, &out->prows);
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static int exchange_nsp_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	
	switch (opnum) {
	case 0:
		return nsp_ndr_push_nspibind(pndr, static_cast<NSPIBIND_OUT *>(pout));
	case 1:
		return nsp_ndr_push_nspiunbind(pndr, static_cast<NSPIUNBIND_OUT *>(pout));
	case 2:
		return nsp_ndr_push_nspiupdatestat(pndr, static_cast<NSPIUPDATESTAT_OUT *>(pout));
	case 3:
		return nsp_ndr_push_nspiqueryrows(pndr, static_cast<NSPIQUERYROWS_OUT *>(pout));
	case 4:
		return nsp_ndr_push_nspiseekentries(pndr, static_cast<NSPISEEKENTRIES_OUT *>(pout));
	case 5:
		return nsp_ndr_push_nspigetmatches(pndr, static_cast<NSPIGETMATCHES_OUT *>(pout));
	case 6:
		return nsp_ndr_push_nspiresortrestriction(pndr, static_cast<NSPIRESORTRESTRICTION_OUT *>(pout));
	case 7:
		return nsp_ndr_push_nspidntomid(pndr, static_cast<NSPIDNTOMID_OUT *>(pout));
	case 8:
		return nsp_ndr_push_nspigetproplist(pndr, static_cast<NSPIGETPROPLIST_OUT *>(pout));
	case 9:
		return nsp_ndr_push_nspigetprops(pndr, static_cast<NSPIGETPROPS_OUT *>(pout));
	case 10:
		return nsp_ndr_push_nspicomparemids(pndr, static_cast<NSPICOMPAREMIDS_OUT *>(pout));
	case 11:
		return nsp_ndr_push_nspimodprops(pndr, static_cast<NSPIMODPROPS_OUT *>(pout));
	case 12:
		return nsp_ndr_push_nspigetspecialtable(pndr, static_cast<NSPIGETSPECIALTABLE_OUT *>(pout));
	case 13:
		return nsp_ndr_push_nspigettemplateinfo(pndr, static_cast<NSPIGETTEMPLATEINFO_OUT *>(pout));
	case 14:
		return nsp_ndr_push_nspimodlinkatt(pndr, static_cast<NSPIMODLINKATT_OUT *>(pout));
	case 16:
		return nsp_ndr_push_nspiquerycolumns(pndr, static_cast<NSPIQUERYCOLUMNS_OUT *>(pout));
	case 19:
		return nsp_ndr_push_nspiresolvenames(pndr, static_cast<NSPIRESOLVENAMES_OUT *>(pout));
	case 20:
		return nsp_ndr_push_nspiresolvenamesw(pndr, static_cast<NSPIRESOLVENAMESW_OUT *>(pout));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static void exchange_nsp_unbind(uint64_t handle)
{
	nsp_interface_unbind_rpc_handle(handle);
}

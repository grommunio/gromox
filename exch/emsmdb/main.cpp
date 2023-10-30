// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <libHX/string.h>
#include <gromox/bounce_gen.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/paths.h>
#include <gromox/proc_common.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>
#include "asyncemsmdb_interface.h"
#include "common_util.h"
#include "emsmdb_interface.h"
#include "emsmdb_ndr.h"
#include "exmdb_client.h"
#include "logon_object.h"
#include "rop_dispatch.h"
#include "rop_processor.h"

using namespace std::string_literals;
using namespace gromox;

static int exchange_emsmdb_dispatch(unsigned int op, const GUID *obj, uint64_t handle, void *in, void **out, uint32_t *ecode);
static void exchange_emsmdb_unbind(uint64_t handle);
static int exchange_async_emsmdb_dispatch(unsigned int op, const GUID *obj, uint64_t handle, void *in, void **out, uint32_t *ecode);
static void exchange_async_emsmdb_reclaim(uint32_t async_id);

DECLARE_PROC_API();
static DCERPC_ENDPOINT *ep_6001;

static constexpr cfg_directive emsmdb_gxcfg_dflt[] = {
	{"backfill_transport_headers", "0", CFG_BOOL},
	CFG_TABLE_END,
};

static constexpr cfg_directive emsmdb_cfg_defaults[] = {
	{"async_threads_num", "4", CFG_SIZE, "1", "20"},
	{"average_handles", "1000", CFG_SIZE, "100"},
	{"average_mem", "4K", CFG_SIZE, "4K"},
	{"ems_max_active_notifh", "0", CFG_SIZE, "0"},
	{"ems_max_active_sessions", "0", CFG_SIZE, "0"},
	{"ems_max_active_users", "0", CFG_SIZE, "0"},
	{"ems_max_pending_sesnotif", "1K", CFG_SIZE, "0"},
	{"emsmdb_max_cxh_per_user", "100", CFG_SIZE, "100"},
	{"emsmdb_max_obh_per_session", "500", CFG_SIZE, "500"},
	{"emsmdb_private_folder_softdelete", "0", CFG_BOOL},
	{"emsmdb_rop_chaining", "1"},
	{"mailbox_ping_interval", "5min", CFG_TIME, "60s", "1h"},
	{"max_ext_rule_length", "510K", CFG_SIZE, "1"},
	{"max_mail_length", "64M", CFG_SIZE, "1"},
	{"max_mail_num", "1000000", CFG_SIZE, "1"},
	{"max_rcpt_num", "256", CFG_SIZE, "1"},
	{"rop_debug", "0"},
	{"smtp_server_ip", "::1"},
	{"smtp_server_port", "25"},
	{"submit_command", "/usr/bin/php " PKGDATADIR "/sa/submit.php"},
	{"x500_org_name", "Gromox default"},
	CFG_TABLE_END,
};

static bool exch_emsmdb_reload(std::shared_ptr<CONFIG_FILE> gxcfg,
    std::shared_ptr<CONFIG_FILE> pconfig) try
{
	if (gxcfg == nullptr)
		gxcfg = config_file_initd("gromox.cfg", get_config_path(), emsmdb_gxcfg_dflt);
	if (gxcfg == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd gromox.cfg: %s",
		       strerror(errno));
		return false;
	}
	emsmdb_backfill_transporthdr = gxcfg->get_ll("backfill_transport_headers");

	if (pconfig == nullptr)
		pconfig = config_file_initd("exchange_emsmdb.cfg", get_config_path(),
		          emsmdb_cfg_defaults);
	if (pconfig == nullptr) {
		mlog(LV_ERR, "exmdb_provider: config_file_initd exmdb_provider.cfg: %s",
		       strerror(errno));
		return false;
	}
	g_rop_debug = pconfig->get_ll("rop_debug");
	emsmdb_max_cxh_per_user = pconfig->get_ll("emsmdb_max_cxh_per_user");
	emsmdb_max_obh_per_session = pconfig->get_ll("emsmdb_max_obh_per_session");
	emsmdb_pvt_folder_softdel = pconfig->get_ll("emsmdb_private_folder_softdelete");
	emsmdb_rop_chaining = pconfig->get_ll("emsmdb_rop_chaining");
	ems_max_active_notifh = pconfig->get_ll("ems_max_active_notifh");
	ems_max_active_sessions = pconfig->get_ll("ems_max_active_sessions");
	ems_max_active_users = pconfig->get_ll("ems_max_active_users");
	ems_max_pending_sesnotif = pconfig->get_ll("ems_max_pending_sesnotif");
	return true;
} catch (const cfg_error &) {
	return false;
}

static constexpr DCERPC_INTERFACE interface_emsmdb = {
	"exchangeEMSMDB",
	/* {a4f1db00-ca47-1067-b31f-00dd010662da} */
	{0xa4f1db00, 0xca47, 0x1067, {0xb3, 0x1f}, {0x00, 0xdd, 0x01, 0x06, 0x62, 0xda}},
	0x510000, emsmdb_ndr_pull, exchange_emsmdb_dispatch,
	emsmdb_ndr_push, exchange_emsmdb_unbind,
};

static constexpr DCERPC_INTERFACE interface_async_emsmdb = {
	"exchangeAsyncEMSMDB",
	/* {5261574a-4572-206e-b268-6b199213b4e4} */
	{0x5261574a, 0x4572, 0x206e, {0xb2, 0x68}, {0x6b, 0x19, 0x92, 0x13, 0xb4, 0xe4}},
	0x10000, asyncemsmdb_ndr_pull, exchange_async_emsmdb_dispatch,
	asyncemsmdb_ndr_push, nullptr, exchange_async_emsmdb_reclaim,
};

extern void emsmdb_report();
static BOOL proc_exchange_emsmdb(int reason, void **ppdata) try
{
	int max_mail;
	int max_rcpt;
	int async_num;
	uint16_t smtp_port;
	int max_length;
	int max_rule_len;
	char smtp_ip[40];
	int ping_interval;
	int average_blocks;
	char org_name[256];
	int average_handles;
	char submit_command[1024];
	
	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_RELOAD:
		exch_emsmdb_reload(nullptr, nullptr);
		return TRUE;
	case PLUGIN_REPORT:
		emsmdb_report();
		return TRUE;
	case PLUGIN_INIT: {
		LINK_PROC_API(ppdata);
		textmaps_init();
		auto pfile = config_file_initd("exchange_emsmdb.cfg",
		             get_config_path(), emsmdb_cfg_defaults);
		if (NULL == pfile) {
			mlog(LV_ERR, "emsmdb: config_file_initd exchange_emsmdb.cfg: %s",
			       strerror(errno));
			return FALSE;
		}
		if (!exch_emsmdb_reload(nullptr, pfile))
			return false;
		gx_strlcpy(org_name, pfile->get_value("x500_org_name"), std::size(org_name));
		average_handles = pfile->get_ll("average_handles");
		average_blocks = pfile->get_ll("average_mem") / 256;
		max_rcpt = pfile->get_ll("max_rcpt_num");
		max_mail = pfile->get_ll("max_mail_num");
		char max_length_s[32], max_rule_len_s[32], ping_int_s[32];
		max_length = pfile->get_ll("max_mail_length");
		max_rule_len = pfile->get_ll("max_ext_rule_length");
		HX_unit_size(max_rule_len_s, std::size(max_rule_len_s), max_rule_len, 1024, 0);
		ping_interval = pfile->get_ll("mailbox_ping_interval");
		HX_unit_seconds(ping_int_s, std::size(ping_int_s), ping_interval, 0);
		HX_unit_size(max_length_s, std::size(max_length_s), max_length, 1024, 0);
		gx_strlcpy(smtp_ip, pfile->get_value("smtp_server_ip"), std::size(smtp_ip));
		smtp_port = pfile->get_ll("smtp_server_port");
		gx_strlcpy(submit_command, pfile->get_value("submit_command"), std::size(submit_command));
		async_num = pfile->get_ll("async_threads_num");

		mlog(LV_INFO, "emsmdb: x500=\"%s\", "
		        "avg_handles=%d, avgmem_per_ctx=%d*256, max_rcpt=%d, "
		        "max_mail=%d, max_mail_len=%s, max_ext_rule_len=%s, "
		        "ping_int=%s, async_threads=%d, smtp=[%s]:%hu",
		       org_name, average_handles, average_blocks, max_rcpt,
		       max_mail, max_length_s, max_rule_len_s, ping_int_s,
		       async_num, smtp_ip, smtp_port);
		
#define regsvr(f) register_service(#f, f)
		if (!regsvr(asyncemsmdb_interface_async_wait) ||
		    !regsvr(asyncemsmdb_interface_register_active) ||
		    !regsvr(asyncemsmdb_interface_remove) ||
		    !regsvr(emsmdb_interface_connect_ex) ||
		    !regsvr(emsmdb_interface_disconnect) ||
		    !regsvr(emsmdb_interface_rpc_ext2) ||
		    !regsvr(emsmdb_interface_touch_handle)) {
			mlog(LV_ERR, "emsmdb: service interface registration failure");
			return false;
		}
#undef regsvr

		/* host can include wildcard */
		ep_6001 = register_endpoint("*", 6001);
		if (ep_6001 == nullptr) {
			mlog(LV_ERR, "emsmdb: failed to register endpoint with port 6001");
			return FALSE;
		}
		if (!register_interface(ep_6001, &interface_emsmdb) ||
		    !register_interface(ep_6001, &interface_async_emsmdb)) {
			mlog(LV_ERR, "emsmdb: failed to register emsmdb interface");
			return FALSE;
		}
		common_util_init(org_name, average_blocks, max_rcpt, max_mail,
			max_length, max_rule_len, smtp_ip, smtp_port, submit_command);
		msgchg_grouping_init(get_data_path());
		rop_processor_init(average_handles, ping_interval);
		emsmdb_interface_init();
		asyncemsmdb_interface_init(async_num);
		if (bounce_gen_init(get_config_path(), get_data_path(),
		    "notify_bounce") != 0) {
			mlog(LV_ERR, "emsmdb: failed to run bounce producer");
			return FALSE;
		}
		if (0 != common_util_run()) {
			mlog(LV_ERR, "emsmdb: failed to run common util");
			return FALSE;
		}
		if (exmdb_client::run() != 0) {
			mlog(LV_ERR, "emsmdb: failed to run exmdb client");
			return FALSE;
		}
		if (0 != msgchg_grouping_run()) {
			mlog(LV_ERR, "emsmdb: failed to run msgchg grouping");
			return FALSE;
		}
		if (0 != emsmdb_interface_run()) {
			mlog(LV_ERR, "emsmdb: failed to run emsmdb interface");
			return FALSE;
		}
		if (0 != asyncemsmdb_interface_run()) {
			mlog(LV_ERR, "emsmdb: failed to run asyncemsmdb interface");
			return FALSE;
		}
		if (0 != rop_processor_run()) {
			mlog(LV_ERR, "emsmdb: failed to run rop processor");
			return FALSE;
		}
		return TRUE;
	}
	case PLUGIN_FREE:
		asyncemsmdb_interface_stop();
		emsmdb_interface_stop();
		rop_processor_stop();
		msgchg_grouping_stop();
		asyncemsmdb_interface_free();
		msgchg_grouping_free();
		return TRUE;
	}
	return TRUE;
} catch (const cfg_error &) {
	return false;
}
PROC_ENTRY(proc_exchange_emsmdb);

static int exchange_emsmdb_dispatch(unsigned int opnum, const GUID *pobject,
    uint64_t handle, void *pin, void **ppout, uint32_t *ecode)
{
	switch (opnum) {
	case ecDoDisconnect: {
		auto in  = static_cast<ECDOASYNCCONNECTEX_IN *>(pin);
		auto out = ndr_stack_anew<ECDODISCONNECT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_disconnect(in->cxh);
		out->cxh = in->cxh;
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case ecRRegisterPushNotification: {
		auto in  = static_cast<ECRREGISTERPUSHNOTIFICATION_IN *>(pin);
		auto out = ndr_stack_anew<ECRREGISTERPUSHNOTIFICATION_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_register_push_notification(&in->cxh,
		              in->rpc, in->pctx, in->cb_ctx, in->advise_bits,
		              in->paddr, in->cb_addr, &out->hnotification);
		out->cxh = in->cxh;
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case ecDummyRpc:
		*ppout = ndr_stack_anew<int32_t>(NDR_STACK_OUT);
		if (*ppout == nullptr)
			return DISPATCH_FAIL;
		*static_cast<int32_t *>(*ppout) = emsmdb_interface_dummy_rpc(handle);
		return DISPATCH_SUCCESS;
	case ecDoConnectEx: {
		auto in  = static_cast<ECDOCONNECTEX_IN *>(pin);
		auto out = ndr_stack_anew<ECDOCONNECTEX_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_connect_ex(handle, &out->cxh,
		              in->puserdn, in->flags, in->conmod, in->limit,
		              in->cpid, in->lcid_string, in->lcid_sort,
		              in->cxr_link, in->cnvt_cps, &out->max_polls,
		              &out->max_retry, &out->retry_delay, &out->cxr,
		              out->pdn_prefix, out->pdisplayname,
		              in->pclient_vers, out->pserver_vers,
		              out->pbest_vers, &in->timestamp, in->pauxin,
		              in->cb_auxin, out->pauxout, &in->cb_auxout);
		out->timestamp = in->timestamp;
		out->cb_auxout = in->cb_auxout;
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case ecDoRpcExt2: {
		auto in  = static_cast<ECDORPCEXT2_IN *>(pin);
		auto out = ndr_stack_anew<ECDORPCEXT2_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_rpc_ext2(in->cxh, &in->flags,
		              in->pin, in->cb_in, out->pout, &in->cb_out,
		              in->pauxin, in->cb_auxin, out->pauxout,
		              &in->cb_auxout, &out->trans_time);
		out->cxh = in->cxh;
		out->flags = in->flags;
		out->cb_out = in->cb_out;
		out->cb_auxout = in->cb_auxout;
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	case ecDoAsyncConnectEx: {
		auto in  = static_cast<ECDOASYNCCONNECTEX_IN *>(pin);
		auto out = ndr_stack_anew<ECDOASYNCCONNECTEX_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_async_connect_ex(in->cxh, &out->acxh);
		*ecode = out->result;
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static void exchange_emsmdb_unbind(uint64_t handle)
{
	emsmdb_interface_unbind_rpc_handle(handle);
}

static int exchange_async_emsmdb_dispatch(unsigned int opnum, const GUID *pobject,
    uint64_t handle, void *pin, void **ppout, uint32_t *ecode)
{
	int result;
	uint32_t async_id;
	
	switch (opnum) {
	case ecDoAsyncWaitEx: {
		auto pout = ndr_stack_anew<ECDOASYNCWAITEX_OUT>(NDR_STACK_OUT);
		*ppout = pout;
		if (*ppout == nullptr)
			return DISPATCH_FAIL;
		async_id = apply_async_id();
		if (async_id == 0)
			return DISPATCH_FAIL;
		result = asyncemsmdb_interface_async_wait(async_id, static_cast<ECDOASYNCWAITEX_IN *>(pin), pout);
		if (result == DISPATCH_PENDING)
			activate_async_id(async_id);
		else
			cancel_async_id(async_id);
		*ecode = pout->result;
		return result;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static void exchange_async_emsmdb_reclaim(uint32_t async_id)
{
	asyncemsmdb_interface_reclaim(async_id);
}

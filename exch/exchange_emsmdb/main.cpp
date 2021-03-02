// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cerrno>
#include <cstdint>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/paths.h>
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/mail_func.hpp>
#include "emsmdb_ndr.h"
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/config_file.hpp>
#include "logon_object.h"
#include "exmdb_client.h"
#include "rop_processor.h"
#include "bounce_producer.h"
#include "msgchg_grouping.h"
#include "asyncemsmdb_ndr.h"
#include "emsmdb_interface.h"
#include "asyncemsmdb_interface.h"
#include <cstring>
#include <cstdio>

static int exchange_emsmdb_ndr_pull(int opnum, NDR_PULL* pndr, void **pin);

static int exchange_emsmdb_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout);

static int exchange_emsmdb_ndr_push(int opnum, NDR_PUSH *pndr, void *pout);

static void exchange_emsmdb_unbind(uint64_t handle);

static int exchange_async_emsmdb_ndr_pull(int opnum,
	NDR_PULL* pndr, void **pin);

static int exchange_async_emsmdb_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout);

static int exchange_async_emsmdb_ndr_push(int opnum,
	NDR_PUSH *pndr, void *pout);

static void exchange_async_emsmdb_reclaim(uint32_t async_id);

DECLARE_API();

static BOOL proc_exchange_emsmdb(int reason, void **ppdata)
{
	int max_mail;
	int max_rcpt;
	int async_num;
	uint16_t smtp_port;
	int max_length;
	void *pendpoint;
	int max_rule_len;
	char smtp_ip[40];
	int ping_interval;
	int average_blocks;
	char size_buff[32];
	char separator[16];
	char org_name[256];
	int average_handles;
	char temp_buff[256];
	char file_name[256];
	char temp_path[256];
	char submit_command[1024], *psearch;
	DCERPC_INTERFACE interface_emsmdb;
	DCERPC_INTERFACE interface_async_emsmdb;
	
	/* path contains the config files directory */
	switch (reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		HX_strlcpy(file_name, get_plugin_name(), GX_ARRAY_SIZE(file_name));
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		snprintf(temp_path, GX_ARRAY_SIZE(temp_path), "%s.cfg", file_name);
		auto pfile = config_file_initd(temp_path, get_config_path());
		if (NULL == pfile) {
			printf("[exchange_emsmdb]: config_file_initd %s: %s\n",
			       temp_path, strerror(errno));
			return FALSE;
		}
		auto str_value = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_value);
		}
		str_value = config_file_get_value(pfile, "X500_ORG_NAME");
		if (NULL == str_value || '\0' == str_value[0]) {
			HX_strlcpy(org_name, "Gromox default", sizeof(org_name));
		} else {
			strcpy(org_name, str_value);
		}
		printf("[exchange_emsmdb]: x500 org name is \"%s\"\n", org_name);
		str_value = config_file_get_value(pfile, "AVERAGE_HANDLES");
		if (NULL == str_value) {
			average_handles = 1000;
			config_file_set_value(pfile, "AVERAGE_HANDLES", "1000");
		} else {
			average_handles = atoi(str_value);
			if (average_handles < 100) {
				average_handles = 100;
				config_file_set_value(pfile, "AVERAGE_HANDLES", "100");
			}
		}
		printf("[exchange_emsmdb]: average handles number "
			"per context is %d\n", average_handles);
		str_value = config_file_get_value(pfile, "AVERAGE_MEM");
		if (NULL == str_value) {
			average_blocks = 16;
			config_file_set_value(pfile, "AVERAGE_MEM", "4K");
		} else {
			average_blocks = atobyte(str_value);
			if (average_blocks < 256*16) {
				average_blocks = 256*16;
				config_file_set_value(pfile, "AVERAGE_MEM", "4K");
			}
			average_blocks /= 256;
		}
		printf("[exchange_emsmdb]: average memory per"
				" context is %d*256\n", average_blocks);
		str_value = config_file_get_value(pfile, "MAX_RCPT_NUM");
		if (NULL == str_value) {
			max_rcpt = 256;
			config_file_set_value(pfile, "MAX_RCPT_NUM", "256");
		} else {
			max_rcpt = atoi(str_value);
			if (max_rcpt <= 0) {
				max_rcpt = 256;
				config_file_set_value(pfile, "MAX_RCPT_NUM", "256");
			}
		}
		printf("[exchange_emsmdb]: maximum rcpt number is %d\n", max_rcpt);
		str_value = config_file_get_value(pfile, "MAX_MAIL_NUM");
		if (NULL == str_value) {
			max_mail = 1000000;
			config_file_set_value(pfile, "MAX_MAIL_NUM", "1000000");
		} else {
			max_mail = atoi(str_value);
			if (max_mail <= 0) {
				max_mail = 1000000;
				config_file_set_value(pfile, "MAX_MAIL_NUM", "1000000");
			}
		}
		printf("[exchange_emsmdb]: maximum mail number is %d\n", max_mail);
		str_value = config_file_get_value(pfile, "MAIL_MAX_LENGTH");
		if (NULL == str_value) {
			max_length = 64*1024*1024;
			config_file_set_value(pfile, "MAIL_MAX_LENGTH", "64M");
		} else {
			max_length = atobyte(str_value);
			if (max_length <= 0) {
				max_length = 64*1024*1024;
				config_file_set_value(pfile, "MAIL_MAX_LENGTH", "64M");
			}
		}
		bytetoa(max_length, size_buff);
		printf("[exchange_emsmdb]: maximum mail length is %s\n", size_buff);
		str_value = config_file_get_value(pfile, "MAX_EXT_RULE_LENGTH");
		if (NULL == str_value) {
			max_rule_len = 510*1024;
			config_file_set_value(pfile, "MAX_EXT_RULE_LENGTH", "510K");
		} else {
			max_rule_len = atobyte(str_value);
			if (max_rule_len <= 0) {
				max_rule_len = 510*1024;
				config_file_set_value(pfile, "MAX_EXT_RULE_LENGTH", "510K");
			}
		}
		bytetoa(max_rule_len, size_buff);
		printf("[exchange_emsmdb]: maximum extended rule length is %s\n", size_buff);
		str_value = config_file_get_value(pfile, "MAILBOX_PING_INTERVAL");
		if (NULL == str_value) {
			ping_interval = 300;
			config_file_set_value(pfile, "MAILBOX_PING_INTERVAL", "5minutes");
		} else {
			ping_interval = atoitvl(str_value);
			if (ping_interval > 3600 || ping_interval < 60) {
				ping_interval = 300;
				config_file_set_value(pfile, "MAILBOX_PING_INTERVAL", "5minutes");
			}
		}
		itvltoa(ping_interval, temp_buff);
		printf("[exchange_emsmdb]: mailbox ping interval is %s\n",
			temp_buff);
		str_value = config_file_get_value(pfile, "SMTP_SERVER_IP");
		HX_strlcpy(smtp_ip, str_value != nullptr ? str_value : "::1",
		           GX_ARRAY_SIZE(smtp_ip));
		str_value = config_file_get_value(pfile, "SMTP_SERVER_PORT");
		if (NULL == str_value) {
			smtp_port = 25;
			config_file_set_value(pfile, "SMTP_SERVER_PORT", "25");
		} else {
			smtp_port = atoi(str_value);
			if (smtp_port <= 0) {
				smtp_port = 25;
				config_file_set_value(pfile, "SMTP_SERVER_PORT", "25");
			}
		}
		printf("[exchange_emsmdb]: smtp server is [%s]:%hu\n", smtp_ip, smtp_port);
		str_value = config_file_get_value(pfile, "SUBMIT_COMMAND");
		if (str_value == nullptr)
			strcpy(submit_command, "/usr/bin/php " PKGDATADIR "/sa/submit.php");
		else
			strcpy(submit_command, str_value);
		str_value = config_file_get_value(pfile, "ASYNC_THREADS_NUM");
		if (NULL == str_value) {
			async_num = 4;
			config_file_set_value(pfile, "ASYNC_THREADS_NUM", "4");
		} else {
			async_num = atoi(str_value);
			if (async_num <= 0 || async_num > 20) {
				async_num = 4;
				config_file_set_value(pfile, "ASYNC_THREADS_NUM", "4");
			}
		}
		printf("[exchange_emsmdb]: async threads number is %d\n", async_num);
		
		/* host can include wildcard */
		pendpoint = register_endpoint("*", 6001);
		if (NULL == pendpoint) {
			printf("[exchange_emsmdb]: failed to register endpoint with port 6001\n");
			return FALSE;
		}
		strcpy(interface_emsmdb.name, "exchangeEMSMDB");
		guid_from_string(&interface_emsmdb.uuid, "a4f1db00-ca47-1067-b31f-00dd010662da");
		interface_emsmdb.version = 0x510000;
		interface_emsmdb.ndr_pull = exchange_emsmdb_ndr_pull;
		interface_emsmdb.dispatch = exchange_emsmdb_dispatch;
		interface_emsmdb.ndr_push = exchange_emsmdb_ndr_push;
		interface_emsmdb.unbind = exchange_emsmdb_unbind;
		interface_emsmdb.reclaim = NULL;
		if (FALSE == register_interface(pendpoint, &interface_emsmdb)) {
			printf("[exchange_emsmdb]: failed to register emsmdb interface\n");
			return FALSE;
		}
		strcpy(interface_async_emsmdb.name, "exchangeAsyncEMSMDB");
		guid_from_string(&interface_async_emsmdb.uuid, "5261574a-4572-206e-b268-6b199213b4e4");
		interface_async_emsmdb.version = 0x10000;
		interface_async_emsmdb.ndr_pull = exchange_async_emsmdb_ndr_pull;
		interface_async_emsmdb.dispatch = exchange_async_emsmdb_dispatch;
		interface_async_emsmdb.ndr_push = exchange_async_emsmdb_ndr_push;
		interface_async_emsmdb.unbind = NULL;
		interface_async_emsmdb.reclaim = exchange_async_emsmdb_reclaim;
		if (FALSE == register_interface(pendpoint, &interface_async_emsmdb)) {
			printf("[exchange_emsmdb]: failed to register emsmdb interface\n");
			return FALSE;
		}
		bounce_producer_init(separator);
		common_util_init(org_name, average_blocks, max_rcpt, max_mail,
			max_length, max_rule_len, smtp_ip, smtp_port, submit_command);
		msgchg_grouping_init(get_data_path());
		emsmdb_interface_init();
		asyncemsmdb_interface_init(async_num);
		rop_processor_init(average_handles, ping_interval);
		if (bounce_producer_run(get_data_path()) != 0) {
			printf("[exchange_emsmdb]: failed to run bounce producer\n");
			return FALSE;
		}
		if (0 != common_util_run()) {
			printf("[exchange_emsmdb]: failed to run common util\n");
			return FALSE;
		}
		if (0 != exmdb_client_run()) {
			printf("[exchange_emsmdb]: failed to run exmdb client\n");
			return FALSE;
		}
		if (0 != msgchg_grouping_run()) {
			printf("[exchange_emsmdb]: failed to run msgchg grouping\n");
			return FALSE;
		}
		if (0 != emsmdb_interface_run()) {
			printf("[exchange_emsmdb]: failed to run emsmdb interface\n");
			return FALSE;
		}
		if (0 != asyncemsmdb_interface_run()) {
			printf("[exchange_emsmdb]: failed to run asyncemsmdb interface\n");
			return FALSE;
		}
		if (0 != rop_processor_run()) {
			printf("[exchange_emsmdb]: failed to run rop processor\n");
			return FALSE;
		}
		printf("[exchange_emsmdb]: plugin is loaded into system\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		rop_processor_stop();
		asyncemsmdb_interface_stop();
		emsmdb_interface_stop();
		msgchg_grouping_stop();
		common_util_stop();
		bounce_producer_stop();
		rop_processor_free();
		asyncemsmdb_interface_free();
		emsmdb_interface_free();
		msgchg_grouping_free();
		common_util_free();
		bounce_producer_free();
		return TRUE;
	}
	return false;
}
PROC_ENTRY(proc_exchange_emsmdb);

static int exchange_emsmdb_ndr_pull(int opnum, NDR_PULL* pndr, void **ppin)
{
	switch (opnum) {
	case 1:
		*ppin = ndr_stack_anew<ECDODISCONNECT_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdodisconnect(pndr, static_cast<ECDODISCONNECT_IN *>(*ppin));
	case 4:
		*ppin = ndr_stack_anew<ECRREGISTERPUSHNOTIFICATION_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecrregisterpushnotification(pndr, static_cast<ECRREGISTERPUSHNOTIFICATION_IN *>(*ppin));
	case 6:
		*ppin = NULL;
		return NDR_ERR_SUCCESS;
	case 10:
		*ppin = ndr_stack_anew<ECDOCONNECTEX_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdoconnectex(pndr, static_cast<ECDOCONNECTEX_IN *>(*ppin));
	case 11:
		*ppin = ndr_stack_anew<ECDORPCEXT2_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdorpcext2(pndr, static_cast<ECDORPCEXT2_IN *>(*ppin));
	case 14:
		*ppin = ndr_stack_anew<ECDOASYNCCONNECTEX_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdoasyncconnectex(pndr, static_cast<ECDOASYNCCONNECTEX_IN *>(*ppin));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static int exchange_emsmdb_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	switch (opnum) {
	case 1: {
		auto in  = static_cast<ECDOASYNCCONNECTEX_IN *>(pin);
		auto out = ndr_stack_anew<ECDODISCONNECT_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_disconnect(&in->cxh);
		out->cxh = in->cxh;
		return DISPATCH_SUCCESS;
	}
	case 4: {
		auto in  = static_cast<ECRREGISTERPUSHNOTIFICATION_IN *>(pin);
		auto out = ndr_stack_anew<ECRREGISTERPUSHNOTIFICATION_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_register_push_notification(&in->cxh,
		              in->rpc, in->pctx, in->cb_ctx, in->advise_bits,
		              in->paddr, in->cb_addr, &out->hnotification);
		out->cxh = in->cxh;
		return DISPATCH_SUCCESS;
	}
	case 6:
		*ppout = ndr_stack_anew<int32_t>(NDR_STACK_OUT);
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		*(int32_t*)*ppout = emsmdb_interface_dummy_rpc(handle);
		return DISPATCH_SUCCESS;
	case 10: {
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
		return DISPATCH_SUCCESS;
	}
	case 11: {
		auto in  = static_cast<ECDORPCEXT2_IN *>(pin);
		auto out = ndr_stack_anew<ECDORPCEXT2_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_rpc_ext2(&in->cxh, &in->flags,
		              in->pin, in->cb_in, out->pout, &in->cb_out,
		              in->pauxin, in->cb_auxin, out->pauxout,
		              &in->cb_auxout, &out->trans_time);
		out->cxh = in->cxh;
		out->flags = in->flags;
		out->cb_out = in->cb_out;
		out->cb_auxout = in->cb_auxout;
		return DISPATCH_SUCCESS;
	}
	case 14: {
		auto in  = static_cast<ECDOASYNCCONNECTEX_IN *>(pin);
		auto out = ndr_stack_anew<ECDOASYNCCONNECTEX_OUT>(NDR_STACK_OUT);
		if (out == nullptr)
			return DISPATCH_FAIL;
		*ppout = out;
		out->result = emsmdb_interface_async_connect_ex(in->cxh, &out->acxh);
		return DISPATCH_SUCCESS;
	}
	default:
		return DISPATCH_FAIL;
	}
}

static int exchange_emsmdb_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	switch (opnum) {
	case 1:
		return emsmdb_ndr_push_ecdodisconnect(pndr, static_cast<ECDODISCONNECT_OUT *>(pout));
	case 4:
		return emsmdb_ndr_push_ecrregisterpushnotification(pndr, static_cast<ECRREGISTERPUSHNOTIFICATION_OUT *>(pout));
	case 6:
		return emsmdb_ndr_push_ecdummyrpc(pndr, static_cast<int32_t *>(pout));
	case 10:
		return emsmdb_ndr_push_ecdoconnectex(pndr, static_cast<ECDOCONNECTEX_OUT *>(pout));
	case 11:
		return emsmdb_ndr_push_ecdorpcext2(pndr, static_cast<ECDORPCEXT2_OUT *>(pout));
	case 14:
		return emsmdb_ndr_push_ecdoasyncconnectex(pndr, static_cast<ECDOASYNCCONNECTEX_OUT *>(pout));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static void exchange_emsmdb_unbind(uint64_t handle)
{
	emsmdb_interface_unbind_rpc_handle(handle);
}

static int exchange_async_emsmdb_ndr_pull(int opnum,
	NDR_PULL* pndr, void **ppin)
{
	switch (opnum) {
	case 0:
		*ppin = ndr_stack_anew<ECDOASYNCWAITEX_IN>(NDR_STACK_IN);
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return asyncemsmdb_ndr_pull_ecdoasyncwaitex(pndr, static_cast<ECDOASYNCWAITEX_IN *>(*ppin));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static int exchange_async_emsmdb_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	int result;
	uint32_t async_id;
	
	switch (opnum) {
	case 0:
		*ppout = ndr_stack_anew<ECDOASYNCWAITEX_OUT>(NDR_STACK_OUT);
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		async_id = apply_async_id();
		if (0 == async_id) {
			return DISPATCH_FAIL;
		}
		result = asyncemsmdb_interface_async_wait(async_id, static_cast<ECDOASYNCWAITEX_IN *>(pin),
		         static_cast<ECDOASYNCWAITEX_OUT *>(*ppout));
		if (DISPATCH_PENDING == result) {
			activate_async_id(async_id);
		} else {
			cancel_async_id(async_id);
		}
		return result;
	default:
		return DISPATCH_FAIL;
	}
}

static int exchange_async_emsmdb_ndr_push(int opnum,
	NDR_PUSH *pndr, void *pout)
{
	switch (opnum) {
	case 0:
		return asyncemsmdb_ndr_push_ecdoasyncwaitex(pndr, static_cast<ECDOASYNCWAITEX_OUT *>(pout));
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static void exchange_async_emsmdb_reclaim(uint32_t async_id)
{
	asyncemsmdb_interface_reclaim(async_id);
}

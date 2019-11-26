#include "guid.h"
#include "util.h"
#include "rop_util.h"
#include "mail_func.h"
#include "emsmdb_ndr.h"
#include "proc_common.h"
#include "common_util.h"
#include "config_file.h"
#include "logon_object.h"
#include "exmdb_client.h"
#include "rop_processor.h"
#include "bounce_producer.h"
#include "msgchg_grouping.h"
#include "asyncemsmdb_ndr.h"
#include "emsmdb_interface.h"
#include "asyncemsmdb_interface.h"
#include <string.h>
#include <stdio.h>

DECLARE_API;


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

BOOL PROC_LibMain(int reason, void **ppdata)
{
	int max_mail;
	int max_rcpt;
	int async_num;
	int smtp_port;
	int max_length;
	void *pendpoint;
	int max_rule_len;
	char smtp_ip[16];
	int ping_interval;
	int average_blocks;
	char size_buff[32];
	char separator[16];
	char org_name[256];
	CONFIG_FILE *pfile;
	int average_handles;
	char temp_buff[256];
	char file_name[256];
	char temp_path[256];
	char data_path[256];
	char resource_path[256];
	char submit_command[1024];
	char *str_value, *psearch;
	DCERPC_INTERFACE interface_emsmdb;
	DCERPC_INTERFACE interface_async_emsmdb;
	
	/* path conatins the config files directory */
	switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		/* get the plugin name from system api */
		strcpy(file_name, get_plugin_name());
		psearch = strrchr(file_name, '.');
		if (NULL != psearch) {
			*psearch = '\0';
		}
		sprintf(data_path, "%s/%s", get_data_path(), file_name);
		sprintf(resource_path, "%s/notify_bounce", get_data_path());
		sprintf(temp_path, "%s/%s.cfg", get_config_path(), file_name);
		pfile = config_file_init(temp_path);
		if (NULL == pfile) {
			printf("[exchange_emsmdb]: error to open config file!!!\n");
			return FALSE;
		}
		str_value = config_file_get_value(pfile, "SEPARATOR_FOR_BOUNCE");
		if (NULL == str_value) {
			strcpy(separator, " ");
		} else {
			strcpy(separator, str_value);
		}
		str_value = config_file_get_value(pfile, "X500_ORG_NAME");
		if (NULL == str_value || '\0' == str_value[0]) {
			strcpy(org_name, "gridware information");
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
		if (NULL == str_value) {
			strcpy(smtp_ip, "127.0.0.1");
			config_file_set_value(pfile, "SMTP_SERVER_IP", "127.0.0.1");
		} else {
			if (NULL == extract_ip(str_value, smtp_ip)) {
				strcpy(smtp_ip, "127.0.0.1");
				config_file_set_value(pfile, "SMTP_SERVER_IP", "127.0.0.1");
			}
		}
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
		printf("[exchange_emsmdb]: smtp server is %s:%d\n", smtp_ip, smtp_port);
		str_value = config_file_get_value(pfile, "SUBMIT_COMMAND");
		if (NULL == str_value) {
			printf("[exchange_emsmdb]: fail to get SUBMIT_COMMAND in config file!!!\n");
			config_file_free(pfile);
			return FALSE;
		}
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
		config_file_save(pfile);
		config_file_free(pfile);
		
		/* host can include wildcard */
		pendpoint = register_endpoint("*", 6001);
		if (NULL == pendpoint) {
			printf("[exchange_emsmdb]: fail to register endpoint with port 6001\n");
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
			printf("[exchange_emsmdb]: fail to register emsmdb interface\n");
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
			printf("[exchange_emsmdb]: fail to register emsmdb interface\n");
			return FALSE;
		}
		bounce_producer_init(resource_path, separator);
		common_util_init(org_name, average_blocks, max_rcpt, max_mail,
			max_length, max_rule_len, smtp_ip, smtp_port, submit_command);
		exmdb_client_init();
		msgchg_grouping_init(data_path);
		emsmdb_interface_init();
		asyncemsmdb_interface_init(async_num);
		rop_processor_init(average_handles, ping_interval);
		if (0 != bounce_producer_run()) {
			printf("[exchange_emsmdb]: fail to run bounce producer\n");
			return FALSE;
		}
		if (0 != common_util_run()) {
			printf("[exchange_emsmdb]: fail to run common util\n");
			return FALSE;
		}
		if (0 != exmdb_client_run()) {
			printf("[exchange_emsmdb]: fail to run exmdb client\n");
			return FALSE;
		}
		if (0 != msgchg_grouping_run()) {
			printf("[exchange_emsmdb]: fail to run msgchg grouping\n");
			return FALSE;
		}
		if (0 != emsmdb_interface_run()) {
			printf("[exchange_emsmdb]: fail to run emsmdb interface\n");
			return FALSE;
		}
		if (0 != asyncemsmdb_interface_run()) {
			printf("[exchange_emsmdb]: fail to run asyncemsmdb interface\n");
			return FALSE;
		}
		if (0 != rop_processor_run()) {
			printf("[exchange_emsmdb]: fail to run rop processor\n");
			return FALSE;
		}
		printf("[exchange_emsmdb]: plugin is loaded into system\n");
		return TRUE;
	case PLUGIN_FREE:
		rop_processor_stop();
		asyncemsmdb_interface_stop();
		emsmdb_interface_stop();
		msgchg_grouping_stop();
		exmdb_client_stop();
		common_util_stop();
		bounce_producer_stop();
		rop_processor_free();
		asyncemsmdb_interface_free();
		emsmdb_interface_free();
		msgchg_grouping_free();
		exmdb_client_free();
		common_util_free();
		bounce_producer_free();
		return TRUE;
	}
}

static int exchange_emsmdb_ndr_pull(int opnum, NDR_PULL* pndr, void **ppin)
{
	switch (opnum) {
	case 1:
		*ppin = ndr_stack_alloc(NDR_STACK_IN, sizeof(ECDODISCONNECT_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdodisconnect(pndr, *ppin);
	case 4:
		*ppin = ndr_stack_alloc(NDR_STACK_IN,
					sizeof(ECRREGISTERPUSHNOTIFICATION_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecrregisterpushnotification(pndr, *ppin);
	case 6:
		*ppin = NULL;
		return NDR_ERR_SUCCESS;
	case 10:
		*ppin = ndr_stack_alloc(NDR_STACK_IN, sizeof(ECDOCONNECTEX_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdoconnectex(pndr, *ppin);
	case 11:
		*ppin = ndr_stack_alloc(NDR_STACK_IN, sizeof(ECDORPCEXT2_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdorpcext2(pndr, *ppin);
	case 14:
		*ppin = ndr_stack_alloc(NDR_STACK_IN, sizeof(ECDOASYNCCONNECTEX_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return emsmdb_ndr_pull_ecdoasyncconnectex(pndr, *ppin);
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static int exchange_emsmdb_dispatch(int opnum, const GUID *pobject,
	uint64_t handle, void *pin, void **ppout)
{
	switch (opnum) {
	case 1:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(ECDODISCONNECT_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		((ECDODISCONNECT_OUT*)*ppout)->result =
			emsmdb_interface_disconnect(&((ECDOASYNCCONNECTEX_IN*)pin)->cxh);
		((ECDODISCONNECT_OUT*)*ppout)->cxh =
										((ECDOASYNCCONNECTEX_IN*)pin)->cxh;
		return DISPATCH_SUCCESS;
	case 4:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT,
						sizeof(ECRREGISTERPUSHNOTIFICATION_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		((ECRREGISTERPUSHNOTIFICATION_OUT*)*ppout)->result =
			emsmdb_interface_register_push_notification(
				&((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->cxh,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->rpc,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->pctx,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->cb_ctx,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->advise_bits,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->paddr,
				((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->cb_addr,
				&((ECRREGISTERPUSHNOTIFICATION_OUT*)*ppout)->hnotification);
		((ECRREGISTERPUSHNOTIFICATION_OUT*)*ppout)->cxh =
			((ECRREGISTERPUSHNOTIFICATION_IN*)pin)->cxh;
		return DISPATCH_SUCCESS;
	case 6:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(int32_t));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		*(int32_t*)*ppout = emsmdb_interface_dummy_rpc(handle);
		return DISPATCH_SUCCESS;
	case 10:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(ECDOCONNECTEX_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		((ECDOCONNECTEX_OUT*)*ppout)->result =
			emsmdb_interface_connect_ex(handle,
				&((ECDOCONNECTEX_OUT*)*ppout)->cxh,
				((ECDOCONNECTEX_IN*)pin)->puserdn,
				((ECDOCONNECTEX_IN*)pin)->flags,
				((ECDOCONNECTEX_IN*)pin)->conmod,
				((ECDOCONNECTEX_IN*)pin)->limit,
				((ECDOCONNECTEX_IN*)pin)->cpid,
				((ECDOCONNECTEX_IN*)pin)->lcid_string,
				((ECDOCONNECTEX_IN*)pin)->lcid_sort,
				((ECDOCONNECTEX_IN*)pin)->cxr_link,
				((ECDOCONNECTEX_IN*)pin)->cnvt_cps,
				&((ECDOCONNECTEX_OUT*)*ppout)->max_polls,
				&((ECDOCONNECTEX_OUT*)*ppout)->max_retry,
				&((ECDOCONNECTEX_OUT*)*ppout)->retry_delay,
				&((ECDOCONNECTEX_OUT*)*ppout)->cxr,
				((ECDOCONNECTEX_OUT*)*ppout)->pdn_prefix,
				((ECDOCONNECTEX_OUT*)*ppout)->pdisplayname,
				((ECDOCONNECTEX_IN*)pin)->pclient_vers,
				((ECDOCONNECTEX_OUT*)*ppout)->pserver_vers,
				((ECDOCONNECTEX_OUT*)*ppout)->pbest_vers,
				&((ECDOCONNECTEX_IN*)pin)->timestamp,
				((ECDOCONNECTEX_IN*)pin)->pauxin,
				((ECDOCONNECTEX_IN*)pin)->cb_auxin,
				((ECDOCONNECTEX_OUT*)*ppout)->pauxout,
				&((ECDOCONNECTEX_IN*)pin)->cb_auxout);
		((ECDOCONNECTEX_OUT*)*ppout)->timestamp =
						((ECDOCONNECTEX_IN*)pin)->timestamp;
		((ECDOCONNECTEX_OUT*)*ppout)->cb_auxout =
						((ECDOCONNECTEX_IN*)pin)->cb_auxout;
		return DISPATCH_SUCCESS;
	case 11:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(ECDORPCEXT2_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		((ECDORPCEXT2_OUT*)*ppout)->result =
			emsmdb_interface_rpc_ext2(&((ECDORPCEXT2_IN*)pin)->cxh,
				&((ECDORPCEXT2_IN*)pin)->flags,
				((ECDORPCEXT2_IN*)pin)->pin,
				((ECDORPCEXT2_IN*)pin)->cb_in,
				((ECDORPCEXT2_OUT*)*ppout)->pout,
				&((ECDORPCEXT2_IN*)pin)->cb_out,
				((ECDORPCEXT2_IN*)pin)->pauxin,
				((ECDORPCEXT2_IN*)pin)->cb_auxin,
				((ECDORPCEXT2_OUT*)*ppout)->pauxout,
				&((ECDORPCEXT2_IN*)pin)->cb_auxout,
				&((ECDORPCEXT2_OUT*)*ppout)->trans_time);
		((ECDORPCEXT2_OUT*)*ppout)->cxh = ((ECDORPCEXT2_IN*)pin)->cxh;
		((ECDORPCEXT2_OUT*)*ppout)->flags = ((ECDORPCEXT2_IN*)pin)->flags;
		((ECDORPCEXT2_OUT*)*ppout)->cb_out = ((ECDORPCEXT2_IN*)pin)->cb_out;
		((ECDORPCEXT2_OUT*)*ppout)->cb_auxout =
									((ECDORPCEXT2_IN*)pin)->cb_auxout;
		return DISPATCH_SUCCESS;
	case 14:
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(ECDOASYNCCONNECTEX_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		((ECDOASYNCCONNECTEX_OUT*)*ppout)->result =
			emsmdb_interface_async_connect_ex(
				((ECDOASYNCCONNECTEX_IN*)pin)->cxh,
				&((ECDOASYNCCONNECTEX_OUT*)*ppout)->acxh);
		return DISPATCH_SUCCESS;
	default:
		return DISPATCH_FAIL;
	}
}

static int exchange_emsmdb_ndr_push(int opnum, NDR_PUSH *pndr, void *pout)
{
	switch (opnum) {
	case 1:
		return emsmdb_ndr_push_ecdodisconnect(pndr, pout);
	case 4:
		return emsmdb_ndr_push_ecrregisterpushnotification(pndr, pout);
	case 6:
		return emsmdb_ndr_push_ecdummyrpc(pndr, pout);
	case 10:
		return emsmdb_ndr_push_ecdoconnectex(pndr, pout);
	case 11:
		return emsmdb_ndr_push_ecdorpcext2(pndr, pout);
	case 14:
		return emsmdb_ndr_push_ecdoasyncconnectex(pndr, pout);
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
		*ppin = ndr_stack_alloc(NDR_STACK_IN, sizeof(ECDOASYNCWAITEX_IN));
		if (NULL == *ppin) {
			return NDR_ERR_ALLOC;
		}
		return asyncemsmdb_ndr_pull_ecdoasyncwaitex(pndr, *ppin);
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
		*ppout = ndr_stack_alloc(NDR_STACK_OUT, sizeof(ECDOASYNCWAITEX_OUT));
		if (NULL == *ppout) {
			return DISPATCH_FAIL;
		}
		async_id = apply_async_id();
		if (0 == async_id) {
			return DISPATCH_FAIL;
		}
		result = asyncemsmdb_interface_async_wait(async_id, pin, *ppout);
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
		return asyncemsmdb_ndr_push_ecdoasyncwaitex(pndr, pout);
	default:
		return NDR_ERR_BAD_SWITCH;
	}
}

static void exchange_async_emsmdb_reclaim(uint32_t async_id)
{
	asyncemsmdb_interface_reclaim(async_id);
}

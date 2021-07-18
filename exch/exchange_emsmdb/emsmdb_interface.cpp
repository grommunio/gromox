// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <atomic>
#include <csignal>
#include <cstdint>
#include <mutex>
#include <libHX/string.h>
#include <gromox/defs.h>
#include "asyncemsmdb_interface.h"
#include "emsmdb_interface.h"
#include "notify_response.h"
#include "rop_processor.h"
#include <gromox/proc_common.h>
#include "common_util.h"
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/str_hash.hpp>
#include "aux_ext.h"
#include <gromox/util.hpp>
#include <gromox/guid.hpp>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>


#define	EMSMDB_PCMSPOLLMAX				60000
#define	EMSMDB_PCRETRY					6
#define	EMSMDB_PCRETRYDELAY				10000

#define HANDLE_EXCHANGE_EMSMDB			2

#define HANDLE_EXCHANGE_ASYNCEMSMDB		3

#define AVERAGE_NOTIFY_NUM				4

#define MAX_NOTIFY_RESPONSE_NUM			128

#define MAX_CONTENT_ROW_DELETED			6

#define FLAG_PRIVILEGE_ADMIN			0x00000001

#define HANLDE_VALID_INTERVAL			2000

#define MAX_HANDLE_PER_USER				100

using namespace gromox;

namespace {

struct HANDLE_DATA {
	DOUBLE_LIST_NODE node;
	GUID guid;
	char username[UADDR_SIZE];
	uint16_t cxr;
	uint32_t last_handle;
	EMSMDB_INFO info;
	BOOL b_processing;	/* if the handle is processing rops */
	BOOL b_occupied;	/* if the notify list is locked */
	DOUBLE_LIST notify_list;
	int rop_num;
	uint16_t rop_left;	/* size left in rop response buffer */
	time_t last_time;
};

struct NOTIFY_ITEM {
	uint32_t handle;
	uint8_t logon_id;
	GUID guid;
};

}

static constexpr size_t TAG_SIZE = 256;
static time_t g_start_time;
static pthread_t g_scan_id;
static std::mutex g_lock, g_notify_lock;
static std::atomic<bool> g_notify_stop{true};
static pthread_key_t g_handle_key;
static STR_HASH_TABLE *g_user_hash;
static STR_HASH_TABLE *g_handle_hash;
static STR_HASH_TABLE *g_notify_hash;

static void *emsi_scanwork(void *);

static uint32_t emsmdb_interface_get_timestamp()
{
	return time(NULL) - g_start_time + 1230336000;
}

BOOL emsmdb_interface_check_acxh(ACXH *pacxh,
	char *username, uint16_t *pcxr, BOOL b_touch)
{
	char guid_string[64];
	HANDLE_DATA *phandle;
	
	if (HANDLE_EXCHANGE_ASYNCEMSMDB != pacxh->handle_type) {
		return FALSE;
	}
	guid_to_string(&pacxh->guid, guid_string, sizeof(guid_string));
	std::lock_guard gl_hold(g_lock);
	phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
	if (NULL != phandle) {
		if (TRUE == b_touch) {
			time(&phandle->last_time);
		}
		strcpy(username, phandle->username);
		*pcxr = phandle->cxr;
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL emsmdb_interface_check_notify(ACXH *pacxh)
{
	char guid_string[64];
	HANDLE_DATA *phandle;
	
	if (HANDLE_EXCHANGE_ASYNCEMSMDB != pacxh->handle_type) {
		return FALSE;
	}
	guid_to_string(&pacxh->guid, guid_string, sizeof(guid_string));
	std::lock_guard gl_hold(g_lock);
	phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
	if (NULL != phandle) {
		if (double_list_get_nodes_num(&phandle->notify_list) > 0) {
			return TRUE;
		}
	}
	return FALSE;
}

/* called by moh_emsmdb module */
void emsmdb_interface_touch_handle(CXH *pcxh)
{
	char guid_string[64];

	if (HANDLE_EXCHANGE_EMSMDB != pcxh->handle_type) {
		return;
	}
	guid_to_string(&pcxh->guid, guid_string, sizeof(guid_string));
	std::lock_guard gl_hold(g_lock);
	auto phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
	if (NULL != phandle) {
		time(&phandle->last_time);
	}
}

static HANDLE_DATA* emsmdb_interface_get_handle_data(CXH *pcxh)
{
	char guid_string[64];
	HANDLE_DATA *phandle;
	
	if (HANDLE_EXCHANGE_EMSMDB != pcxh->handle_type) {
		return NULL;
	}
	guid_to_string(&pcxh->guid, guid_string, sizeof(guid_string));
	while (TRUE) {
		std::unique_lock gl_hold(g_lock);
		phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
		if (NULL == phandle) {
			return NULL;
		}
		if (TRUE == phandle->b_processing) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_processing = TRUE;
			return phandle;
		}
	}
}

static void emsmdb_interface_put_handle_data(HANDLE_DATA *phandle)
{
	std::lock_guard gl_hold(g_lock);
	phandle->b_processing = FALSE;
}

static HANDLE_DATA* emsmdb_interface_get_handle_notify_list(CXH *pcxh)
{
	char guid_string[64];
	HANDLE_DATA *phandle;
	
	if (HANDLE_EXCHANGE_EMSMDB != pcxh->handle_type) {
		return NULL;
	}
	guid_to_string(&pcxh->guid, guid_string, sizeof(guid_string));
	while (TRUE) {
		std::unique_lock gl_hold(g_lock);
		phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
		if (NULL == phandle) {
			return NULL;
		}
		if (TRUE == phandle->b_occupied) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_occupied = TRUE;
			return phandle;
		}
	}
}

static void emsmdb_interface_put_handle_notify_list(HANDLE_DATA *phandle)
{
	std::lock_guard gl_hold(g_lock);
	phandle->b_occupied = FALSE;
}

static BOOL emsmdb_interface_alloc_cxr(DOUBLE_LIST *plist,
	HANDLE_DATA *phandle)
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	
	for (i=1,pnode=double_list_get_head(plist); NULL!=pnode&&i<=0xFFFF;
		pnode=double_list_get_after(plist, pnode),i++) {
		if (i < ((HANDLE_DATA*)pnode->pdata)->cxr) {
			phandle->cxr = i;
			double_list_insert_before(plist, pnode, &phandle->node);
			return TRUE;
		}
	}
	if (i > 0xFFFF) {
		return FALSE;
	}
	phandle->cxr = i;
	double_list_append_as_tail(plist, &phandle->node);
	return TRUE;
}

static BOOL emsmdb_interface_create_handle(const char *username,
	uint16_t client_version[4], uint16_t client_mode, uint32_t cpid,
	uint32_t lcid_string, uint32_t lcid_sort, uint16_t *pcxr, CXH *pcxh)
{
	void *plogmap;
	DOUBLE_LIST *plist;
	DOUBLE_LIST tmp_list;
	char guid_string[64];
	HANDLE_DATA *phandle;
	HANDLE_DATA temp_handle;
	
	if (!common_util_verify_cpid(cpid))
		return FALSE;
	temp_handle.b_processing = FALSE;
	temp_handle.b_occupied = FALSE;
	temp_handle.guid = guid_random_new();
	temp_handle.info.cpid = cpid;
	temp_handle.info.lcid_string = lcid_string;
	temp_handle.info.lcid_sort = lcid_sort;
	memcpy(temp_handle.info.client_version, client_version, 4);
	temp_handle.info.client_mode = client_mode;
	temp_handle.info.upctx_ref = 0;
	time(&temp_handle.last_time);
	gx_strlcpy(temp_handle.username, username, GX_ARRAY_SIZE(temp_handle.username));
	HX_strlower(temp_handle.username);
	guid_to_string(&temp_handle.guid, guid_string, sizeof(guid_string));
	std::unique_lock gl_hold(g_lock);
	if (1 != str_hash_add(g_handle_hash, guid_string, &temp_handle)) {
		return FALSE;
	}
	phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
	if (phandle == nullptr)
		/* Should never occur; the value was recently added successfully. */
		return false;
	phandle->node.pdata = phandle;
	
	phandle->last_handle = 0;
	plogmap = rop_processor_create_logmap();
	if (NULL == plogmap) {
		str_hash_remove(g_handle_hash, guid_string);
		return FALSE;
	}
	phandle->info.plogmap = plogmap;
	
	plist = static_cast<DOUBLE_LIST *>(str_hash_query(g_user_hash, temp_handle.username));
	if (NULL == plist) {
		if (1 != str_hash_add(g_user_hash,
			temp_handle.username, &tmp_list)) {
			str_hash_remove(g_handle_hash, guid_string);
			gl_hold.unlock();
			rop_processor_release_logmap(plogmap);
			return FALSE;
		}
		plist = static_cast<DOUBLE_LIST *>(str_hash_query(g_user_hash, temp_handle.username));
		if (plist == nullptr)
			/* Should never occur; the value was recently added successfully. */
			return false;
		double_list_init(plist);
	} else {
		if (double_list_get_nodes_num(plist) >= MAX_HANDLE_PER_USER) {
			str_hash_remove(g_handle_hash, guid_string);
			gl_hold.unlock();
			rop_processor_release_logmap(plogmap);
			return FALSE;
		}
	}
	if (FALSE == emsmdb_interface_alloc_cxr(plist, phandle)) {
		if (0 == double_list_get_nodes_num(plist)) {
			double_list_free(plist);
			str_hash_remove(g_user_hash, temp_handle.username);
		}
		str_hash_remove(g_handle_hash, guid_string);
		gl_hold.unlock();
		rop_processor_release_logmap(plogmap);
		return FALSE;
	}
	*pcxr = phandle->cxr;
	gl_hold.unlock();
	pcxh->handle_type = HANDLE_EXCHANGE_EMSMDB;
	pcxh->guid = temp_handle.guid;
	double_list_init(&phandle->notify_list);
	return TRUE;
}

static void emsmdb_interface_remove_handle(CXH *pcxh)
{
	void *plogmap;
	DOUBLE_LIST *plist;
	char guid_string[64];
	HANDLE_DATA *phandle;
	DOUBLE_LIST_NODE *pnode;
	
	if (HANDLE_EXCHANGE_EMSMDB != pcxh->handle_type) {
		return;
	}
	guid_to_string(&pcxh->guid, guid_string, sizeof(guid_string));
	std::unique_lock gl_hold(g_lock);
	while (TRUE) {
		phandle = static_cast<HANDLE_DATA *>(str_hash_query(g_handle_hash, guid_string));
		if (NULL == phandle) {
			return;
		}
		if (TRUE == phandle->b_processing) {
			/* this means handle is being processed
			   in emsmdb_interface_rpc_ext2 by another
			   rpc connection, can not be released! */
			return;
		}
		if (TRUE == phandle->b_occupied) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			break;
		}
	}
	plist = static_cast<DOUBLE_LIST *>(str_hash_query(g_user_hash, phandle->username));
	if (NULL != plist) {
		double_list_remove(plist, &phandle->node);
		if (0 == double_list_get_nodes_num(plist)) {
			double_list_free(plist);
			str_hash_remove(g_user_hash, phandle->username);
		}
	}
	plogmap = phandle->info.plogmap;
	while ((pnode = double_list_pop_front(&phandle->notify_list)) != nullptr) {
		notify_response_free(static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload));
		free(pnode->pdata);
		free(pnode);
	}
	double_list_free(&phandle->notify_list);
	str_hash_remove(g_handle_hash, guid_string);
	gl_hold.unlock();
	rop_processor_release_logmap(plogmap);
}

void emsmdb_interface_init()
{
	time(&g_start_time);
	pthread_key_create(&g_handle_key, NULL);
}

int emsmdb_interface_run()
{
	int context_num;
	
	context_num = get_context_num();
	g_handle_hash = str_hash_init((context_num + 1)*
		MAX_HANDLES_ON_CONTEXT, sizeof(HANDLE_DATA), NULL);
	if (NULL == g_handle_hash) {
		printf("[exchange_emsmdb]: Failed to init handle hash table\n");
		return -1;
	}
	g_user_hash = str_hash_init(context_num + 1, sizeof(DOUBLE_LIST), NULL);
	if (NULL == g_user_hash) {
		printf("[exchange_emsmdb]: Failed to init user hash table\n");
		return -2;
	}
	g_notify_hash = str_hash_init(AVERAGE_NOTIFY_NUM
			*context_num, sizeof(NOTIFY_ITEM), NULL);
	if (NULL == g_notify_hash) {
		printf("[exchange_emsmdb]: Failed to init notify hash map\n");
		return -3;
	}
	g_notify_stop = false;
	auto ret = pthread_create(&g_scan_id, nullptr, emsi_scanwork, nullptr);
	if (ret != 0) {
		g_notify_stop = true;
		printf("[exchange_emsmdb]: E-1447: pthread_create: %s\n", strerror(ret));
		return -4;
	}
	pthread_setname_np(g_scan_id, "emsmdb/scan");
	return 0;
}

void emsmdb_interface_stop()
{
	if (!g_notify_stop) {
		g_notify_stop = true;
		pthread_kill(g_scan_id, SIGALRM);
		pthread_join(g_scan_id, NULL);
	}
	if (NULL != g_notify_hash) {
		str_hash_free(g_notify_hash);
		g_notify_hash = NULL;
	}
	if (NULL != g_user_hash) {
		str_hash_free(g_user_hash);
		g_user_hash = NULL;
	}
	if (NULL != g_handle_hash) {
		str_hash_free(g_handle_hash);
		g_handle_hash = NULL;
	}
}

void emsmdb_interface_free()
{
	pthread_key_delete(g_handle_key);
}

int emsmdb_interface_disconnect(CXH *pcxh)
{
	emsmdb_interface_remove_handle(pcxh);
	memset(pcxh, 0, sizeof(CXH));
	return ecSuccess;
}

int emsmdb_interface_register_push_notification(CXH *pcxh, uint32_t rpc,
	uint8_t *pctx, uint16_t cb_ctx, uint32_t advise_bits, uint8_t *paddr,
	uint16_t cb_addr, uint32_t *phnotification)
{
	return ecNotSupported;
}

int emsmdb_interface_dummy_rpc(uint64_t hrpc)
{
	return ecSuccess;
}

static BOOL emsmdb_interface_decode_version(const uint16_t pvers[3],
	uint16_t pnormal_vers[4])
{
	if (pvers[1] & 0x8000) {
		pnormal_vers[0] = (pvers[0] & 0xFF00) >> 8;
		pnormal_vers[1] = pvers[0] & 0xFF;
		pnormal_vers[2] = pvers[1] & 0x7FFF;
		pnormal_vers[3] = pvers[2];
		return TRUE;
	} else {
		pnormal_vers[0] = pvers[0];
		pnormal_vers[1] = 0;
		pnormal_vers[2] = pvers[1];
		pnormal_vers[3] = pvers[2];
		return FALSE;
	}
}

static void emsmdb_interface_encode_version(BOOL high_bit,
	const uint16_t pnormal_vers[4], uint16_t pvers[3])
{
	if (TRUE == high_bit) {
		pvers[0] = (pnormal_vers[0] << 8) | pnormal_vers[1];
		pvers[1] = pnormal_vers[2] | 0x8000;
		pvers[2] = pnormal_vers[3];
	} else {
		pvers[0] = pnormal_vers[0];
		pvers[1] = pnormal_vers[2];
		pvers[2] = pnormal_vers[3];
	}
}

int emsmdb_interface_connect_ex(uint64_t hrpc, CXH *pcxh,
	const char *puser_dn, uint32_t flags, uint32_t con_mode,
	uint32_t limit, uint32_t cpid, uint32_t lcid_string,
	uint32_t lcid_sort, uint32_t cxr_link, uint16_t cnvt_cps,
	uint32_t *pmax_polls, uint32_t *pmax_retry, uint32_t *pretry_delay,
	uint16_t *pcxr, char *pdn_prefix, char *pdisplayname,
	const uint16_t pclient_vers[3], uint16_t pserver_vers[3],
	uint16_t pbest_vers[3], uint32_t *ptimestamp, const uint8_t *pauxin,
	uint32_t cb_auxin, uint8_t *pauxout, uint32_t *pcb_auxout)
{
	AUX_INFO aux_in;
	AUX_INFO aux_out;
	EXT_PULL ext_pull;
	EXT_PUSH ext_push;
	char username[UADDR_SIZE];
	AUX_HEADER *pheader;
	char temp_buff[1024];
	uint16_t client_mode;
	AUX_HEADER header_cap;
	AUX_HEADER header_info;
	DOUBLE_LIST_NODE *pnode;
	AUX_HEADER header_control;
	AUX_EXORGINFO aux_orginfo;
	DOUBLE_LIST_NODE node_cap;
	DOUBLE_LIST_NODE node_info;
	DOUBLE_LIST_NODE node_ctrl;
	uint16_t client_version[4];
	AUX_CLIENT_CONTROL aux_control;
	AUX_ENDPOINT_CAPABILITIES aux_cap;
	uint16_t server_normal_version[4] = {15, 0, 847, 4040};
	bool is_success = false;

	auto cl_0 = make_scope_exit([&]() {
		if (is_success)
			return;
		memset(pcxh, 0, sizeof(CXH));
		*pmax_polls = 0;
		*pmax_retry = 0;
		*pretry_delay = 0;
		*pcxr = 0;
		pdisplayname[0] = '\0';
		memset(pserver_vers, 0, 3 * sizeof(*pserver_vers));
		memset(pbest_vers, 0, 3 * sizeof(*pbest_vers));
		*ptimestamp = 0;
	});
	
	aux_out.rhe_version = 0;
	aux_out.rhe_flags = RHE_FLAG_LAST;
	double_list_init(&aux_out.aux_list);
	
	header_info.version = AUX_VERSION_1;
	header_info.type = AUX_TYPE_EXORGINFO;
	aux_orginfo.org_flags = PUBLIC_FOLDERS_ENABLED |
		USE_AUTODISCOVER_FOR_PUBLIC_FOLDR_CONFIGURATION;
	header_info.ppayload = &aux_orginfo;
	node_info.pdata = &header_info;
	double_list_append_as_tail(&aux_out.aux_list, &node_info);
	
	header_control.version = AUX_VERSION_1;
	header_control.type = AUX_TYPE_CLIENT_CONTROL;
	aux_control.enable_flags = ENABLE_COMPRESSION | ENABLE_HTTP_TUNNELING;
	aux_control.expiry_time = 604800000;
	header_control.ppayload = &aux_control;
	node_ctrl.pdata = &header_control;
	double_list_append_as_tail(&aux_out.aux_list, &node_ctrl);
	
	header_cap.version = AUX_VERSION_1;
	header_cap.type = AUX_TYPE_ENDPOINT_CAPABILITIES;
	aux_cap.endpoint_capability_flag = ENDPOINT_CAPABILITIES_SINGLE_ENDPOINT;
	header_cap.ppayload = &aux_cap;
	node_cap.pdata = &header_cap;
	double_list_append_as_tail(&aux_out.aux_list, &node_cap);
	DCERPC_INFO rpc_info;
	if (!ext_push.init(pauxout, 0x1008, EXT_FLAG_UTF16)) {
		double_list_free(&aux_out.aux_list);
		return ecMAPIOOM;
	}
	*pcb_auxout = aux_ext_push_aux_info(&ext_push, &aux_out) != EXT_ERR_SUCCESS ?
	              0 : ext_push.m_offset;
	double_list_free(&aux_out.aux_list);
	
	pdn_prefix[0] = '\0';
	rpc_info = get_rpc_info();
	if (flags & FLAG_PRIVILEGE_ADMIN) {
		return ecLoginPerm;
	}
	
	*pmax_polls = EMSMDB_PCMSPOLLMAX;
	*pmax_retry = EMSMDB_PCRETRY;
	*pretry_delay = EMSMDB_PCRETRYDELAY;
	
	if ('\0' == puser_dn[0]) {
		return ecAccessDenied;
	}
	if (!common_util_essdn_to_username(puser_dn,
	    username, GX_ARRAY_SIZE(username))) {
		return ecRpcFailed;
	}
	if (*username == '\0') {
		return ecUnknownUser;
	}
	if (0 != strcasecmp(username, rpc_info.username)) {
		return ecAccessDenied;
	}
	if (FALSE == common_util_get_user_displayname(username, temp_buff) ||
		common_util_mb_from_utf8(cpid, temp_buff, pdisplayname, 1024) < 0) {
		return ecRpcFailed;
	}
	if ('\0' == pdisplayname[0]) {
		strcpy(pdisplayname, rpc_info.username);
	}
	
	emsmdb_interface_decode_version(pclient_vers, client_version);
	emsmdb_interface_encode_version(TRUE, server_normal_version, pserver_vers);
	pbest_vers[0] = pclient_vers[0];
	pbest_vers[1] = pclient_vers[1];
	pbest_vers[2] = pclient_vers[2];
	
	if (cb_auxin > 0 && cb_auxin < 0x8) {
		return ecRpcFailed;
	} else if (cb_auxin > 0x1008) {
		return RPC_X_BAD_STUB_DATA;
	}
	
	client_mode = CLIENT_MODE_UNKNOWN;
	if (0 != cb_auxin) {
		ext_pull.init(pauxin, cb_auxin, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != aux_ext_pull_aux_info(&ext_pull, &aux_in)) {
			debug_info("[exchange_emsmdb]: fail to pull input "
				"auxiliary buffer in emsmdb_interface_connect_ex\n");
		} else {
			for (pnode=double_list_get_head(&aux_in.aux_list); NULL!=pnode;
				pnode=double_list_get_after(&aux_in.aux_list, pnode)) {
				pheader = (AUX_HEADER*)pnode->pdata;
				if (AUX_VERSION_1 == pheader->version &&
					AUX_TYPE_PERF_CLIENTINFO == pheader->type) {
					client_mode = ((AUX_PERF_CLIENTINFO*)
						pheader->ppayload)->client_mode;
				}
			}
		}
	}
	
	/* just like EXCHANGE 2010 or later, we do
		not support session context linking */
	if (0xFFFFFFFF == cxr_link) {
		*ptimestamp = emsmdb_interface_get_timestamp();
	}
	if (FALSE == emsmdb_interface_create_handle(
		rpc_info.username, client_version, client_mode,
		cpid, lcid_string, lcid_sort, pcxr, pcxh)) {
		return ecLoginFailure;
	}
	is_success = true;
	return ecSuccess;
}

static uint32_t emsmdb_interface_get_interval(struct timeval first_time)
{
	struct timeval last_time;
	
	gettimeofday(&last_time, NULL);
	return (last_time.tv_sec - first_time.tv_sec)*1000 +
			last_time.tv_usec/1000 - first_time.tv_usec/1000;
}

int emsmdb_interface_rpc_ext2(CXH *pcxh, uint32_t *pflags,
	const uint8_t *pin, uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out,
	const uint8_t *pauxin, uint32_t cb_auxin, uint8_t *pauxout,
	uint32_t *pcb_auxout, uint32_t *ptrans_time)
{
	int result;
	uint16_t cxr;
	AUX_INFO aux_in;
	EXT_PULL ext_pull;
	char username[UADDR_SIZE];
	HANDLE_DATA *phandle;
	struct timeval first_time;
	
	/* ms-oxcrpc 3.1.4.2 */
	if (cb_in < 0x00000008 || *pcb_out < 0x00000008) {
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecRpcFailed;
	}
	if (cb_auxin > 0x1008) {
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		memset(pcxh, 0, sizeof(CXH));
		return RPC_X_BAD_STUB_DATA;
	}
	gettimeofday(&first_time, NULL);
	phandle = emsmdb_interface_get_handle_data(pcxh);
	if (NULL == phandle) {
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecError;
	}
	auto rpc_info = get_rpc_info();
	if (0 != strcasecmp(phandle->username, rpc_info.username)) {
		emsmdb_interface_put_handle_data(phandle);
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecAccessDenied;
	}
	if (first_time.tv_sec - phandle->last_time > HANLDE_VALID_INTERVAL) {
		emsmdb_interface_put_handle_data(phandle);
		emsmdb_interface_remove_handle(pcxh);
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		memset(pcxh, 0, sizeof(CXH));
		return ecError;
	}
	time(&phandle->last_time);
	pthread_setspecific(g_handle_key, (const void*)phandle);
	if (cb_auxin > 0) {
		ext_pull.init(pauxin, cb_auxin, common_util_alloc, EXT_FLAG_UTF16);
		if (EXT_ERR_SUCCESS != aux_ext_pull_aux_info(&ext_pull, &aux_in)) {
			debug_info("[exchange_emsmdb]: fail to pharse input "
				"auxiliary buffer in emsmdb_interface_rpc_ext2\n");
		}
	}
	result = rop_processor_proc(*pflags, pin, cb_in, pout, pcb_out);
	gx_strlcpy(username, phandle->username, GX_ARRAY_SIZE(username));
	cxr = phandle->cxr;
	BOOL b_wakeup = double_list_get_nodes_num(&phandle->notify_list) == 0 ? false : TRUE;
	emsmdb_interface_put_handle_data(phandle);
	if (TRUE == b_wakeup) {
		asyncemsmdb_interface_wakeup(username, cxr);
	}
	pthread_setspecific(g_handle_key, NULL);
	if (result == ecSuccess) {
		*pflags = 0;
		*pcb_auxout = 0;
		*ptrans_time = emsmdb_interface_get_interval(first_time);
		return ecSuccess;
	} else {
		*pflags = 0;
		*pcb_out = 0;
		*pcb_auxout = 0;
		*ptrans_time = 0;
		return result;
	}
}
	
int emsmdb_interface_async_connect_ex(CXH cxh, ACXH *pacxh)
{
	pacxh->handle_type = HANDLE_EXCHANGE_ASYNCEMSMDB;
	pacxh->guid = cxh.guid;
	return ecSuccess;
}

void emsmdb_interface_unbind_rpc_handle(uint64_t hrpc)
{
	/* do nothing */
}

const GUID* emsmdb_interface_get_handle()
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return NULL;
	}
	return &phandle->guid;
}

EMSMDB_INFO* emsmdb_interface_get_emsmdb_info()
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return NULL;
	}
	return &phandle->info;
}

DOUBLE_LIST* emsmdb_interface_get_notify_list()
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return NULL;
	}
	while (TRUE) {
		std::unique_lock gl_hold(g_lock);
		if (TRUE == phandle->b_occupied) {
			gl_hold.unlock();
			usleep(100000);
		} else {
			phandle->b_occupied = TRUE;
			return &phandle->notify_list;
		}
	}
}

void emsmdb_interface_put_notify_list()
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return;
	}
	emsmdb_interface_put_handle_notify_list(phandle);
}

BOOL emsmdb_interface_get_cxr(uint16_t *pcxr)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	*pcxr = phandle->cxr;
	return TRUE;
}

BOOL emsmdb_interface_alloc_hanlde_number(uint32_t *pnum)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	*pnum = phandle->last_handle;
	phandle->last_handle ++;
	return TRUE;
}

BOOL emsmdb_interface_get_cxh(CXH *pcxh)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	pcxh->handle_type = HANDLE_EXCHANGE_EMSMDB;
	pcxh->guid = phandle->guid;
	return TRUE;
}

BOOL emsmdb_interface_get_rop_left(uint16_t *psize)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	*psize = phandle->rop_left;
	return TRUE;
}

BOOL emsmdb_interface_set_rop_left(uint16_t size)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	phandle->rop_left = size;
	return TRUE;
}

BOOL emsmdb_interface_get_rop_num(int *pnum)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	*pnum = phandle->rop_num;
	return TRUE;
}

BOOL emsmdb_interface_set_rop_num(int num)
{
	HANDLE_DATA *phandle;
	
	phandle = (HANDLE_DATA*)pthread_getspecific(g_handle_key);
	if (NULL == phandle) {
		return FALSE;
	}
	phandle->rop_num = num;
	return TRUE;
}

void emsmdb_interface_add_table_notify(const char *dir,
	uint32_t table_id, uint32_t handle, uint8_t logon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM tmp_notify;
	
	tmp_notify.handle = handle;
	tmp_notify.logon_id = logon_id;
	tmp_notify.guid = *pguid;
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	str_hash_add(g_notify_hash, tag_buff, &tmp_notify);
}

static BOOL emsmdb_interface_get_table_notify(const char *dir,
	uint32_t table_id, uint32_t *phandle, uint8_t *plogon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM *pnotify;
	
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	pnotify = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_hash, tag_buff));
	if (NULL == pnotify) {
		return FALSE;
	}
	*phandle = pnotify->handle;
	*plogon_id = pnotify->logon_id;
	*pguid = pnotify->guid;
	return TRUE;
}

void emsmdb_interface_remove_table_notify(
	const char *dir, uint32_t table_id)
{
	char tag_buff[TAG_SIZE];
	
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u:%s", table_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	str_hash_remove(g_notify_hash, tag_buff);
}

void emsmdb_interface_add_subscription_notify(const char *dir,
	uint32_t sub_id, uint32_t handle, uint8_t logon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM tmp_notify;
	
	
	tmp_notify.handle = handle;
	tmp_notify.logon_id = logon_id;
	tmp_notify.guid = *pguid;
	
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	str_hash_add(g_notify_hash, tag_buff, &tmp_notify);
}

static BOOL emsmdb_interface_get_subscription_notify(
	const char *dir, uint32_t sub_id, uint32_t *phandle,
	uint8_t *plogon_id, GUID *pguid)
{
	char tag_buff[TAG_SIZE];
	NOTIFY_ITEM *pnotify;
	
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	pnotify = static_cast<NOTIFY_ITEM *>(str_hash_query(g_notify_hash, tag_buff));
	if (NULL == pnotify) {
		return FALSE;
	}
	*phandle = pnotify->handle;
	*plogon_id = pnotify->logon_id;
	*pguid = pnotify->guid;
	return TRUE;
}

void emsmdb_interface_remove_subscription_notify(
	const char *dir, uint32_t sub_id)
{
	char tag_buff[TAG_SIZE];
	
	snprintf(tag_buff, GX_ARRAY_SIZE(tag_buff), "%u|%s", sub_id, dir);
	std::lock_guard nt_hold(g_notify_lock);
	str_hash_remove(g_notify_hash, tag_buff);
}

static BOOL emsmdb_interface_merge_content_row_deleted(
	uint32_t obj_handle, uint8_t logon_id, DOUBLE_LIST *pnotify_list)
{
	int count;
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	
	count = 1;
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle ||
			pnotify->logon_id != logon_id) {
			continue;
		}
		if (NULL == pnotification_data->ptable_event) {
			continue;
		}
		if (TABLE_EVENT_ROW_DELETED ==
			*pnotification_data->ptable_event) {
			count ++;
			if (MAX_CONTENT_ROW_DELETED == count) {
				notify_response_content_table_row_event_to_change(pnotify);
				return TRUE;
			}
		} else if (TABLE_EVENT_TABLE_CHANGED ==
			*pnotification_data->ptable_event) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_hierarchy_row_modified(
	const DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *pmodified_row,
	uint32_t obj_handle, uint8_t logon_id, DOUBLE_LIST *pnotify_list)
{
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	uint64_t row_folder_id = (pmodified_row->row_folder_id & 0xFF00000000000000ULL) == 0 ?
	                         rop_util_make_eid_ex(1, pmodified_row->row_folder_id) :
	                         rop_util_make_eid_ex(pmodified_row->row_folder_id >> 48, pmodified_row->row_folder_id & 0x00FFFFFFFFFFFFFFULL);
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle ||
			pnotify->logon_id != logon_id) {
			continue;
		}
		if (NULL == pnotification_data->ptable_event) {
			continue;
		}
		if (TABLE_EVENT_ROW_MODIFIED ==
			*pnotification_data->ptable_event &&
			*pnotification_data->prow_folder_id
			== row_folder_id) {
			double_list_remove(pnotify_list, pnode);
			double_list_append_as_tail(pnotify_list, pnode);
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_message_modified(
	const DB_NOTIFY_MESSAGE_MODIFIED *pmodified_message,
	uint32_t obj_handle, uint8_t logon_id,
	DOUBLE_LIST *pnotify_list)
{
	uint64_t folder_id;
	uint64_t message_id;
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	
	folder_id = rop_util_make_eid_ex(
		1, pmodified_message->folder_id);
	message_id = rop_util_make_eid_ex(
		1, pmodified_message->message_id);
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle ||
			pnotify->logon_id != logon_id) {
			continue;
		}
		if ((NOTIFICATION_FLAG_OBJECTMODIFIED |
			NOTIFICATION_FLAG_MOST_MESSAGE) ==
			pnotification_data->notification_flags &&
			folder_id == *pnotification_data->pfolder_id &&
			message_id == *pnotification_data->pmessage_id
			&& 0 == pnotification_data->pproptags->count) {
			return TRUE;
		}
	}
	return FALSE;
}

static BOOL emsmdb_interface_merge_folder_modified(
	const DB_NOTIFY_FOLDER_MODIFIED *pmodified_folder,
	uint32_t obj_handle, uint8_t logon_id,
	DOUBLE_LIST *pnotify_list)
{
	DOUBLE_LIST_NODE *pnode;
	NOTIFY_RESPONSE *pnotify;
	NOTIFICATION_DATA *pnotification_data;
	uint64_t folder_id = (pmodified_folder->folder_id & 0xFF00000000000000ULL) == 0 ?
	                     rop_util_make_eid_ex(1, pmodified_folder->folder_id) :
	                     rop_util_make_eid_ex(pmodified_folder->folder_id >> 48, pmodified_folder->folder_id & 0x00FFFFFFFFFFFFFFULL);
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		pnotify = static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload);
		pnotification_data = &pnotify->notification_data;
		if (pnotify->handle != obj_handle ||
			pnotify->logon_id != logon_id) {
			continue;
		}
		if (NOTIFICATION_FLAG_OBJECTMODIFIED
			== pnotification_data->notification_flags &&
			folder_id == *pnotification_data->pfolder_id
			&& 0 == pnotification_data->pproptags->count) {
			return TRUE;
		}
	}
	return FALSE;
}

void emsmdb_interface_event_proc(const char *dir, BOOL b_table,
	uint32_t notify_id, const DB_NOTIFY *pdb_notify)
{
	CXH cxh;
	uint16_t cxr;
	uint8_t logon_id;
	BOOL b_processing;
	char username[UADDR_SIZE];
	uint32_t obj_handle;
	HANDLE_DATA *phandle;
	DOUBLE_LIST_NODE *pnode;
	
	cxh.handle_type = HANDLE_EXCHANGE_EMSMDB;
	if (FALSE == b_table) {
		if (FALSE == emsmdb_interface_get_subscription_notify(
			dir, notify_id, &obj_handle, &logon_id, &cxh.guid)) {
			return;
		}
	} else {
		if (FALSE == emsmdb_interface_get_table_notify(dir,
			notify_id, &obj_handle, &logon_id, &cxh.guid)) {
			return;
		}
	}
	phandle = emsmdb_interface_get_handle_notify_list(&cxh);
	if (NULL == phandle) {
		return;
	}
	switch (pdb_notify->type) {
	case DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED:
		if (TRUE == emsmdb_interface_merge_content_row_deleted(
			obj_handle, logon_id, &phandle->notify_list)) {
			emsmdb_interface_put_handle_notify_list(phandle);
			return;
		}
		break;
	case DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED:
		if (emsmdb_interface_merge_hierarchy_row_modified(
		    static_cast<DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list)) {
			b_processing = phandle->b_processing;
			if (FALSE == b_processing) {
				cxr = phandle->cxr;
				gx_strlcpy(username, phandle->username, GX_ARRAY_SIZE(username));
			}
			emsmdb_interface_put_handle_notify_list(phandle);
			if (FALSE == b_processing) {
				asyncemsmdb_interface_wakeup(username, cxr);
			}
			return;
		}
		break;
	case DB_NOTIFY_TYPE_MESSAGE_MODIFIED:
		if (emsmdb_interface_merge_message_modified(
		    static_cast<DB_NOTIFY_MESSAGE_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list)) {
			emsmdb_interface_put_handle_notify_list(phandle);
			return;
		}
		break;
	case DB_NOTIFY_TYPE_FOLDER_MODIFIED:
		if (emsmdb_interface_merge_folder_modified(
		    static_cast<DB_NOTIFY_FOLDER_MODIFIED *>(pdb_notify->pdata),
		    obj_handle, logon_id, &phandle->notify_list)) {
			emsmdb_interface_put_handle_notify_list(phandle);
			return;
		}
		break;
	}
	if (double_list_get_nodes_num(&phandle->notify_list)
		>= MAX_NOTIFY_RESPONSE_NUM) {
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	}
	cxr = phandle->cxr;
	gx_strlcpy(username, phandle->username, GX_ARRAY_SIZE(username));
	pnode = me_alloc<DOUBLE_LIST_NODE>();
	if (NULL == pnode) {
		emsmdb_interface_put_handle_notify_list(phandle);
		return;
	}
	pnode->pdata = me_alloc<ROP_RESPONSE>();
	if (NULL == pnode->pdata) {
		emsmdb_interface_put_handle_notify_list(phandle);
		free(pnode);
		return;
	}
	static_cast<ROP_RESPONSE *>(pnode->pdata)->rop_id = ropRegisterNotify;
	((ROP_RESPONSE*)pnode->pdata)->hindex = 0; /* ignore by system */
	((ROP_RESPONSE*)pnode->pdata)->result = 0; /* ignore by system */
	((ROP_RESPONSE*)pnode->pdata)->ppayload =
			notify_response_init(obj_handle, logon_id);
	if (NULL == ((ROP_RESPONSE*)pnode->pdata)->ppayload) {
		emsmdb_interface_put_handle_notify_list(phandle);
		free(pnode->pdata);
		free(pnode);
		return;
	}
	BOOL b_cache = phandle->info.client_mode == CLIENT_MODE_CACHED ? TRUE : false;
	if (notify_response_retrieve(
	    static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload),
	    b_cache, pdb_notify)) {
		double_list_append_as_tail(&phandle->notify_list, pnode);
		b_processing = phandle->b_processing;
		emsmdb_interface_put_handle_notify_list(phandle);
	} else {
		b_processing = phandle->b_processing;
		emsmdb_interface_put_handle_notify_list(phandle);
		notify_response_free(static_cast<NOTIFY_RESPONSE *>(static_cast<ROP_RESPONSE *>(pnode->pdata)->ppayload));
		free(pnode->pdata);
		free(pnode);
	}
	if (FALSE == b_processing) {
		asyncemsmdb_interface_wakeup(username, cxr);
	}
}

static void *emsi_scanwork(void *pparam)
{
	CXH cxh;
	time_t cur_time;
	STR_HASH_ITER *iter;
	char guid_string[64];
	HANDLE_DATA *phandle;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	while (!g_notify_stop) {
		time(&cur_time);
		std::unique_lock gl_hold(g_lock);
		iter = str_hash_iter_init(g_handle_hash);
		for (str_hash_iter_begin(iter);
			FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			phandle = static_cast<HANDLE_DATA *>(str_hash_iter_get_value(iter, guid_string));
			if (TRUE == phandle->b_processing ||
				TRUE == phandle->b_occupied) {
				continue;
			}
			if (cur_time - phandle->last_time > HANLDE_VALID_INTERVAL) {
				pnode = me_alloc<DOUBLE_LIST_NODE>();
				if (NULL == pnode) {
					continue;
				}
				pnode->pdata = strdup(guid_string);
				if (NULL == pnode->pdata) {
					free(pnode);
					continue;
				}
				double_list_append_as_tail(&temp_list, pnode);
			}
		}
		str_hash_iter_free(iter);
		gl_hold.unlock();
		while ((pnode = double_list_pop_front(&temp_list)) != nullptr) {
			cxh.handle_type = HANDLE_EXCHANGE_EMSMDB;
			guid_from_string(&cxh.guid, static_cast<char *>(pnode->pdata));
			emsmdb_interface_remove_handle(&cxh);
			free(pnode->pdata);
			free(pnode);
		}
		sleep(3);
	}
	return nullptr;
}

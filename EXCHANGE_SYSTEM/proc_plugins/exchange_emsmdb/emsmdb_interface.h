#ifndef _H_EMSMDB_INTERFACE_
#define _H_EMSMDB_INTERFACE_
#include "common_types.h"
#include "proc_common.h"
#include "mapi_types.h"

typedef struct _EMSMDB_INFO {
	uint32_t cpid;
	uint32_t lcid_string;
	uint32_t lcid_sort;
	uint16_t client_version[4];
	uint16_t client_mode;
	void *plogmap;
	int upctx_ref;
} EMSMDB_INFO;

typedef CONTEXT_HANDLE CXH;

typedef CONTEXT_HANDLE ACXH;

extern const char* (*emsmdb_interface_cpid_to_charset)(uint32_t cpid);

void emsmdb_interface_init();

int emsmdb_interface_run();

int emsmdb_interface_stop();

void emsmdb_interface_free();

int emsmdb_interface_disconnect(CXH *pcxh);

int emsmdb_interface_register_push_notification(CXH *pcxh, uint32_t rpc,
	uint8_t *pctx, uint16_t cb_ctx, uint32_t advise_bits, uint8_t *paddr,
	uint16_t cb_addr, uint32_t *phnotification);

int emsmdb_interface_dummy_rpc(uint64_t hrpc);

int emsmdb_interface_connect_ex(uint64_t hrpc, CXH *pcxh,
	const char *puser_dn, uint32_t flags, uint32_t con_mode,
	uint32_t limit, uint32_t cpid, uint32_t lcid_string,
	uint32_t lcid_sort, uint32_t cxr_link, uint16_t cnvt_cps,
	uint32_t *pmax_polls, uint32_t *pmax_retry, uint32_t *pretry_delay,
	uint16_t *pcxr, uint8_t *pdn_prefix, uint8_t *pdisplayname,
	const uint16_t pclient_vers[3], uint16_t pserver_vers[3],
	uint16_t pbest_vers[3], uint32_t *ptimestamp, const uint8_t *pauxin,
	uint32_t cb_auxin, uint8_t *pauxout, uint32_t *pcb_auxout);
	
int emsmdb_interface_rpc_ext2(CXH *pcxh, uint32_t *pflags,
	const uint8_t *pin, uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out,
	const uint8_t *pauxin, uint32_t cb_auxin, uint8_t *pauxout,
	uint32_t *pcb_auxout, uint32_t *ptrans_time);
	
int emsmdb_interface_async_connect_ex(CXH cxh, ACXH *pacxh);

void emsmdb_interface_unbind_rpc_handle(uint64_t hrpc);

BOOL emsmdb_interface_check_acxh(ACXH *pacxh,
	char *username, uint16_t *pcxr, BOOL b_touch);

BOOL emsmdb_interface_check_notify(ACXH *pacxh);

const GUID* emsmdb_interface_get_handle();

EMSMDB_INFO* emsmdb_interface_get_emsmdb_info();

DOUBLE_LIST* emsmdb_interface_get_notify_list();

void emsmdb_interface_put_notify_list();

BOOL emsmdb_interface_get_cxr(uint16_t *pcxr);

BOOL emsmdb_interface_alloc_hanlde_number(uint32_t *pnum);

BOOL emsmdb_interface_get_cxh(CXH *pcxh);

BOOL emsmdb_interface_get_rop_left(uint16_t *psize);

BOOL emsmdb_interface_set_rop_left(uint16_t size);

BOOL emsmdb_interface_get_rop_num(int *pnum);

BOOL emsmdb_interface_set_rop_num(int num);

void emsmdb_interface_add_table_notify(
	const char *dir, uint32_t table_id,
	uint32_t handle, uint8_t logon_id,
	GUID *pguid);

void emsmdb_interface_remove_table_notify(
	const char *dir, uint32_t table_id);

void emsmdb_interface_add_subscription_notify(const char *dir,
	uint32_t sub_id, uint32_t handle, uint8_t logon_id, GUID *pguid);

void emsmdb_interface_remove_subscription_notify(
	const char *dir, uint32_t sub_id);

void emsmdb_interface_event_proc(const char *dir, BOOL b_table,
	uint32_t notify_id, const DB_NOTIFY *pdb_notify);

#endif /* _H_EMSMDB_INTERFACE_ */

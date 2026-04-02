#pragma once
#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <gromox/clock.hpp>
#include <gromox/double_list.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/rpc_types.hpp>
#include "rop_processor.hpp"

struct DB_NOTIFY;

enum {
	RPCEXT2_FLAG_NOCOMPRESSION = 0x1U,
	RPCEXT2_FLAG_NOXORMAGIC    = 0x2U,
	RPCEXT2_FLAG_CHAIN         = 0x4U,

	/* Only for within Gromox */
	GROMOX_READSTREAM_NOCHAIN  = 0x8000U,
};

struct emsmdb_info {
	emsmdb_info() = default;
	emsmdb_info(emsmdb_info &&) noexcept;
	void operator=(emsmdb_info &&) noexcept = delete;

	cpid_t cpid = CP_ACP;
	uint32_t lcid_string = 0, lcid_sort = 0;
	uint16_t client_version[4]{}, client_mode = 0;
	LOGMAP logmap;
	std::atomic<int> upctx_ref{0};
};

struct notify_response;

struct emsmdb_session {
	emsmdb_session();
	~emsmdb_session();
	NOMOVE(emsmdb_session);

	GUID guid{};
	char username[UADDR_SIZE]{};
	uint32_t cxr = 0xFFFFFFFFU; /* ... curious if EXC actually models it as int32_t */
	std::atomic<gromox::time_point> last_time;

	/*
	 * In practice, these three are protected by processing_lock (only
	 * modified in rpc_ext2 subordinate functions).
	 */
	uint32_t last_handle = 0;
	int rop_num = 0;
	uint16_t rop_left = 0; /* size left in rop response buffer */
	emsmdb_info info;

	using notify_list_t = std::vector<std::unique_ptr<notify_response>>;
	notify_list_t notify_list;
	std::mutex notify_lock; /* protects notify_list */
	std::mutex processing_lock; /* rpc_ext2 serial execution */
};

extern void emsmdb_interface_init();
extern int emsmdb_interface_run();
extern void emsmdb_interface_stop();
extern void emsmdb_interface_remove_handle(const CXH &);
extern ec_error_t emsmdb_interface_register_push_notification(CXH *, uint32_t rpc, uint8_t *ctx, uint16_t cb_ctx, uint32_t advise_bits, uint8_t *addr, uint16_t cb_addr, uint32_t *notification);
extern ec_error_t emsmdb_interface_connect_ex(uint64_t hrpc, CXH *, const char *user_dn, uint32_t flags, uint32_t con_mode, uint32_t limit, cpid_t, uint32_t lcid_string, uint32_t lcid_sort, uint32_t cxr_link, uint16_t cnvt_cps, uint32_t *max_polls, uint32_t *max_retry, uint32_t *retry_delay, uint16_t *cxr, std::string &dn_prefix, std::string &dispname, const uint16_t client_vers[3], uint16_t server_vers[3], uint16_t best_vers[3], uint32_t *timestamp, const uint8_t *auxin, uint32_t cb_auxin, uint8_t *auxout, uint32_t *cb_auxout);
extern ec_error_t emsmdb_interface_rpc_ext2(CXH &, uint32_t *flags, const uint8_t *in, uint32_t cb_in, uint8_t *out, uint32_t *cb_out, const uint8_t *auxin, uint32_t cb_auxin, uint8_t *auxout, uint32_t *cb_auxout, uint32_t *trans_time);
extern ec_error_t emsmdb_interface_async_connect_ex(CXH, ACXH *);
extern bool emsmdb_interface_inspect_acxh(const ACXH *, std::string &username, uint16_t *cxr, bool touch);
extern bool emsmdb_interface_notifications_pending(const ACXH &);
extern void emsmdb_interface_touch_handle(const CXH &);
extern std::shared_ptr<emsmdb_session> emsmdb_interface_get_handle_data_SP();
extern const GUID *emsmdb_interface_get_handle();
extern emsmdb_info *emsmdb_interface_get_emsmdb_info();

BOOL emsmdb_interface_get_cxr(uint16_t *pcxr);
extern BOOL emsmdb_interface_alloc_handle_number(uint32_t *num);
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
extern void emsmdb_report();

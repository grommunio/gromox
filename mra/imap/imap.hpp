#pragma once
#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>
#include <gromox/atomic.hpp>
#include <gromox/authmgr.hpp>
#include <gromox/clock.hpp>
#include <gromox/common_types.hpp>
#include <gromox/config_file.hpp>
#include <gromox/contexts_pool.hpp>
#include <gromox/generic_connection.hpp>
#include <gromox/mjson.hpp>
#include <gromox/range_set.hpp>
#include <gromox/simple_tree.hpp>
#include <gromox/stream.hpp>
#include <gromox/threads_pool.hpp>
#include <gromox/util.hpp>
#include <gromox/xarray2.hpp>
#define MAX_LINE_LENGTH (64 * 1024)

struct MITEM;

/* enumeration for the return value of imap_parser_dispatch_cmd */
enum {
	DISPATCH_CONTINUE,
	DISPATCH_SHOULD_CLOSE = 1U << 24,
	DISPATCH_BREAK = 1U << 25,

	DISPATCH_VALMASK = 0x0000FFFFU,
	DISPATCH_MIDB    = 0x00400000U,
	DISPATCH_TAG     = 0x00800000U,
	DISPATCH_ACTMASK = 0xFF000000U,
};

enum class iproto_stat {
	none = 0, noauth, username, password, auth, select,
};

enum class isched_stat {
	none = 0, rdcmd, appending, appended, stls, wrlst, wrdat, idling,
	notifying, autologout, disconnected,
};

/* For use in report_what, imap_context::async_change_flags */
enum {
	REPORT_NEWMAIL = 0x01,
	REPORT_FLAGS   = 0x02,
	REPORT_EXPUNGE = 0x04,
	REPORT_ALL     = ~0U,
};

enum {
	IMAP_RETRIEVE_TERM,
	IMAP_RETRIEVE_OK,
	IMAP_RETRIEVE_ERROR
};

struct MJSON_MIME;
struct XARRAY;
struct XARRAY_UNIT;

struct DIR_NODE {
	SIMPLE_TREE_NODE stree;
	BOOL b_loaded;
	char name[256];
};

struct imap_context;
struct content_array final : public XARRAY {
	using XARRAY::XARRAY;
	using XARRAY::operator=;
	int refresh(imap_context &, const std::string &folder, bool with_expunges = false);
	inline size_t n_exists() const { return m_vec.size(); }
	unsigned int n_recent = 0, firstunseen = -1;
};

/**
 * @mid:        midstr
 * @b_modify:	flag indicating that other clients concurrently modified the mailbox
 * 		(@f_flags, @f_expunged_uids is filled with changes)
 * @contents:	current mapping of seqid -> mid/uid for the currently selected folder
 * @f_flags:    imapuids that were asynchronously reflagged by another thread
 *              and which needs to be conveyed to the client
 * @f_expunged_uids: imapuids that were asynchronously deleted by another thread
 *                   and which needs to be conveyed to the client
 */
struct imap_context final : public schedule_context {
	imap_context();
	NOMOVE(imap_context);
	/* a.k.a. is_login in pop3 */
	inline bool is_authed() const { return proto_stat >= iproto_stat::auth; }

	GENERIC_CONNECTION connection;
	std::string mid, append_folder, append_flags;
	time_t append_time = 0;
	iproto_stat proto_stat = iproto_stat::none;
	isched_stat sched_stat = isched_stat::none;
	char *write_buff = nullptr;
	size_t write_length = 0, write_offset = 0;
	size_t wrdat_offset = 0;
	time_t selected_time = 0;
	std::string selected_folder;
	content_array contents;
	std::string wrdat_content;
	bool wrdat_active = false;
	BOOL b_readonly = false; /* is selected folder read only, this is for the examine command */
	std::atomic<unsigned int> async_change_mask{0};
	/*
	 * Because one mail can get repeatedly re-flagged, f_flags is modeled
	 * with unordered_set (to squash duplicates outright). But a mail can
	 * only be expunged once, so f_expunged_uids is just a vector.
	 */
	std::unordered_set<uint32_t> f_flags;
	std::vector<uint32_t> f_expunged_uids;
	char tag_string[32]{};
	int command_len = 0;
	char command_buffer[64*1024]{};
	int read_offset = 0;
	char read_buffer[64*1024]{};
	char *literal_ptr = nullptr;
	int literal_len = 0, current_len = 0;
	STREAM stream; /* stream for writing to imap client */
	STREAM append_stream;
	mjson_io io_actor;
	int auth_times = 0;
	char username[UADDR_SIZE]{}, maildir[256]{}, defcharset[32]{};
	bool synchronizing_literal = true;
};

extern void imap_parser_init(int context_num, int average_num, gromox::time_duration timeout, gromox::time_duration autologout_time, int max_auth_times, int block_auth_fail, bool support_tls, bool force_tls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int imap_parser_run();
extern tproc_status imap_parser_process(schedule_context *);
extern void imap_parser_stop();
extern int imap_parser_get_context_socket(const schedule_context *);
extern gromox::time_point imap_parser_get_context_timestamp(const schedule_context *);
extern SCHEDULE_CONTEXT **imap_parser_get_contexts_list();
extern int imap_parser_threads_event_proc(int action);
extern void imap_parser_bcast_touch(const imap_context *, const char *user, const std::string &fld);
extern void imap_parser_echo_modify(imap_context *, STREAM *);
extern void imap_parser_bcast_flags(const imap_context &, uint32_t uid);
extern void imap_parser_add_select(imap_context *);
extern void imap_parser_bcast_expunge(const imap_context &, const std::vector<MITEM *> &);
extern void imap_parser_remove_select(imap_context *);
extern  void imap_parser_safe_write(imap_context *, const void *pbuff, size_t count);
extern int imap_parser_get_sequence_ID();
extern void imap_parser_log_info(imap_context *, int level, const char *format, ...) __attribute__((format(printf, 3, 4)));

extern void icp_clsfld(imap_context &);
extern int icp_capability(int argc, char **argv, imap_context &);
extern int icp_id(int argc, char **argv, imap_context &);
extern int icp_noop(int argc, char **argv, imap_context &);
extern int icp_logout(int argc, char **argv, imap_context &);
extern int icp_starttls(int argc, char **argv, imap_context &);
extern int icp_authenticate(int argc, char **argv, imap_context &);
extern int icp_username(int argc, char **argv, imap_context &);
extern int icp_password(int argc, char **argv, imap_context &);
extern int icp_login(int argc, char **argv, imap_context &);
extern int icp_idle(int argc, char **argv, imap_context &);
extern int icp_select(int argc, char **argv, imap_context &);
extern int icp_examine(int argc, char **argv, imap_context &);
extern int icp_create(int argc, char **argv, imap_context &);
extern int icp_delete(int argc, char **argv, imap_context &);
extern int icp_rename(int argc, char **argv, imap_context &);
extern int icp_subscribe(int argc, char **argv, imap_context &);
extern int icp_unsubscribe(int argc, char **argv, imap_context &);
extern int icp_list(int argc, char **argv, imap_context &);
extern int icp_xlist(int argc, char **argv, imap_context &);
extern int icp_lsub(int argc, char **argv, imap_context &);
extern int icp_status(int argc, char **argv, imap_context &);
extern int icp_append(int argc, char **argv, imap_context &);
extern int icp_append_begin(int argc, char **argv, imap_context &);
extern int icp_append_end(int argc, char **argv, imap_context &);
extern int icp_check(int argc, char **argv, imap_context &);
extern int icp_close(int argc, char **argv, imap_context &);
extern int icp_expunge(int argc, char **argv, imap_context &);
extern int icp_unselect(int argc, char **argv, imap_context &);
extern int icp_search(int argc, char **argv, imap_context &);
extern int icp_fetch(int argc, char **argv, imap_context &);
extern int icp_store(int argc, char **argv, imap_context &);
extern int icp_copy(int argc, char **argv, imap_context &);
extern int icp_uid_search(int argc, char **argv, imap_context &);
extern int icp_uid_fetch(int argc, char **argv, imap_context &);
extern int icp_uid_store(int argc, char **argv, imap_context &);
extern int icp_uid_copy(int argc, char **argv, imap_context &);
extern int icp_uid_expunge(int argc, char **argv, imap_context &);
extern int icp_dval(int argc, char **argv, imap_context &, unsigned int res);

extern char *capability_list(char *, size_t, imap_context *);

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_imap_code(unsigned int code_type, unsigned int n, size_t *len = nullptr);
extern const char *resource_get_default_charset(const char *lang);
extern const char *resource_get_error_string(unsigned int);
extern void imap_parser_event_expunge(const char *user, const char *folder, unsigned int uid);

extern void imrpc_build_env();
extern void imrpc_free_env();

extern bool (*system_services_judge_ip)(const char *host, std::string &reason);
extern bool (*system_services_judge_user)(const char *);
extern void (*system_services_ban_user)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern void (*system_services_install_event_stub)(void (*)(char *));
extern void (*system_services_broadcast_event)(const char *);
extern void (*system_services_broadcast_select)(const char *, const std::string &fld);
extern void (*system_services_broadcast_unselect)(const char *, const std::string &fld);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
extern uint16_t g_listener_ssl_port;
extern unsigned int g_imapcmd_debug;
extern int g_max_auth_times, g_block_auth_fail;
extern bool g_support_tls, g_force_tls, g_rfc9051_enable;

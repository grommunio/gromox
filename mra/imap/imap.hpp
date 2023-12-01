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
	int refresh(imap_context &, const char *folder_name, bool with_expunges = false);
	inline size_t n_exists() const { return m_vec.size(); }
	unsigned int n_recent = 0, firstunseen = -1;
};

/**
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
	~imap_context();
	NOMOVE(imap_context);
	/* a.k.a. is_login in pop3 */
	inline bool is_authed() const { return proto_stat >= iproto_stat::auth; }

	GENERIC_CONNECTION connection;
	std::string mid, file_path;
	iproto_stat proto_stat = iproto_stat::none;
	isched_stat sched_stat = isched_stat::none;
	int message_fd = -1;
	char *write_buff = nullptr;
	size_t write_length = 0, write_offset = 0;
	time_t selected_time = 0;
	char selected_folder[1024]{};
	content_array contents;
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
	int auth_times = 0;
	char username[UADDR_SIZE]{}, maildir[256]{}, lang[32]{}, defcharset[32]{};
	bool synchronizing_literal = true;
};
using IMAP_CONTEXT = imap_context;

extern void imap_parser_init(int context_num, int average_num, size_t cache_size, gromox::time_duration timeout, gromox::time_duration autologout_time, int max_auth_times, int block_auth_fail, bool support_tls, bool force_tls, const char *certificate_path, const char *cb_passwd, const char *key_path);
extern int imap_parser_run();
extern tproc_status imap_parser_process(schedule_context *);
extern void imap_parser_stop();
extern int imap_parser_get_context_socket(const schedule_context *);
extern gromox::time_point imap_parser_get_context_timestamp(const schedule_context *);
extern SCHEDULE_CONTEXT **imap_parser_get_contexts_list();
extern int imap_parser_threads_event_proc(int action);
extern void imap_parser_bcast_touch(const imap_context *, const char *user, const char *folder);
extern void imap_parser_echo_modify(imap_context *, STREAM *, unsigned int report = REPORT_NEWMAIL | REPORT_FLAGS | REPORT_EXPUNGE);
extern void imap_parser_bcast_flags(const imap_context &, uint32_t uid);
extern void imap_parser_add_select(IMAP_CONTEXT *);
extern void imap_parser_bcast_expunge(const IMAP_CONTEXT &, const std::vector<MITEM *> &);
extern void imap_parser_remove_select(IMAP_CONTEXT *);
extern  void imap_parser_safe_write(IMAP_CONTEXT *, const void *pbuff, size_t count);
extern int imap_parser_get_sequence_ID();
extern void imap_parser_log_info(IMAP_CONTEXT *, int level, const char *format, ...);

extern void imap_cmd_parser_clsfld(IMAP_CONTEXT *);
extern int imap_cmd_parser_capability(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_id(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_noop(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_logout(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_starttls(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_authenticate(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_username(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_password(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_login(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_idle(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_select(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_examine(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_create(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_delete(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_rename(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_subscribe(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_unsubscribe(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_list(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_xlist(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_lsub(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_status(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_append(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_append_begin(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_append_end(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_check(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_close(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_expunge(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_unselect(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_search(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_fetch(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_store(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_copy(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_uid_search(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_uid_fetch(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_uid_store(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_uid_copy(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_uid_expunge(int argc, char **argv, IMAP_CONTEXT *);
extern int imap_cmd_parser_dval(int argc, char **argv, IMAP_CONTEXT *, unsigned int res);

extern char *capability_list(char *, size_t, IMAP_CONTEXT *);

extern int resource_run();
extern void resource_stop();
extern const char *resource_get_imap_code(unsigned int code_type, unsigned int n, size_t *len = nullptr);
extern const char *resource_get_default_charset(const char *lang);
extern const char *resource_get_error_string(unsigned int);
extern void imap_parser_event_expunge(const char *user, const char *folder, unsigned int uid);

extern void imrpc_build_env();
extern void imrpc_free_env();

extern bool (*system_services_judge_ip)(const char *host, std::string &reason);
extern BOOL (*system_services_judge_user)(const char *);
extern BOOL (*system_services_add_user_into_temp_list)(const char *, int);
extern authmgr_login_t system_services_auth_login;
extern gromox::errno_t (*system_services_auth_meta)(const char *username, unsigned int wantpriv, sql_meta_result &out);
extern int (*system_services_get_uid)(const char *, const char *, const std::string &, unsigned int *);
extern int (*system_services_summary_folder)(const char *, const char *, size_t *, size_t *, size_t *, uint32_t *, uint32_t *, int *);
extern int (*system_services_make_folder)(const char *, const char *, int *);
extern int (*system_services_remove_folder)(const char *, const char *, int *);
extern int (*system_services_rename_folder)(const char *, const char *, const char *, int *);
extern int (*system_services_ping_mailbox)(const char *, int *);
extern int (*system_services_subscribe_folder)(const char *, const char *, int *);
extern int (*system_services_unsubscribe_folder)(const char *, const char *, int *);
extern int (*system_services_enum_folders)(const char *, std::vector<std::string> &, int *);
extern int (*system_services_enum_subscriptions)(const char *, std::vector<std::string> &, int *);
extern int (*system_services_insert_mail)(const char *, const char *, const char *, const char *, long, int *);
extern int (*system_services_remove_mail)(const char *, const char *, const std::vector<MITEM *> &, int *);
extern int (*system_services_list_deleted)(const char *, const char *, XARRAY *, int *);
extern int (*system_services_fetch_simple_uid)(const char *, const char *, const gromox::imap_seq_list &, XARRAY *, int *);
extern int (*system_services_fetch_detail_uid)(const char *, const char *, const gromox::imap_seq_list &, XARRAY *, int *);
extern int (*system_services_set_flags)(const char *, const char *, const std::string &mid, int, int *);
extern int (*system_services_unset_flags)(const char *, const char *, const std::string &mid, int, int *);
extern int (*system_services_get_flags)(const char *, const char *, const std::string &mid, int *, int *);
extern int (*system_services_copy_mail)(const char *, const char *, const std::string &mid, const char *, std::string &dst_mid, int *);
extern int (*system_services_search)(const char *, const char *, const char *, int, char **, std::string &, int *);
extern int (*system_services_search_uid)(const char *, const char *, const char *, int, char **, std::string &, int *);
extern void (*system_services_install_event_stub)(void (*)(char *));
extern void (*system_services_broadcast_event)(const char *);
extern void (*system_services_broadcast_select)(const char *, const char *);
extern void (*system_services_broadcast_unselect)(const char *, const char *);

extern std::shared_ptr<CONFIG_FILE> g_config_file;
extern uint16_t g_listener_ssl_port;
extern unsigned int g_imapcmd_debug;
extern int g_max_auth_times, g_block_auth_fail;
extern bool g_support_tls, g_force_tls, g_rfc9051_enable;

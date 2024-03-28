#pragma once
#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sqlite3.h>
#include <string>
#include <gromox/clock.hpp>
#include <gromox/database.h>
#include <gromox/element_data.hpp>
#include <gromox/mapi_types.hpp>
#define CONTENT_ROW_HEADER						1
#define CONTENT_ROW_MESSAGE						2

enum {
	EXMDB_UPGRADE_NO = 0,
	EXMDB_UPGRADE_YES,
	EXMDB_UPGRADE_AUTO,
};

enum class dynamic_event {
	new_msg, modify_msg, del_msg, move_folder,
};

struct dynamic_node {
	dynamic_node() = default;
	dynamic_node(dynamic_node &&) noexcept;
	~dynamic_node();
	dynamic_node &operator=(dynamic_node &&) noexcept;

	uint64_t folder_id = 0; /* search folder ID */
	uint32_t search_flags = 0;
	RESTRICTION *prestriction = nullptr;
	LONGLONG_ARRAY folder_ids{}; /* source folder IDs */
};

enum class table_type : uint8_t {
	hierarchy, content, permission, rule,
};

enum class instance_type {
	message, attachment,
};

struct table_node {
	struct clone_t {};

	table_node() = default;
	table_node(const table_node &, clone_t);
	~table_node();
	NOMOVE(table_node);

	uint32_t table_id = 0, table_flags = 0;
	cpid_t cpid = CP_ACP;
	enum table_type type = table_type::hierarchy;
	bool cloned = false;
	char *remote_id = nullptr, *username = nullptr;
	uint64_t folder_id = 0;
	GUID handle_guid{};
	RESTRICTION *prestriction = nullptr;
	SORTORDER_SET *psorts = nullptr;
	uint32_t instance_tag = 0, extremum_tag = 0, header_id = 0;
	BOOL b_search = false;
	BOOL b_hint = false; /* is table touched in batch-mode */
};

struct nsub_node {
	char *remote_id = nullptr;
	uint32_t sub_id = 0;
	uint8_t notification_type = 0;
	BOOL b_whole = false;
	uint64_t folder_id = 0, message_id = 0;
};

#define CHANGE_MASK_HTML						0x01
#define CHANGE_MASK_BODY						0x02

struct instance_node {
	instance_node() = default;
	instance_node(instance_node &&) noexcept;
	~instance_node() { release(); }
	instance_node &operator=(instance_node &&) noexcept;
	void release();

	uint32_t instance_id = 0, parent_id = 0, folder_id = 0, last_id = 0;
	cpid_t cpid = CP_ACP;
	enum instance_type type = instance_type::message;
	BOOL b_new = false;
	uint8_t change_mask{};
	std::string username;
	void *pcontent = nullptr;
};

struct prepared_statements {
	~prepared_statements();
	bool begin(sqlite3 *);

	gromox::xstmt msg_norm, msg_str, rcpt_norm, rcpt_str;
};

/**
 * @reference: client reference count, db_base can be destroyed when count is 0
 */
struct db_base {
	db_base();
	~db_base();
	NOMOVE(db_base);

	std::shared_mutex giant_lock;
	std::atomic<int> reference;
	gromox::time_point last_time{};
	sqlite3 *psqlite = nullptr, *m_sqlite_eph = nullptr;
	/* memory database for holding rop table objects instance */
	struct {
		uint32_t last_id = 0;
		bool b_batch = false; /* message database is in batch-mode */
		std::list<table_node> table_list;
	} tables;
	std::vector<nsub_node> nsub_list;
	std::vector<dynamic_node> dynamic_list; /* dynamic searches */
	std::vector<instance_node> instance_list;

	uint32_t next_instance_id() const;
	instance_node *get_instance(uint32_t);
	inline const instance_node *get_instance_c(uint32_t id) const { return const_cast<db_base *>(this)->get_instance(id); }
	const table_node *find_table(uint32_t) const;
};

class db_item_deleter;
struct db_conn : public db_base {
	db_conn() : m_base(this) {}
	bool postconstruct_init(const char *dir);
	void update_dynamic(uint64_t folder_id, uint32_t search_flags, const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids);
	void delete_dynamic(uint64_t folder_id);
	void proc_dynamic_event(cpid_t, enum dynamic_event, uint64_t id1, uint64_t id2, uint64_t id3);
	void notify_new_mail(uint64_t folder_id, uint64_t msg_id);
	void notify_message_creation(uint64_t folder_id, uint64_t msg_id);
	void notify_link_creation(uint64_t parent_id, uint64_t msg_id);
	void notify_folder_creation(uint64_t parent_id, uint64_t folder_id);
	void notify_message_deletion(uint64_t folder_id, uint64_t msg_id);
	void notify_link_deletion(uint64_t parent_id, uint64_t msg_id);
	void notify_folder_deletion(uint64_t parent_id, uint64_t folder_id);
	void notify_message_modification(uint64_t folder_id, uint64_t msg_id);
	void notify_folder_modification(uint64_t parent_id, uint64_t folder_id);
	void notify_message_movecopy(BOOL b_copy, uint64_t folder_id, uint64_t msg_id, uint64_t old_fid, uint64_t old_mid);
	void notify_folder_movecopy(BOOL b_copy, uint64_t parent_id, uint64_t folder_id, uint64_t old_pid, uint64_t old_fid);
	void notify_cttbl_reload(uint32_t table_id);
	void transport_new_mail(uint64_t folder_id, uint64_t msg_id, uint32_t msg_flags, const char *klass);
	void begin_batch_mode();
	/* pdb will also be put */
	static void commit_batch_mode_release(std::unique_ptr<db_conn, db_item_deleter> &&pdb);
	void cancel_batch_mode();
	std::unique_ptr<prepared_statements> begin_optim();

	gromox::xstmt prep(const char *q) const { return gromox::gx_sql_prep(psqlite, q); }
	int exec(const char *q, unsigned int fl = 0) const { return gromox::gx_sql_exec(psqlite, q, fl); }
	gromox::xstmt eph_prep(const char *q) const { return gromox::gx_sql_prep(m_sqlite_eph, q); }
	int eph_exec(const char *q) const { return gromox::gx_sql_exec(m_sqlite_eph, q); }

	db_base *m_base = nullptr;
};

extern void db_engine_init(size_t table_size, int cache_interval, unsigned int threads_num);
extern int db_engine_run();
extern void db_engine_stop();

class db_item_deleter {
	public:
	void operator()(db_conn *) const;
};

using db_conn_ptr = std::unique_ptr<db_conn, db_item_deleter>;

extern db_conn_ptr db_engine_get_db(const char *dir);
extern BOOL db_engine_vacuum(const char *path);
BOOL db_engine_unload_db(const char *path);
extern BOOL db_engine_enqueue_populating_criteria(const char *dir, cpid_t, uint64_t folder_id, BOOL recursive, const RESTRICTION *, const LONGLONG_ARRAY *folder_ids);
extern bool db_engine_check_populating(const char *dir, uint64_t folder_id);

extern unsigned int g_exmdb_schema_upgrades, g_exmdb_search_pacing;
extern unsigned long long g_exmdb_search_pacing_time, g_exmdb_lock_timeout;
extern unsigned int g_exmdb_search_yield, g_exmdb_search_nice;
extern unsigned int g_exmdb_pvt_folder_softdel;
extern std::string g_exmdb_ics_log_file;

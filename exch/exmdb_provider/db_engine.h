#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <gromox/double_list.hpp>
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

struct DYNAMIC_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

enum class table_type {
	hierarchy, content, permission, rule,
};

enum class instance_type {
	message, attachment,
};

struct TABLE_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t table_id;
	enum table_type type;
	char *remote_id;
	uint64_t folder_id;
	GUID handle_guid;
	uint32_t table_flags;
	cpid_t cpid;
	char *username;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
	uint32_t instance_tag;
	uint32_t extremum_tag;
	uint32_t header_id;
	BOOL b_search;
	BOOL b_hint;		/* is table touched in batch-mode */
};

struct nsub_node {
	char *remote_id = nullptr;
	uint32_t sub_id = 0;
	uint8_t notification_type = 0;
	BOOL b_whole = false;
	uint64_t folder_id = 0, message_id = 0;
};
using NSUB_NODE = nsub_node;

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
using INSTANCE_NODE = instance_node;

struct DB_ITEM {
	DB_ITEM() = default;
	~DB_ITEM();
	NOMOVE(DB_ITEM);

	/* client reference count, item can be flushed into file system only count is 0 */
	std::atomic<int> reference{0};
	time_t last_time = 0;
	std::timed_mutex giant_lock; /* should be broken up */
	sqlite3 *psqlite = nullptr;
	DOUBLE_LIST dynamic_list{};	/* dynamic search list */
	std::vector<nsub_node> nsub_list;
	std::vector<instance_node> instance_list;

	/* memory database for holding rop table objects instance */
	struct {
		uint32_t last_id = 0;
		BOOL b_batch = false; /* message database is in batch-mode */
		DOUBLE_LIST table_list{};
		sqlite3 *psqlite = nullptr;
	} tables;
};

extern void db_engine_init(size_t table_size, int cache_interval, BOOL async, BOOL wal, uint64_t mmap_size, unsigned int threads_num);
extern int db_engine_run();
extern void db_engine_stop();

class db_item_deleter {
	public:
	void operator()(DB_ITEM *) const;
};

using db_item_ptr = std::unique_ptr<DB_ITEM, db_item_deleter>;

extern db_item_ptr db_engine_get_db(const char *dir);
extern BOOL db_engine_vacuum(const char *path);
BOOL db_engine_unload_db(const char *path);
extern BOOL db_engine_enqueue_populating_criteria(const char *dir, cpid_t, uint64_t folder_id, BOOL recursive, const RESTRICTION *, const LONGLONG_ARRAY *folder_ids);
extern bool db_engine_check_populating(const char *dir, uint64_t folder_id);
extern void db_engine_update_dynamic(db_item_ptr &, uint64_t folder_id, uint32_t search_flags, const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids);
extern void db_engine_delete_dynamic(db_item_ptr &, uint64_t folder_id);
extern void db_engine_proc_dynamic_event(db_item_ptr &, cpid_t, enum dynamic_event, uint64_t id1, uint64_t id2, uint64_t id3);
extern void db_engine_notify_new_mail(db_item_ptr &, uint64_t folder_id, uint64_t msg_id);
extern void db_engine_notify_message_creation(db_item_ptr &, uint64_t folder_id, uint64_t msg_id);
extern void db_engine_notify_link_creation(db_item_ptr &, uint64_t parent_id, uint64_t msg_id);
extern void db_engine_notify_folder_creation(db_item_ptr &, uint64_t parent_id, uint64_t folder_id);
extern void db_engine_notify_message_deletion(db_item_ptr &, uint64_t folder_id, uint64_t msg_id);
extern void db_engine_notify_link_deletion(db_item_ptr &, uint64_t parent_id, uint64_t msg_id);
extern void db_engine_notify_folder_deletion(db_item_ptr &, uint64_t parent_id, uint64_t folder_id);
extern void db_engine_notify_message_modification(db_item_ptr &, uint64_t folder_id, uint64_t msg_id);
extern void db_engine_notify_folder_modification(db_item_ptr &, uint64_t parent_id, uint64_t folder_id);
extern void db_engine_notify_message_movecopy(db_item_ptr &, BOOL b_copy, uint64_t folder_id, uint64_t msg_id, uint64_t old_fid, uint64_t old_mid);
extern void db_engine_notify_folder_movecopy(db_item_ptr &, BOOL b_copy, uint64_t parent_id, uint64_t folder_id, uint64_t old_pid, uint64_t old_fid);
extern void db_engine_notify_content_table_reload(db_item_ptr &, uint32_t table_id);
extern void db_engine_transport_new_mail(db_item_ptr &, uint64_t folder_id, uint64_t msg_id, uint32_t message_flags, const char *pstr_class);
extern void db_engine_begin_batch_mode(db_item_ptr &);
/* pdb will also be put */
extern void db_engine_commit_batch_mode(db_item_ptr &&);
extern void db_engine_cancel_batch_mode(db_item_ptr &);

extern unsigned int g_exmdb_schema_upgrades, g_exmdb_search_pacing;
extern unsigned int g_exmdb_search_yield, g_exmdb_search_nice;
extern unsigned int g_exmdb_pvt_folder_softdel;

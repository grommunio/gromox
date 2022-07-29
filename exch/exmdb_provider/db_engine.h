#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sqlite3.h>
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

enum {
	DYNAMIC_EVENT_NEW_MESSAGE,
	DYNAMIC_EVENT_MODIFY_MESSAGE,
	DYNAMIC_EVENT_DELETE_MESSAGE,
	DYNAMIC_EVENT_MOVE_FOLDER
};

struct DYNAMIC_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t folder_id;
	uint32_t search_flags;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
};

enum {
	TABLE_TYPE_HIERARCHY,
	TABLE_TYPE_CONTENT,
	TABLE_TYPE_PERMISSION,
	TABLE_TYPE_RULE
};

enum instance_type {
	INSTANCE_TYPE_MESSAGE,
	INSTANCE_TYPE_ATTACHMENT
};

struct TABLE_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t table_id;
	char *remote_id;
	int type;
	BOOL b_search;
	uint64_t folder_id;
	uint8_t table_flags;
	GUID handle_guid;
	uint32_t cpid;
	char *username;
	RESTRICTION *prestriction;
	SORTORDER_SET *psorts;
	uint32_t instance_tag;
	uint32_t extremum_tag;
	uint32_t header_id;
	BOOL b_hint;		/* is table touched in batch-mode */
};

struct NSUB_NODE {
	DOUBLE_LIST_NODE node;
	char *remote_id;
	uint32_t sub_id;
	uint8_t notificaton_type;
	BOOL b_whole;
	uint64_t folder_id;
	uint64_t message_id;
};

#define CHANGE_MASK_HTML						0x01
#define CHANGE_MASK_BODY						0x02

struct INSTANCE_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t instance_id;
	uint32_t parent_id;
	uint64_t folder_id;
	uint32_t last_id;
	uint32_t cpid;
	char *username;
	enum instance_type type;
	BOOL b_new;
	uint8_t change_mask;
	void *pcontent;
};

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
	DOUBLE_LIST nsub_list{};
	DOUBLE_LIST instance_list{};

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
void db_engine_put_db(DB_ITEM *pdb);

class db_item_deleter {
	public:
	void operator()(DB_ITEM *d) { db_engine_put_db(d); }
};

using db_item_ptr = std::unique_ptr<DB_ITEM, db_item_deleter>;

extern db_item_ptr db_engine_get_db(const char *dir);
BOOL db_engine_unload_db(const char *path);
BOOL db_engine_enqueue_populating_criteria(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	BOOL b_recursive, const RESTRICTION *prestriction,
	const LONGLONG_ARRAY *pfolder_ids);
extern bool db_engine_check_populating(const char *dir, uint64_t folder_id);
extern void db_engine_update_dynamic(db_item_ptr &, uint64_t folder_id, uint32_t search_flags, const RESTRICTION *prestriction, const LONGLONG_ARRAY *pfolder_ids);
extern void db_engine_delete_dynamic(db_item_ptr &, uint64_t folder_id);
extern void db_engine_proc_dynamic_event(db_item_ptr &, uint32_t cpid, int event_type, uint64_t id1, uint64_t id2, uint64_t id3);
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
extern unsigned int g_exmdb_search_yield;

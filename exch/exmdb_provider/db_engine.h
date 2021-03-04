#pragma once
#include <atomic>
#include <cstdint>
#include <gromox/element_data.hpp>
#include <gromox/double_list.hpp>
#include <gromox/mapi_types.hpp>
#include <pthread.h>
#include <sqlite3.h>

#define CONTENT_ROW_HEADER						1
#define CONTENT_ROW_MESSAGE						2

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

enum {
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
	int type;
	BOOL b_new;
	uint8_t change_mask;
	void *pcontent;
};

/* memory database for holding rop table objects instance */
struct MEMORY_TABLES {
	uint32_t last_id;
	BOOL b_batch;			/* message database is in batch-mode */
	DOUBLE_LIST table_list;
	sqlite3 *psqlite;
};

struct DB_ITEM {
	/* client reference count, item can be flushed into file system only count is 0 */
	std::atomic<int> reference{0};
	time_t last_time = 0;
	pthread_mutex_t lock{};
	sqlite3 *psqlite = nullptr;
	DOUBLE_LIST dynamic_list{};	/* dynamic search list */
	DOUBLE_LIST nsub_list{};
	DOUBLE_LIST instance_list{};
	MEMORY_TABLES tables{};
};

void db_engine_init(int table_size, int cache_interval,
	BOOL b_async, BOOL b_wal, uint64_t mmap_size, int threads_num);
extern int db_engine_run();
extern int db_engine_stop();
extern void db_engine_free();
DB_ITEM* db_engine_get_db(const char *path);

void db_engine_put_db(DB_ITEM *pdb);

BOOL db_engine_unload_db(const char *path);

BOOL db_engine_enqueue_populating_criteria(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	BOOL b_recursive, const RESTRICTION *prestriction,
	const LONGLONG_ARRAY *pfolder_ids);

BOOL db_engine_check_populating(const char *dir, uint64_t folder_id);

void db_engine_update_dynamic(DB_ITEM *pdb, uint64_t folder_id,
	uint32_t search_flags, const RESTRICTION *prestriction,
	const LONGLONG_ARRAY *pfolder_ids);

void db_engine_delete_dynamic(DB_ITEM *pdb, uint64_t folder_id);
extern void db_engine_proc_dynamic_event(DB_ITEM *pdb, uint32_t cpid, int event_type, uint64_t id1, uint64_t id2, uint64_t id3);
void db_engine_notify_new_mail(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id);

void db_engine_notify_message_creation(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id);

void db_engine_notify_link_creation(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t message_id);

void db_engine_notify_folder_creation(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id);

void db_engine_notify_message_deletion(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id);

void db_engine_notify_link_deletion(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t message_id);

void db_engine_notify_folder_deletion(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id);

void db_engine_notify_message_modification(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id);

void db_engine_notify_folder_modification(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id);

void db_engine_notify_message_movecopy(DB_ITEM *pdb,
	BOOL b_copy, uint64_t folder_id, uint64_t message_id,
	uint64_t old_fid, uint64_t old_mid);

void db_engine_notify_folder_movecopy(DB_ITEM *pdb,
	BOOL b_copy, uint64_t parent_id, uint64_t folder_id, 
	uint64_t old_pid, uint64_t old_fid);

void db_engine_notify_content_table_reload(
	DB_ITEM *pdb, uint32_t table_id);
	
void db_engine_transport_new_mail(DB_ITEM *pdb, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class);

void db_engine_begin_batch_mode(DB_ITEM *pdb);

/* pdb will also be put */
void db_engine_commit_batch_mode(DB_ITEM *pdb);

void db_engine_cancel_batch_mode(DB_ITEM *pdb);

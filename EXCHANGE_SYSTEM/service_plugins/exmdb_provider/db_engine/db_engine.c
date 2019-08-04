#include "util.h"
#include "guid.h"
#include "str_hash.h"
#include "db_engine.h"
#include "eid_array.h"
#include "ext_buffer.h"
#include "double_list.h"
#include "restriction.h"
#include "common_util.h"
#include "exmdb_server.h"
#include "sortorder_set.h"
#include "proptag_array.h"
#include "notification_agent.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define DB_LOCK_TIMEOUT					30

#define MAX_DB_WAITING_THREADS			5

#define MAX_DYNAMIC_NODES				100

typedef struct _POPULATING_NODE {
	DOUBLE_LIST_NODE node;
	char *dir;
	uint32_t cpid;
	uint64_t folder_id;
	BOOL b_recursive;
	RESTRICTION *prestriction;
	LONGLONG_ARRAY folder_ids;
} POPULATING_NODE;

typedef struct _SUBLIST_NODE {
	DOUBLE_LIST_NODE node;
	const char *remote_id;
	DOUBLE_LIST list;
} SUBLIST_NODE;

typedef struct _ID_ARRAYS {
	int count;
	const char **remote_ids;
	LONG_ARRAY *parray;
} ID_ARRAYS;

typedef struct _ID_NODE {
	DOUBLE_LIST_NODE node;
	const char *remote_id;
	uint32_t id;
} ID_NODE;

typedef struct _ROWINFO_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_added;
	uint64_t row_id;
} ROWINFO_NODE;

typedef struct _ROWDEL_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t row_id;
	uint32_t idx;
	int64_t prev_id;
	uint64_t inst_id;
	uint64_t parent_id;
	uint32_t depth;
	uint32_t inst_num;
	BOOL b_read;
} ROWDEL_NODE;

static BOOL g_wal;
static BOOL g_async;
static int g_table_size;		/* hash table size */
static int g_threads_num;
static BOOL g_notify_stop;		/* stop signal for scaning thread */
static pthread_t g_scan_tid;
static uint64_t g_mmap_size;
static int g_cache_interval;	/* maximum living interval in table */
static pthread_t *g_thread_ids;
static pthread_mutex_t g_list_lock;
static pthread_mutex_t g_hash_lock;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_cond_mutex;
static STR_HASH_TABLE *g_hash_table;
static DOUBLE_LIST g_populating_list;
static DOUBLE_LIST g_populating_list1;

static void db_engine_notify_content_table_modify_row(
	DB_ITEM *pdb, uint64_t folder_id, uint64_t message_id);

static void db_engine_load_dynamic_list(DB_ITEM *pdb)
{
	int sql_len;
	EXT_PULL ext_pull;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint32_t search_flags;
	DYNAMIC_NODE *pdynamic;
	LONGLONG_ARRAY tmp_fids;
	RESTRICTION tmp_restriction;
	
	sql_len = sprintf(sql_string, "SELECT folder_id,"
		" search_flags, search_criteria FROM folders"
		" WHERE is_search=1");
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (double_list_get_nodes_num(
			&pdb->dynamic_list) >= MAX_DYNAMIC_NODES) {
			break;
		}
		search_flags = sqlite3_column_int64(pstmt, 1);
		if ((0 == search_flags) || (search_flags &
			SEARCH_FLAG_STATIC) || (search_flags &
			SEARCH_FLAG_STOP)) {
			continue;
		}
		pdynamic = malloc(sizeof(DYNAMIC_NODE));
		if (NULL == pdynamic) {
			break;
		}
		pdynamic->node.pdata = pdynamic;
		pdynamic->folder_id = sqlite3_column_int64(pstmt, 0);
		pdynamic->search_flags = search_flags;
		ext_buffer_pull_init(&ext_pull,
			sqlite3_column_blob(pstmt, 2),
			sqlite3_column_bytes(pstmt, 2),
			common_util_alloc, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_pull_restriction(
			&ext_pull, &tmp_restriction)) {
			free(pdynamic);
			continue;
		}
		pdynamic->prestriction = restriction_dup(&tmp_restriction);
		if (NULL == pdynamic->prestriction) {
			free(pdynamic);
			break;
		}
		if (FALSE == common_util_load_search_scopes(
			pdb->psqlite, pdynamic->folder_id, &tmp_fids)) {
			restriction_free(pdynamic->prestriction);
			free(pdynamic);
			continue;
		}
		pdynamic->folder_ids.count = tmp_fids.count;
		pdynamic->folder_ids.pll = malloc(
			sizeof(uint64_t)*tmp_fids.count);
		if (NULL == pdynamic->folder_ids.pll) {
			restriction_free(pdynamic->prestriction);
			free(pdynamic);
			break;
		}
		memcpy(pdynamic->folder_ids.pll, tmp_fids.pll,
					sizeof(uint64_t)*tmp_fids.count);
		double_list_append_as_tail(
			&pdb->dynamic_list, &pdynamic->node);
	}
	sqlite3_finalize(pstmt);
}

/* query or create DB_ITEM in hash table */
DB_ITEM* db_engine_get_db(const char *path)
{
	BOOL b_new;
	DB_ITEM *pdb;
	char htag[256];
	DB_ITEM temp_db;
	char db_path[256];
	char sql_string[256];
	struct timespec timeout_tm;
	
	b_new = FALSE;
	swap_string(htag, path);
	pthread_mutex_lock(&g_hash_lock);
	pdb = (DB_ITEM*)str_hash_query(g_hash_table, htag);
	if (NULL == pdb) {
		memset(&temp_db, 0, sizeof(DB_ITEM));
		if (1 != str_hash_add(g_hash_table, htag, &temp_db)) {
			pthread_mutex_unlock(&g_hash_lock);
			printf("[exmdb_provider]: no room in db hash table!\n");
			return NULL;
		}
		pdb = (DB_ITEM*)str_hash_query(g_hash_table, htag);
		pdb->reference = 0;
		time(&pdb->last_time);
		pthread_mutex_init(&pdb->lock, NULL);
		b_new = TRUE;
	} else if (pdb->reference > MAX_DB_WAITING_THREADS) {
		pthread_mutex_unlock(&g_hash_lock);	
		printf("[exmdb_provider]: too many threads waiting on %s\n", path);
		return NULL;
	}
	pdb->reference ++;
	pthread_mutex_unlock(&g_hash_lock);	
    clock_gettime(CLOCK_REALTIME, &timeout_tm);
    timeout_tm.tv_sec += DB_LOCK_TIMEOUT;
	if (0 != pthread_mutex_timedlock(&pdb->lock, &timeout_tm)) {
		pthread_mutex_lock(&g_hash_lock);
		pdb->reference --;
		pthread_mutex_unlock(&g_hash_lock);
		return NULL;
	}
	if (TRUE == b_new) {
		double_list_init(&pdb->dynamic_list);
		double_list_init(&pdb->tables.table_list);
		double_list_init(&pdb->nsub_list);
		double_list_init(&pdb->instance_list);
		pdb->tables.last_id = 0;
		pdb->tables.b_batch = FALSE;
		pdb->tables.psqlite = NULL;
		sprintf(db_path, "%s/exmdb/exchange.sqlite3", path);
		if (SQLITE_OK != sqlite3_open_v2(db_path,
			&pdb->psqlite, SQLITE_OPEN_READWRITE, NULL)) {
			pdb->psqlite = NULL;
		} else {
			sqlite3_exec(pdb->psqlite, "PRAGMA foreign_keys=ON",
				NULL, NULL, NULL);
			sqlite3_exec(pdb->psqlite, "PRAGMA journal_mode=OFF",
				NULL, NULL, NULL);
			if (FALSE == g_async) {
				sqlite3_exec(pdb->psqlite, "PRAGMA synchronous=OFF",
					NULL, NULL, NULL);
			} else {
				sqlite3_exec(pdb->psqlite, "PRAGMA synchronous=ON",
					NULL, NULL, NULL);
			}
			if (FALSE == g_wal) {
				sqlite3_exec(pdb->psqlite, "PRAGMA journal_mode=DELETE",
					NULL, NULL, NULL);
			} else {
				sqlite3_exec(pdb->psqlite, "PRAGMA journal_mode=WAL",
					NULL, NULL, NULL);
			}
			if (0 != g_mmap_size) {
				sprintf(sql_string, "PRAGMA mmap_size=%llu", g_mmap_size);
				sqlite3_exec(pdb->psqlite, sql_string, NULL, NULL, NULL);
			}
			if (TRUE == exmdb_server_check_private()) {
				db_engine_load_dynamic_list(pdb);
			}
		}
	}
	return pdb;
}

void db_engine_put_db(DB_ITEM *pdb)
{
	time(&pdb->last_time);
	pthread_mutex_unlock(&pdb->lock);
	pthread_mutex_lock(&g_hash_lock);
	pdb->reference --;
	pthread_mutex_unlock(&g_hash_lock);
}

BOOL db_engine_unload_db(const char *path)
{
	int i;
	DB_ITEM *pdb;
	char htag[256];
	DB_ITEM temp_db;
	
	swap_string(htag, path);
	for (i=0; i<20; i++) {
		pthread_mutex_lock(&g_hash_lock);
		pdb = (DB_ITEM*)str_hash_query(g_hash_table, htag);
		if (NULL == pdb) {
			memset(&temp_db, 0, sizeof(DB_ITEM));
			temp_db.last_time = time(NULL) + g_cache_interval - 10;
			str_hash_add(g_hash_table, htag, &temp_db);
			pthread_mutex_unlock(&g_hash_lock);
			return TRUE;
		}
		pdb->last_time = time(NULL) - g_cache_interval - 1;
		pthread_mutex_unlock(&g_hash_lock);
		sleep(1);
	}
	return FALSE;
}

static void db_engine_free_db(DB_ITEM *pdb)
{
	TABLE_NODE *ptable;
	DYNAMIC_NODE *pdynamic;
	DOUBLE_LIST_NODE *pnode;
	INSTANCE_NODE *pinstance;
	
	while (pnode=double_list_get_from_head(&pdb->instance_list)) {
		pinstance = (INSTANCE_NODE*)pnode->pdata;
		if (NULL != pinstance->username) {
			free(pinstance->username);
		}
		if (INSTANCE_TYPE_MESSAGE == pinstance->type) {
			message_content_free(pinstance->pcontent);
		} else {
			attachment_content_free(pinstance->pcontent);
		}
		free(pinstance);
	}
	double_list_free(&pdb->instance_list);
	while (pnode=double_list_get_from_head(&pdb->nsub_list)) {
		free(pnode->pdata);
	}
	double_list_free(&pdb->nsub_list);
	while (pnode=double_list_get_from_head(&pdb->dynamic_list)) {
		pdynamic = (DYNAMIC_NODE*)pnode->pdata;
		restriction_free(pdynamic->prestriction);
		free(pdynamic->folder_ids.pll);
		free(pdynamic);
	}
	double_list_free(&pdb->dynamic_list);
	while (pnode=double_list_get_from_head(&pdb->tables.table_list)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (NULL != ptable->remote_id) {
			free(ptable->remote_id);
		}
		if (NULL != ptable->prestriction) {
			restriction_free(ptable->prestriction);
		}
		if (NULL != ptable->psorts) {
			sortorder_set_free(ptable->psorts);
		}
		free(ptable);
	}
	double_list_free(&pdb->tables.table_list);
	if (NULL != pdb->tables.psqlite) {
		sqlite3_close(pdb->tables.psqlite);
		pdb->tables.psqlite = NULL;
	}
	pthread_mutex_destroy(&pdb->lock);
	pdb->last_time = 0;
	if (NULL != pdb->psqlite) {
		sqlite3_close(pdb->psqlite);
		pdb->psqlite = NULL;
	}
}

static void *scan_work_func(void *param)
{
	int count;
	DB_ITEM *pdb;
	char htag[256];
	time_t now_time;
	STR_HASH_ITER *iter;
	
	count = 0;
	while (FALSE == g_notify_stop) {
		sleep(1);
		if (count < 10) {
			count ++;
			continue;
		}
		count = 0;
		pthread_mutex_lock(&g_hash_lock);
		time(&now_time);
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pdb = (DB_ITEM*)str_hash_iter_get_value(iter, htag);
			if (0 == pdb->reference && NULL == pdb->psqlite) {
				db_engine_free_db(pdb);
				str_hash_iter_remove(iter);
				continue;
			}
			if (0 != pdb->reference || now_time - 
				pdb->last_time <= g_cache_interval) {
				continue;
			}
			db_engine_free_db(pdb);
			str_hash_iter_remove(iter);
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
	}
	pthread_mutex_lock(&g_hash_lock);
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pdb = (DB_ITEM*)str_hash_iter_get_value(iter, htag);
		db_engine_free_db(pdb);
		str_hash_iter_remove(iter);
	}
	str_hash_iter_free(iter);
	pthread_mutex_unlock(&g_hash_lock);
	pthread_exit(0);
}

static BOOL db_engine_search_folder(const char *dir,
	uint32_t cpid, uint64_t search_fid, uint64_t scope_fid,
	const RESTRICTION *prestriction)
{
	int i;
	int count;
	int sql_len;
	DB_ITEM *pdb;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	EID_ARRAY *pmessage_ids;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT is_search "
		"FROM folders WHERE folder_id=%llu", scope_fid);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return TRUE;
	}
	if (0 == sqlite3_column_int64(pstmt, 0)) {
		sql_len = sprintf(sql_string, "SELECT message_id FROM"
				" messages WHERE parent_fid=%llu", scope_fid);
	} else {
		sql_len = sprintf(sql_string, "SELECT message_id FROM"
			" search_result WHERE folder_id=%llu", scope_fid);
	}
	sqlite3_finalize(pstmt);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pmessage_ids = eid_array_init();
	if (NULL == pmessage_ids) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (FALSE == eid_array_append(pmessage_ids,
			sqlite3_column_int64(pstmt, 0))) {
			eid_array_free(pmessage_ids);
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sqlite3_finalize(pstmt);
	exmdb_server_build_environment(FALSE, TRUE, dir);
	for (i=0,count=0; i<pmessage_ids->count; i++,count++) {
		if (TRUE == g_notify_stop) {
			break;
		}
		if (200 == count) {
			db_engine_put_db(pdb);
			exmdb_server_free_environment();
			sleep(1);
			pdb = db_engine_get_db(dir);
			if (NULL == pdb) {
				eid_array_free(pmessage_ids);
				return FALSE;
			}
			if (NULL == pdb->psqlite) {
				db_engine_put_db(pdb);
				eid_array_free(pmessage_ids);
				return FALSE;
			}
			exmdb_server_build_environment(FALSE, TRUE, dir);
			count = 0;
		}
		if (TRUE == common_util_evaluate_message_restriction(
			pdb->psqlite, cpid, pmessage_ids->pids[i], prestriction)) {
			sprintf(sql_string, "REPLACE INTO search_result "
				"(folder_id, message_id) VALUES (%llu, %llu)",
				search_fid, pmessage_ids->pids[i]);
			if (SQLITE_OK == sqlite3_exec(pdb->psqlite,
				sql_string, NULL, NULL, NULL)) {
				db_engine_proc_dynmaic_event(pdb, cpid,
					DYNAMIC_EVENT_NEW_MESSAGE, search_fid,
					pmessage_ids->pids[i], 0);
			}
		}
	}
	db_engine_put_db(pdb);
	exmdb_server_free_environment();
	eid_array_free(pmessage_ids);
	return TRUE;
}

static BOOL db_engine_load_folder_decendant(const char *dir,
	BOOL b_recursive, uint64_t folder_id, EID_ARRAY *pfolder_ids)
{
	int sql_len;
	DB_ITEM *pdb;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT folder_id FROM "
				"folders WHERE parent_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (FALSE == eid_array_append(pfolder_ids,
			sqlite3_column_int64(pstmt, 0))) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

static void db_engine_free_populating_node(POPULATING_NODE *psearch)
{
	pthread_mutex_lock(&g_list_lock);
	double_list_remove(&g_populating_list1, &psearch->node);
	pthread_mutex_unlock(&g_list_lock);
	free(psearch->dir);
	restriction_free(psearch->prestriction);
	free(psearch->folder_ids.pll);
	free(psearch);
}

static ID_ARRAYS* db_engine_classify_id_array(DOUBLE_LIST *plist)
{
	int i, j;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	SUBLIST_NODE *psubnode;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	
	double_list_init(&tmp_list);
	while (pnode=double_list_get_from_head(plist)) {
		pidnode = (ID_NODE*)pnode->pdata;
		for (pnode1=double_list_get_head(&tmp_list); NULL!=pnode1;
			pnode1=double_list_get_after(&tmp_list, pnode1)) {
			psubnode = (SUBLIST_NODE*)pnode1->pdata;
			if ((NULL == psubnode->remote_id &&
				NULL == pidnode->remote_id) ||
				(NULL != psubnode->remote_id &&
				NULL != pidnode->remote_id &&
				0 == strcasecmp(psubnode->remote_id,
				pidnode->remote_id))) {
				break;
			}
		}
		if (NULL == pnode1) {
			psubnode = common_util_alloc(sizeof(SUBLIST_NODE));
			if (NULL == psubnode) {
				return NULL;
			}
			psubnode->node.pdata = psubnode;
			psubnode->remote_id = pidnode->remote_id;
			double_list_init(&psubnode->list);
			double_list_append_as_tail(&tmp_list, &psubnode->node);
		}
		double_list_append_as_tail(&psubnode->list, &pidnode->node);
	}
	parrays = common_util_alloc(sizeof(ID_ARRAYS));
	if (NULL == parrays) {
		return NULL;
	}
	parrays->count = double_list_get_nodes_num(&tmp_list);
	parrays->remote_ids = common_util_alloc(
				sizeof(char*)*parrays->count);
	if (NULL == parrays->remote_ids) {
		return NULL;
	}
	parrays->parray = common_util_alloc(
		sizeof(LONG_ARRAY)*parrays->count);
	if (NULL == parrays->parray) {
		return NULL;
	}
	i = 0;
	for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
		pnode=double_list_get_after(&tmp_list, pnode)) {
		psubnode = (SUBLIST_NODE*)pnode->pdata;
		parrays->remote_ids[i] = psubnode->remote_id;
		parrays->parray[i].count =
			double_list_get_nodes_num(&psubnode->list);
		parrays->parray[i].pl = common_util_alloc(
			sizeof(uint32_t)*parrays->parray[i].count);
		if (NULL == parrays->parray[i].pl) {
			return NULL;
		}
		j = 0;
		for (pnode1=double_list_get_head(&psubnode->list); NULL!=pnode1;
			pnode1=double_list_get_after(&psubnode->list, pnode1)) {
			pidnode = (ID_NODE*)pnode1->pdata;
			parrays->parray[i].pl[j] = pidnode->id;
			j ++;
		}
		i ++;
	}
	return parrays;
}

static void db_engine_notify_search_completion(
	DB_ITEM *pdb, uint64_t folder_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_SEARCH_COMPLETED *psearch_completed;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_SEARCHCOMPLETE)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_SEARCH_COMPLETED;
		psearch_completed = common_util_alloc(
			sizeof(DB_NOTIFY_SEARCH_COMPLETED));
		if (NULL == psearch_completed) {
			return;
		}
		datagram.db_notify.pdata = psearch_completed;
		psearch_completed->folder_id = folder_id;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
}

static void *thread_work_func(void *param)
{
	int i;
	DB_ITEM *pdb;
	int table_num;
	TABLE_NODE *ptable;
	uint32_t *ptable_ids;
	EID_ARRAY *pfolder_ids;
	DOUBLE_LIST_NODE *pnode;
	POPULATING_NODE *psearch;
	
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_cond_mutex);
		pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
		pthread_mutex_unlock(&g_cond_mutex);
NEXT_SEARCH:
		if (TRUE == g_notify_stop) {
			break;
		}
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_populating_list);
		if (NULL != pnode) {
			double_list_append_as_tail(&g_populating_list1, pnode);
		}
		pthread_mutex_unlock(&g_list_lock);
		if (NULL == pnode) {
			continue;
		}
		psearch = (POPULATING_NODE*)pnode->pdata;
		pfolder_ids = eid_array_init();
		if (NULL == pfolder_ids) {
			db_engine_free_populating_node(psearch);
			goto NEXT_SEARCH;	
		}
		for (i=0; i<psearch->folder_ids.count; i++) {
			if (FALSE == eid_array_append(pfolder_ids,
				psearch->folder_ids.pll[i])) {
				eid_array_free(pfolder_ids);
				db_engine_free_populating_node(psearch);
				goto NEXT_SEARCH;	
			}
			if (FALSE == psearch->b_recursive) {
				continue;
			}
			if (FALSE == db_engine_load_folder_decendant(
				psearch->dir, psearch->b_recursive,
				psearch->folder_ids.pll[i], pfolder_ids)) {
				eid_array_free(pfolder_ids);
				db_engine_free_populating_node(psearch);
				goto NEXT_SEARCH;
			}
		}
		for (i=0; i<pfolder_ids->count; i++) {
			if (TRUE == g_notify_stop) {
				break;
			}
			if (FALSE == db_engine_search_folder(
				psearch->dir, psearch->cpid, psearch->folder_id,
				pfolder_ids->pids[i], psearch->prestriction)) {
				break;	
			}
		}
		if (FALSE == g_notify_stop) {
			pdb = db_engine_get_db(psearch->dir);
			if (NULL != pdb) {
				if (NULL != pdb->psqlite) {
					exmdb_server_build_environment(
						FALSE, TRUE, psearch->dir);
					db_engine_notify_search_completion(
						pdb, psearch->folder_id);
					db_engine_notify_folder_modification(pdb,
						common_util_get_folder_parent_fid(
						pdb->psqlite, psearch->folder_id),
						psearch->folder_id);
					table_num = double_list_get_nodes_num(
								&pdb->tables.table_list);
					if (table_num > 0) {
						ptable_ids = common_util_alloc(
							sizeof(uint32_t)*(table_num));
						if (NULL != ptable_ids) {
							table_num = 0;
							for (pnode=double_list_get_head(
								&pdb->tables.table_list); NULL!=pnode;
								pnode=double_list_get_after(
								&pdb->tables.table_list, pnode)) {
								ptable = (TABLE_NODE*)pnode->pdata;
								if (TABLE_TYPE_CONTENT == ptable->type &&
									psearch->folder_id == ptable->folder_id) {
									ptable_ids[table_num] = ptable->table_id;
									table_num ++;
								}
							}
						}
					}
					db_engine_put_db(pdb);
					while (0 != table_num) {
						table_num --;
						exmdb_server_reload_content_table(
							psearch->dir, ptable_ids[table_num]);
					}
					exmdb_server_free_environment();
				} else {
					db_engine_put_db(pdb);
				}
			}
		}
		eid_array_free(pfolder_ids);
		db_engine_free_populating_node(psearch);
		goto NEXT_SEARCH;
	}
	pthread_exit(0);
}

void db_engine_init(int table_size, int cache_interval,
	BOOL b_async, BOOL b_wal, uint64_t mmap_size, int threads_num)
{
	g_notify_stop = TRUE;
	g_table_size = table_size;
	g_cache_interval = cache_interval;
	g_async = b_async;
	g_wal = b_wal;
	g_mmap_size = mmap_size;
	g_threads_num = threads_num;
	double_list_init(&g_populating_list);
	double_list_init(&g_populating_list1);
	pthread_mutex_init(&g_hash_lock, NULL);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);
}

int db_engine_run()
{
	int i;
	
	g_thread_ids = malloc(sizeof(pthread_t)*g_threads_num);
	if (NULL == g_thread_ids) {
		printf("[exmdb_provider]: fail to allocate"
			" populating thread id buffer\n");
		return -1;
	}
	if (SQLITE_OK != sqlite3_config(SQLITE_CONFIG_MULTITHREAD)) {
		printf("[exmdb_provider]: warning! fail to change"
			" to multiple thread mode for sqlite engine\n");
	}
	if (SQLITE_OK != sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 0)) {
		printf("[exmdb_provider]: warning! fail to close"
			" memory statistic for sqlite engine\n");
	}
	if (SQLITE_OK != sqlite3_initialize()) {
		printf("[exmdb_provider]: fail to initialize sqlite engine\n");
		return -2;
	}
	g_hash_table = str_hash_init(g_table_size, sizeof(DB_ITEM), NULL);
	if (NULL == g_hash_table) {
		printf("[exmdb_provider]: fail to init db hash table\n");
		return -3;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_tid, NULL, scan_work_func, NULL)) {
		printf("[exmdb_provider]: fail to create db scan thread\n");
		return -4;
	}
	for (i=0; i<g_threads_num; i++) {
		if (0 != pthread_create(g_thread_ids + i,
			NULL, thread_work_func, NULL)) {
			g_threads_num = i;
			printf("[exmdb_provider]: fail to "
				"create populating thread\n");
			return -5;
		}
	}
	return 0;
}

int db_engine_stop()
{
	int i;
	DOUBLE_LIST_NODE *pnode;
	POPULATING_NODE *psearch;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_tid, NULL);
		pthread_cond_broadcast(&g_waken_cond);
		for (i=0; i<g_threads_num; i++) {
			pthread_join(g_thread_ids[i], NULL);
		}
	}
	if (NULL != g_thread_ids) {
		free(g_thread_ids);
		g_thread_ids = NULL;
	}
	if (NULL != g_hash_table) {
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	while (pnode=double_list_get_from_head(&g_populating_list)) {
		psearch = (POPULATING_NODE*)pnode->pdata;
		restriction_free(psearch->prestriction);
		free(psearch->folder_ids.pll);
		free(psearch);
	}
	sqlite3_shutdown();
	return 0;
}

void db_engine_free()
{
	double_list_free(&g_populating_list);
	double_list_free(&g_populating_list1);
	pthread_mutex_destroy(&g_hash_lock);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);
}

BOOL db_engine_enqueue_populating_criteria(
	const char *dir, uint32_t cpid, uint64_t folder_id,
	BOOL b_recursive, const RESTRICTION *prestriction,
	const LONGLONG_ARRAY *pfolder_ids)
{
	POPULATING_NODE *psearch;
	
	psearch = malloc(sizeof(POPULATING_NODE));
	if (NULL == psearch) {
		return FALSE;
	}
	psearch->node.pdata = psearch;
	psearch->dir = strdup(dir);
	if (NULL == psearch->dir) {
		free(psearch);
		return FALSE;
	}
	psearch->prestriction = restriction_dup(prestriction);
	if (NULL == psearch->prestriction) {
		free(psearch->dir);
		free(psearch);
		return FALSE;
	}
	psearch->folder_ids.pll = malloc(
		sizeof(uint64_t)*pfolder_ids->count);
	if (NULL == psearch->folder_ids.pll) {
		restriction_free(psearch->prestriction);
		free(psearch->dir);
		free(psearch);
		return FALSE;
	}
	memcpy(psearch->folder_ids.pll, pfolder_ids->pll,
		sizeof(uint64_t)*pfolder_ids->count);
	psearch->cpid = cpid;
	psearch->folder_id = folder_id;
	psearch->b_recursive = b_recursive;
	psearch->folder_ids.count = pfolder_ids->count;
	pthread_mutex_lock(&g_list_lock);
	double_list_append_as_tail(&g_populating_list, &psearch->node);
	pthread_mutex_unlock(&g_list_lock);
	pthread_cond_signal(&g_waken_cond);
	return TRUE;
}

BOOL db_engine_check_populating(const char *dir, uint64_t folder_id)
{
	DOUBLE_LIST_NODE *pnode;
	POPULATING_NODE *psearch;
	
	pthread_mutex_lock(&g_list_lock);
	for (pnode=double_list_get_head(&g_populating_list); NULL!=pnode;
		pnode=double_list_get_after(&g_populating_list, pnode)) {
		psearch = (POPULATING_NODE*)pnode->pdata;
		if (0 == strcmp(psearch->dir, dir) &&
			folder_id == psearch->folder_id) {
			pthread_mutex_unlock(&g_list_lock);
			return TRUE;
		}
	}
	for (pnode=double_list_get_head(&g_populating_list1); NULL!=pnode;
		pnode=double_list_get_after(&g_populating_list1, pnode)) {
		psearch = (POPULATING_NODE*)pnode->pdata;
		if (0 == strcmp(psearch->dir, dir) &&
			folder_id == psearch->folder_id) {
			pthread_mutex_unlock(&g_list_lock);
			return TRUE;
		}
	}
	pthread_mutex_unlock(&g_list_lock);
	return FALSE;
}

void db_engine_update_dynamic(DB_ITEM *pdb, uint64_t folder_id,
	uint32_t search_flags, const RESTRICTION *prestriction,
	const LONGLONG_ARRAY *pfolder_ids)
{
	uint64_t *pll;
	DYNAMIC_NODE *pdynamic;
	DOUBLE_LIST_NODE *pnode;
	RESTRICTION *prestriction1;
	
	for (pnode=double_list_get_head(&pdb->dynamic_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->dynamic_list, pnode)) {
		pdynamic = (DYNAMIC_NODE*)pnode->pdata;
		if (pdynamic->folder_id == folder_id) {
			break;
		}
	}
	prestriction1 = restriction_dup(prestriction);
	if (NULL == prestriction1) {
		return;
	}
	pll = malloc(sizeof(uint64_t)*pfolder_ids->count);
	if (NULL == pll) {
		restriction_free(prestriction1);
		return;
	}
	memcpy(pll, pfolder_ids->pll, sizeof(uint64_t)*pfolder_ids->count);
	if (NULL == pnode) {
		pdynamic = malloc(sizeof(DYNAMIC_NODE));
		if (NULL == pdynamic) {
			free(pll);
			restriction_free(prestriction1);
			return;
		}
		pdynamic->node.pdata = pdynamic;
		pdynamic->folder_id = folder_id;
		double_list_append_as_tail(&pdb->dynamic_list, &pdynamic->node);
	} else {
		free(pdynamic->folder_ids.pll);
		restriction_free(pdynamic->prestriction);
	}
	pdynamic->search_flags = search_flags;
	pdynamic->prestriction = prestriction1;
	pdynamic->folder_ids.count = pfolder_ids->count;
	pdynamic->folder_ids.pll = pll;
}

void db_engine_delete_dynamic(DB_ITEM *pdb, uint64_t folder_id)
{
	DYNAMIC_NODE *pdynamic;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pdb->dynamic_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->dynamic_list, pnode)) {
		pdynamic = (DYNAMIC_NODE*)pnode->pdata;
		if (pdynamic->folder_id == folder_id) {
			double_list_remove(&pdb->dynamic_list, pnode);
			restriction_free(pdynamic->prestriction);
			free(pdynamic->folder_ids.pll);
			free(pdynamic);
			break;
		}
	}
}

void db_engine_proc_dynmaic_event(DB_ITEM *pdb, uint32_t cpid,
	int event_type, uint64_t id1, uint64_t id2, uint64_t id3)
{
	int i;
	int sql_len;
	BOOL b_exist;
	BOOL b_included;
	BOOL b_included1;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	uint32_t folder_type;
	DYNAMIC_NODE *pdynamic;
	DOUBLE_LIST_NODE *pnode;
	
	if (DYNAMIC_EVENT_MOVE_FOLDER == event_type) {
		if (FALSE == common_util_get_folder_type(
			pdb->psqlite, id3, &folder_type)) {
			debug_info("[db_engine]: fatal error in"
				" common_util_get_folder_type\n");
			return;
		}
	}
	for (pnode=double_list_get_head(&pdb->dynamic_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->dynamic_list, pnode)) {
		pdynamic = (DYNAMIC_NODE*)pnode->pdata;
		for (i=0; i<pdynamic->folder_ids.count; i++) {
			if (DYNAMIC_EVENT_MOVE_FOLDER == event_type) {
				if (pdynamic->search_flags & SEARCH_FLAG_RECURSIVE) {
					if (FALSE == common_util_check_decendant(pdb->psqlite,
						id1, pdynamic->folder_ids.pll[i], &b_included) ||
						FALSE == common_util_check_decendant(pdb->psqlite,
						id2, pdynamic->folder_ids.pll[i], &b_included1)) {
						debug_info("[db_engine]: fatal error in"
							" common_util_check_decendant\n");
						continue;
					}
					if (b_included == b_included1) {
						continue;
					}
					if (FOLDER_TYPE_SEARCH == folder_type) {
						sql_len = sprintf(sql_string, "SELECT message_id "
							"FROM search_result WHERE folder_id=%llu", id3);
					} else {
						sql_len = sprintf(sql_string, "SELECT message_id "
								"FROM messages WHERE parent_fid=%llu", id3);
					}
					if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
						sql_string, sql_len, &pstmt, NULL)) {
						continue;
					}
					while (SQLITE_ROW == sqlite3_step(pstmt)) {
						message_id = sqlite3_column_int64(pstmt, 0);
						if (FALSE == common_util_check_search_result(
							pdb->psqlite, pdynamic->folder_id,
							message_id, &b_exist)) {
							debug_info("[db_engine]: fail to check"
								" item in search_result\n");
							continue;
						}
						if (b_included != b_exist) {
							continue;
						}
						if (TRUE == b_included) {
							db_engine_notify_link_deletion(pdb,
								pdynamic->folder_id, message_id);
							db_engine_proc_dynmaic_event(pdb, cpid,
								DYNAMIC_EVENT_DELETE_MESSAGE,
								pdynamic->folder_id, message_id, 0);
							sprintf(sql_string, "DELETE FROM search_result "
								"WHERE folder_id=%llu AND message_id=%llu",
								pdynamic->folder_id, message_id);
							if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
								sql_string, NULL, NULL, NULL)) {
								debug_info("[db_engine]: fail to "
									"delete from search_result\n");
							}
						} else {
							if (FALSE ==
								common_util_evaluate_message_restriction(
								pdb->psqlite, cpid, message_id,
								pdynamic->prestriction)) {
								continue;
							}
							sprintf(sql_string, "INSERT INTO search_result "
								"(folder_id, message_id) VALUES (%llu, %llu)",
								pdynamic->folder_id, message_id);
							if (SQLITE_OK == sqlite3_exec(pdb->psqlite,
								sql_string, NULL, NULL, NULL)) {
								db_engine_notify_link_creation(pdb,
									pdynamic->folder_id, message_id);
								db_engine_proc_dynmaic_event(pdb,
									cpid, DYNAMIC_EVENT_NEW_MESSAGE,
									pdynamic->folder_id, message_id, 0);
							}
						}
					}
					sqlite3_finalize(pstmt);
				}
				continue;
			}
			if (pdynamic->search_flags & SEARCH_FLAG_RECURSIVE) {
				if (FALSE == common_util_check_decendant(pdb->psqlite,
					id1, pdynamic->folder_ids.pll[i], &b_included)) {
					debug_info("[db_engine]: fatal error in"
						" common_util_check_decendant\n");
					continue;
				}
				if (FALSE == b_included) {
					continue;
				}
			} else {
				if (id1 != pdynamic->folder_ids.pll[i]) {
					continue;
				}
			}
			switch (event_type) {
			case DYNAMIC_EVENT_NEW_MESSAGE:
				if (FALSE == common_util_check_search_result(
					pdb->psqlite, pdynamic->folder_id, id2, &b_exist)) {
					debug_info("[db_engine]: fail to check"
						" item in search_result\n");
					continue;
				}
				if (TRUE == b_exist) {
					continue;
				}
				if (FALSE == common_util_evaluate_message_restriction(
					pdb->psqlite, cpid, id2, pdynamic->prestriction)) {
					continue;
				}
				sprintf(sql_string, "INSERT INTO search_result "
					"(folder_id, message_id) VALUES (%llu, %llu)",
					pdynamic->folder_id, id2);
				if (SQLITE_OK == sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					db_engine_notify_link_creation(pdb,
						pdynamic->folder_id, id2);
					db_engine_proc_dynmaic_event(pdb,
						cpid, DYNAMIC_EVENT_NEW_MESSAGE,
						pdynamic->folder_id, id2, 0);
				} else {
					debug_info("[db_engine]: fail to "
						"insert into search_result\n");
				}
				break;
			case DYNAMIC_EVENT_DELETE_MESSAGE:
				if (FALSE == common_util_check_search_result(
					pdb->psqlite, pdynamic->folder_id, id2, &b_exist)) {
					debug_info("[db_engine]: fail to check"
						" item in search_result\n");
					continue;
				}
				if (FALSE == b_exist) {
					continue;
				}
				db_engine_notify_link_deletion(pdb,
					pdynamic->folder_id, id2);
				db_engine_proc_dynmaic_event(pdb, cpid,
					DYNAMIC_EVENT_DELETE_MESSAGE,
					pdynamic->folder_id, id2, 0);
				sprintf(sql_string, "DELETE FROM search_result "
					"WHERE folder_id=%llu AND message_id=%llu",
					pdynamic->folder_id, id2);
				if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
					sql_string, NULL, NULL, NULL)) {
					debug_info("[db_engine]: fail to "
						"delete from search_result\n");
				}
				break;
			case DYNAMIC_EVENT_MODIFY_MESSAGE:
				if (FALSE == common_util_check_search_result(
					pdb->psqlite, pdynamic->folder_id, id2, &b_exist)) {
					debug_info("[db_engine]: fail to check"
						" item in search_result\n");
					continue;
				}
				if (TRUE == common_util_evaluate_message_restriction(
					pdb->psqlite, cpid, id2, pdynamic->prestriction)) {
					if (TRUE == b_exist) {
						db_engine_notify_content_table_modify_row(
							pdb, pdynamic->folder_id, id2);
						db_engine_notify_folder_modification(pdb,
							common_util_get_folder_parent_fid(
							pdb->psqlite, pdynamic->folder_id),
							pdynamic->folder_id);
						continue;
					}
					sprintf(sql_string, "INSERT INTO search_result "
						"(folder_id, message_id) VALUES (%llu, %llu)",
						pdynamic->folder_id, id2);
					if (SQLITE_OK == sqlite3_exec(pdb->psqlite,
						sql_string, NULL, NULL, NULL)) {
						db_engine_notify_link_creation(pdb,
							pdynamic->folder_id, id2);
						db_engine_proc_dynmaic_event(pdb,
							cpid, DYNAMIC_EVENT_NEW_MESSAGE,
							pdynamic->folder_id, id2, 0);
					} else {
						debug_info("[db_engine]: fail to "
							"insert into search_result\n");
					}
				} else {
					if (FALSE == b_exist) {
						continue;
					}
					db_engine_notify_link_deletion(pdb,
						pdynamic->folder_id, id2);
					db_engine_proc_dynmaic_event(pdb, cpid,
						DYNAMIC_EVENT_DELETE_MESSAGE,
						pdynamic->folder_id, id2, 0);
					sprintf(sql_string, "DELETE FROM search_result "
						"WHERE folder_id=%llu AND message_id=%llu",
						pdynamic->folder_id, id2);
					if (SQLITE_OK != sqlite3_exec(pdb->psqlite,
						sql_string, NULL, NULL, NULL)) {
						debug_info("[db_engine]: fail to "
							"delete from search_result\n");
					}
				}
				break;
			}
		}
	}
}

static int db_engine_compare_propval(
	uint16_t proptype, void *pvalue1, void *pvalue2)
{
	if (NULL == pvalue1 && NULL == pvalue2) {
		return 0;
	}
	if (NULL == pvalue1 && NULL != pvalue2) {
		return -1;
	}
	if (NULL != pvalue1 && NULL == pvalue2) {
		return 1;
	}
	switch (proptype) {
	case PROPVAL_TYPE_SHORT:
		if (*(uint16_t*)pvalue1 > *(uint16_t*)pvalue2) {
			return 1;
		} else if (*(uint16_t*)pvalue1 < *(uint16_t*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_LONG:
	case PROPVAL_TYPE_ERROR:
		if (*(uint32_t*)pvalue1 > *(uint32_t*)pvalue2) {
			return 1;
		} else if (*(uint32_t*)pvalue1 < *(uint32_t*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_BYTE:
		if (*(uint8_t*)pvalue1 > *(uint8_t*)pvalue2) {
			return 1;
		} else if (*(uint8_t*)pvalue1 < *(uint8_t*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_CURRENCY:
	case PROPVAL_TYPE_LONGLONG:
	case PROPVAL_TYPE_FILETIME:
		if (*(uint64_t*)pvalue1 > *(uint64_t*)pvalue2) {
			return 1;
		} else if (*(uint64_t*)pvalue1 < *(uint64_t*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_FLOAT:
		if (*(float*)pvalue1 > *(float*)pvalue2) {
			return 1;
		} else if (*(float*)pvalue1 < *(float*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_DOUBLE:
	case PROPVAL_TYPE_FLOATINGTIME:
		if (*(double*)pvalue1 > *(double*)pvalue2) {
			return 1;
		} else if (*(double*)pvalue1 < *(double*)pvalue2) {
			return -1;
		}
		return 0;
	case PROPVAL_TYPE_STRING:
	case PROPVAL_TYPE_WSTRING:
		return strcasecmp(pvalue1, pvalue2);
	case PROPVAL_TYPE_GUID:
		return guid_compare(pvalue1, pvalue2);
	case PROPVAL_TYPE_BINARY:
		if (0 == ((BINARY*)pvalue1)->cb &&
			0 != ((BINARY*)pvalue2)->cb) {
			return -1;
		} else if (0 != ((BINARY*)pvalue1)->cb
			&& 0 == ((BINARY*)pvalue2)->cb) {
			return 1;
		} else if (0 == ((BINARY*)pvalue1)->cb
			&& 0 == ((BINARY*)pvalue2)->cb) {
			return 0;	
		}
		if (((BINARY*)pvalue1)->cb >
			((BINARY*)pvalue2)->cb) {
			return 	memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue2)->cb);
		} else {
			return memcmp(((BINARY*)pvalue1)->pb,
						((BINARY*)pvalue2)->pb,
						((BINARY*)pvalue1)->cb);
		}
	}
	return 0;
}

static BOOL db_engine_insert_categories(sqlite3 *psqlite,
	int depth, uint64_t parent_id, uint64_t after_row_id,
	uint64_t before_row_id, SORTORDER_SET *psorts,
	TAGGED_PROPVAL *ppropvals, sqlite3_stmt *pstmt_insert,
	sqlite3_stmt *pstmt_update, uint32_t *pheader_id,
	DOUBLE_LIST *pnotify_list, uint64_t *plast_row_id)
{
	int i;
	uint16_t type;
	uint64_t row_id;
	uint64_t prev_id;
	uint64_t inst_id;
	ROWINFO_NODE *prnode;
	
	if (0 != before_row_id) {
		sqlite3_bind_null(pstmt_update, 1);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_update)) {
			return FALSE;
		}
		sqlite3_reset(pstmt_update);
	}
	for (i=depth; i<psorts->ccategories; i++) {
		(*pheader_id) ++;
		inst_id = *pheader_id | 0x100000000000000ULL;
		sqlite3_bind_int64(pstmt_insert, 1, inst_id);
		sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_HEADER);
		if (i < psorts->cexpanded) {
			sqlite3_bind_int64(pstmt_insert, 3, 1);
		} else {
			sqlite3_bind_int64(pstmt_insert, 3, 0);
		}
		sqlite3_bind_int64(pstmt_insert, 4, parent_id);
		sqlite3_bind_int64(pstmt_insert, 5, i);
		sqlite3_bind_int64(pstmt_insert, 6, 0);
		sqlite3_bind_int64(pstmt_insert, 7, 0);
		sqlite3_bind_int64(pstmt_insert, 8, 0);
		if (0x3000 == (psorts->psort[i].type & 0x3000)) {
			type = psorts->psort[i].type & (~0x3000);
		} else {
			type = psorts->psort[i].type;
		}
		if (NULL == ppropvals[i].pvalue) {
			sqlite3_bind_null(pstmt_insert, 9);
		} else {
			if (FALSE == common_util_bind_sqlite_statement(
				pstmt_insert, 9, type, ppropvals[i].pvalue)) {
				return FALSE;	
			}
		}
		sqlite3_bind_null(pstmt_insert, 10);
		if (i == depth && 0 != after_row_id) {
			sqlite3_bind_int64(pstmt_insert, 11, after_row_id);
		} else {
			sqlite3_bind_int64(pstmt_insert, 11, (-1)*parent_id);
		}
		if (SQLITE_DONE != sqlite3_step(pstmt_insert)) {
			return FALSE;
		}
		sqlite3_reset(pstmt_insert);
		prnode = common_util_alloc(sizeof(ROWINFO_NODE));
		if (NULL == prnode) {
			return FALSE;
		}
		row_id = sqlite3_last_insert_rowid(psqlite);
		prnode->node.pdata = prnode;
		prnode->b_added = TRUE;
		prnode->row_id = row_id;
		double_list_append_as_tail(pnotify_list, &prnode->node);
		if (i == depth) {
			prev_id = row_id;
		}
		parent_id = row_id;
	}
	if (0 != before_row_id) {
		sqlite3_bind_int64(pstmt_update, 1, prev_id);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_update)) {
			return FALSE;
		}
		sqlite3_reset(pstmt_update);
	}
	*plast_row_id = row_id;
	return TRUE;
}

static BOOL db_engine_insert_message(sqlite3 *psqlite,
	uint64_t message_id, BOOL b_read, int depth,
	uint32_t inst_num, uint16_t type, void *pvalue,
	uint64_t parent_id, uint64_t after_row_id,
	uint64_t before_row_id, sqlite3_stmt *pstmt_insert,
	sqlite3_stmt *pstmt_update, DOUBLE_LIST *pnotify_list,
	uint64_t *plast_row_id)
{
	uint64_t row_id;
	ROWINFO_NODE *prnode;
	
	if (0 != before_row_id) {
		sqlite3_bind_null(pstmt_update, 1);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_update)) {
			return FALSE;
		}
		sqlite3_reset(pstmt_update);
	}
	sqlite3_bind_int64(pstmt_insert, 1, message_id);
	sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_MESSAGE);
	sqlite3_bind_null(pstmt_insert, 3);
	sqlite3_bind_int64(pstmt_insert, 4, parent_id);
	sqlite3_bind_int64(pstmt_insert, 5, depth);
	sqlite3_bind_null(pstmt_insert, 6);
	sqlite3_bind_null(pstmt_insert, 7);
	sqlite3_bind_int64(pstmt_insert, 8, inst_num);
	if (NULL == pvalue) {
		sqlite3_bind_null(pstmt_insert, 9);
	} else {
		if (FALSE == common_util_bind_sqlite_statement(
			pstmt_insert, 9, type, pvalue)) {
			return FALSE;
		}
	}
	if (FALSE == b_read) {
		sqlite3_bind_int64(pstmt_insert, 10, 0);
	} else {
		sqlite3_bind_int64(pstmt_insert, 10, 1);
	}
	if (0 == after_row_id) {
		sqlite3_bind_int64(pstmt_insert, 11, (-1)*parent_id);
	} else {
		sqlite3_bind_int64(pstmt_insert, 11, after_row_id);
	}
	if (SQLITE_DONE != sqlite3_step(pstmt_insert)) {
		return FALSE;
	}
	row_id = sqlite3_last_insert_rowid(psqlite);
	if (0 != before_row_id) {
		sqlite3_bind_int64(pstmt_update, 1, row_id);
		sqlite3_bind_int64(pstmt_update, 2, before_row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_update)) {
			return FALSE;
		}
		sqlite3_reset(pstmt_update);
	}
	sqlite3_reset(pstmt_insert);
	prnode = common_util_alloc(sizeof(ROWINFO_NODE));
	if (NULL == prnode) {
		return FALSE;
	}
	prnode->node.pdata = prnode;
	prnode->b_added = TRUE;
	prnode->row_id = row_id;
	double_list_append_as_tail(pnotify_list, &prnode->node);
	*plast_row_id = row_id;
	return TRUE;
}

static void db_engine_append_rowinfo_node(
	DOUBLE_LIST *pnotify_list, uint64_t row_id)
{
	ROWINFO_NODE *prnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		prnode = (ROWINFO_NODE*)pnode->pdata;
		if (row_id == prnode->row_id) {
			return;
		}
	}
	prnode = common_util_alloc(sizeof(ROWINFO_NODE));
	if (NULL != prnode) {
		prnode->node.pdata = prnode;
		prnode->b_added = FALSE;
		prnode->row_id = row_id;
		double_list_append_as_tail(pnotify_list, &prnode->node);
	}
}

static BOOL db_engine_check_new_header(
	DOUBLE_LIST *pnotify_list, uint64_t row_id)
{
	ROWINFO_NODE *prnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(pnotify_list); NULL!=pnode;
		pnode=double_list_get_after(pnotify_list, pnode)) {
		prnode = (ROWINFO_NODE*)pnode->pdata;
		if (row_id == prnode->row_id && TRUE == prnode->b_added) {
			return TRUE;
		}
	}
	return FALSE;
}

static void db_engine_notify_content_table_add_row(
	DB_ITEM *pdb, uint64_t folder_id, uint64_t message_id)
{
	int i, j;
	int result;
	BOOL b_fai;
	int sql_len;
	BOOL b_read;
	BOOL b_break;
	void *pvalue;
	uint32_t idx;
	uint16_t type;
	BOOL b_resorted;
	void *pmultival;
	int multi_index;
	int64_t prev_id;
	uint64_t row_id;
	int64_t prev_id1;
	uint64_t row_id1;
	uint64_t inst_id;
	uint64_t inst_id1;
	uint32_t inst_num;
	uint32_t multi_num;
	uint8_t table_sort;
	uint64_t parent_id;
	TABLE_NODE *ptable;
	uint8_t *pread_byte;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	sqlite3_stmt *pstmt4;
	char sql_string[1024];
	uint64_t inst_folder_id;
	DOUBLE_LIST notify_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_DATAGRAM datagram1;
	TAGGED_PROPVAL propvals[MAXIMUM_SORT_COUNT];
	DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *padded_row;
	DB_NOTIFY_CONTENT_TABLE_ROW_ADDED *padded_row1;
	
	pstmt = NULL;
	pstmt1 = NULL;
	pstmt2 = NULL;
	pstmt3 = NULL;
	pstmt4 = NULL;
	padded_row = NULL;
	pread_byte = NULL;
	if (FALSE == common_util_get_property(MESSAGE_PROPERTIES_TABLE,
		message_id, 0, pdb->psqlite, PROP_TAG_ASSOCIATED, &pvalue)) {
		return;	
	}
	if (NULL != pvalue && 0 != *(uint8_t*)pvalue) {
		b_fai = TRUE;
	} else {
		b_fai = FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_CONTENT != ptable->type ||
			folder_id != ptable->folder_id) {
			continue;
		}
		if (ptable->table_flags & TABLE_FLAG_ASSOCIATED) {
			if (FALSE == b_fai) {
				continue;
			}
		} else {
			if (TRUE == b_fai) {
				continue;
			}
		}
		if (TRUE == pdb->tables.b_batch && TRUE == ptable->b_hint) {
			continue;
		}
		if (NULL != ptable->prestriction && FALSE ==
			common_util_evaluate_message_restriction(pdb->psqlite,
			ptable->cpid, message_id, ptable->prestriction)) {
			continue;
		}
		if (TRUE == pdb->tables.b_batch) {
			ptable->b_hint = TRUE;
			continue;
		}
		if (NULL == padded_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			padded_row = common_util_alloc(2*sizeof(
				DB_NOTIFY_CONTENT_TABLE_ROW_ADDED));
			if (NULL == padded_row) {
				return;
			}
			padded_row->row_folder_id = folder_id;
			padded_row->row_message_id = message_id;
			datagram.db_notify.pdata = padded_row;
			datagram1.dir = (char*)exmdb_server_get_dir();
			datagram1.b_table = TRUE;
			datagram1.id_array.count = 1;
			padded_row1 = padded_row + 1;
			padded_row1->row_folder_id = folder_id;
			padded_row1->row_instance = 0;
			datagram1.db_notify.pdata = padded_row1;
			if (FALSE == common_util_begin_message_optimize(
				pdb->psqlite)) {
				return;
			}
		}
		if (NULL == ptable->psorts) {
			sql_len = sprintf(sql_string, "SELECT "
				"count(*) FROM t%u", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				pstmt = NULL;
				continue;
			}
			idx = sqlite3_column_int64(pstmt, 0);
			sqlite3_finalize(pstmt);
			pstmt = NULL;
			if (0 == idx) {
				row_id = 0;
				inst_id = 0;
				sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id,"
					" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
					"%u, 0, 0, 1)", ptable->table_id, message_id,
					CONTENT_ROW_MESSAGE);
			} else {
				sql_len = sprintf(sql_string, "SELECT row_id, inst_id "
						"FROM t%u WHERE idx=%u", ptable->table_id, idx);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt, NULL)) {
					continue;
				}
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					sqlite3_finalize(pstmt);
					pstmt = NULL;
					continue;
				}
				row_id = sqlite3_column_int64(pstmt, 0);
				inst_id = sqlite3_column_int64(pstmt, 1);
				sqlite3_finalize(pstmt);
				pstmt = NULL;
				sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id, "
					"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
					" %u, 0, 0, %u)", ptable->table_id, message_id, row_id,
					CONTENT_ROW_MESSAGE, idx + 1);
			}
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			padded_row->row_instance = 0;
			padded_row->after_row_id = inst_id;
			padded_row->after_instance = 0;
			if (0 == padded_row->after_row_id) {
				padded_row->after_folder_id = 0;
			} else {
				if (FALSE == common_util_get_message_parent_folder(
					pdb->psqlite, padded_row->after_row_id,
					&padded_row->after_folder_id)) {
					continue;
				}
			}
			datagram.id_array.pl = &ptable->table_id;
			if (FALSE == ptable->b_search) {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED;
			} else {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_ADDED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram);
		} else if (0 == ptable->psorts->ccategories) {
			for (i=0; i<ptable->psorts->count; i++) {
				propvals[i].proptag = ptable->psorts->psort[i].propid;
				propvals[i].proptag <<= 16;
				propvals[i].proptag |= ptable->psorts->psort[i].type;
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					ptable->cpid, pdb->psqlite, propvals[i].proptag,
					&propvals[i].pvalue)) {
					goto ADD_CONTENT_ROW_FAIL;
				}
			}
			sql_len = sprintf(sql_string, "SELECT row_id, inst_id,"
				" idx FROM t%u ORDER BY idx ASC", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			idx = 0;
			row_id = 0;
			row_id1 = 0;
			inst_id = 0;
			inst_id1 = 0;
			b_break = FALSE;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				row_id = row_id1;
				inst_id = inst_id1;
				row_id1 = sqlite3_column_int64(pstmt, 0);
				inst_id1 = sqlite3_column_int64(pstmt, 1);
				idx = sqlite3_column_int64(pstmt, 2);
				for (i=0; i<ptable->psorts->count; i++) {
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, inst_id1,
						ptable->cpid, pdb->psqlite,
						propvals[i].proptag, &pvalue)) {
						goto ADD_CONTENT_ROW_FAIL;
					}
					result = db_engine_compare_propval(
							ptable->psorts->psort[i].type,
							propvals[i].pvalue, pvalue);
					if (TABLE_SORT_ASCEND ==
						ptable->psorts->psort[i].table_sort) {
						if (result < 0) {
							b_break = TRUE;
							break;
						} else if (result > 0) {
							break;
						}
					} else {
						if (result > 0) {
							b_break = TRUE;
							break;	
						} else if (result < 0) {
							break;	
						}
					}
				}
				if (TRUE == b_break) {
					break;
				}
			}
			sqlite3_finalize(pstmt);
			pstmt = NULL;
			if (0 == idx) {
				sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id,"
					" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
					"%u, 0, 0, 1)", ptable->table_id, message_id,
					CONTENT_ROW_MESSAGE);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					continue;
				}
				padded_row->after_row_id = 0;
			} else if (FALSE == b_break) {
				sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id, "
					"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
					" %u, 0, 0, %u)", ptable->table_id, message_id,
					row_id1, CONTENT_ROW_MESSAGE, idx + 1);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					continue;
				}
				padded_row->after_row_id = inst_id1;
			} else {
				sqlite3_exec(pdb->tables.psqlite,
					"BEGIN TRANSACTION", NULL, NULL, NULL);
				sprintf(sql_string, "UPDATE t%u SET idx=-(idx+1)"
					" WHERE idx>=%u;UPDATE t%u SET idx=-idx WHERE"
					" idx<0", ptable->table_id, idx, ptable->table_id);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					continue;
				}
				sprintf(sql_string, "UPDATE t%u SET prev_id=NULL "
					"WHERE row_id=%llu", ptable->table_id, row_id1);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					continue;
				}
				if (0 == row_id) {
					sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id,"
						" row_type, depth, inst_num, idx) VALUES (%llu, 0, "
						"%u, 0, 0, 1)", ptable->table_id, message_id,
						CONTENT_ROW_MESSAGE);
				} else {
					sprintf(sql_string, "INSERT INTO t%u (inst_id, prev_id, "
						"row_type, depth, inst_num, idx) VALUES (%llu, %llu,"
						" %u, 0, 0, %u)", ptable->table_id, message_id,
						row_id, CONTENT_ROW_MESSAGE, idx);
				}
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					continue;
				}
				row_id = sqlite3_last_insert_rowid(pdb->tables.psqlite);
				sprintf(sql_string, "UPDATE t%u SET prev_id=%llu WHERE"
					" row_id=%llu", ptable->table_id, row_id, row_id1);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					continue;
				}
				sqlite3_exec(pdb->tables.psqlite,
					"COMMIT TRANSACTION", NULL, NULL, NULL);
				padded_row->after_row_id = inst_id;
			}
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			if (0 == padded_row->after_row_id) {
				padded_row->after_folder_id = 0;
			} else {
				if (FALSE == common_util_get_message_parent_folder(
					pdb->psqlite, padded_row->after_row_id,
					&padded_row->after_folder_id)) {
					continue;
				}
			}
			padded_row->row_instance = 0;
			padded_row->after_instance = 0;
			datagram.id_array.pl = &ptable->table_id;
			if (FALSE == ptable->b_search) {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED;
			} else {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_ADDED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram);
		} else {
			multi_index = -1;
			if (NULL == pread_byte) {
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					ptable->cpid, pdb->psqlite, PROP_TAG_READ,
					(void**)&pread_byte) || NULL == pread_byte) {
					goto ADD_CONTENT_ROW_FAIL;
				}
				if (0 == *pread_byte) {
					b_read = FALSE;
				} else {
					b_read = TRUE;
				}
			}
			for (i=0; i<ptable->psorts->count; i++) {
				propvals[i].proptag = ptable->psorts->psort[i].propid;
				propvals[i].proptag <<= 16;
				propvals[i].proptag |= ptable->psorts->psort[i].type;
				if (propvals[i].proptag == ptable->instance_tag) {
					multi_index = i;
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, message_id, ptable->cpid,
						pdb->psqlite, propvals[i].proptag & (~0x2000),
						&propvals[i].pvalue)) {
						goto ADD_CONTENT_ROW_FAIL;
					}
				} else {
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, message_id,
						ptable->cpid, pdb->psqlite, propvals[i].proptag,
						&propvals[i].pvalue)) {
						goto ADD_CONTENT_ROW_FAIL;
					}
				}
			}
			if (0 == ptable->instance_tag) {
				pmultival = NULL;
				multi_num = 1;
			} else {
				pmultival = propvals[multi_index].pvalue;
				if (NULL == pmultival) {
					multi_num = 1;
				} else {
					type = ptable->psorts->psort[
						multi_index].type & (~0x2000);
					switch (type) {
					case PROPVAL_TYPE_SHORT_ARRAY:
						multi_num = ((SHORT_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_LONG_ARRAY:
						multi_num = ((LONG_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_LONGLONG_ARRAY:
						multi_num = ((LONGLONG_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_STRING_ARRAY:
					case PROPVAL_TYPE_WSTRING_ARRAY:
						multi_num = ((STRING_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_GUID_ARRAY:
						multi_num = ((GUID_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_BINARY_ARRAY:
						multi_num = ((BINARY_ARRAY*)pmultival)->count;
						break;
					default:
						goto ADD_CONTENT_ROW_FAIL;
					}
					if (0 == multi_num) {
						pmultival = NULL;
						multi_num = 1;
						propvals[multi_index].pvalue = NULL;
					}
				}
			}
			sqlite3_exec(pdb->tables.psqlite,
				"BEGIN TRANSACTION", NULL, NULL, NULL);
			sql_len = sprintf(sql_string, "SELECT row_id, inst_id, "
				"value FROM t%u WHERE prev_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sql_len = sprintf(sql_string, "INSERT INTO t%u (inst_id, "
				"row_type, row_stat, parent_id, depth, count, unread,"
				" inst_num, value, extremum, prev_id) VALUES (?, ?, "
				"?, ?, ?, ?, ?, ?, ?, ?, ?)", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				pstmt = NULL;
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sql_len = sprintf(sql_string, "UPDATE t%u SET "
				"prev_id=? WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt2, NULL)) {
				sqlite3_finalize(pstmt);
				pstmt = NULL;
				sqlite3_finalize(pstmt1);
				pstmt1 = NULL;
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM"
				" t%u WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt3, NULL)) {
				sqlite3_finalize(pstmt);
				pstmt = NULL;
				sqlite3_finalize(pstmt1);
				pstmt1 = NULL;
				sqlite3_finalize(pstmt2);
				pstmt2 = NULL;
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			if (0 != ptable->extremum_tag) {
				sql_len = sprintf(sql_string, "UPDATE t%u SET "
					"extremum=? WHERE row_id=?", ptable->table_id);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt4, NULL)) {
					sqlite3_finalize(pstmt);
					pstmt = NULL;
					sqlite3_finalize(pstmt1);
					pstmt1 = NULL;
					sqlite3_finalize(pstmt2);
					pstmt2 = NULL;
					sqlite3_finalize(pstmt3);
					pstmt3 = NULL;
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					continue;
				}
			}
			b_resorted = FALSE;
			double_list_init(&notify_list);
			for (j=0; j<multi_num; j++) {
				if (NULL != pmultival) {
					inst_num = j + 1;
					type = ptable->psorts->psort[
						multi_index].type & (~0x2000);
					switch (type) {
					case PROPVAL_TYPE_SHORT_ARRAY:
						propvals[multi_index].pvalue =
							((SHORT_ARRAY*)pmultival)->ps + j;
						break;
					case PROPVAL_TYPE_LONG_ARRAY:
						propvals[multi_index].pvalue =
							((LONG_ARRAY*)pmultival)->pl + j;
						break;
					case PROPVAL_TYPE_LONGLONG_ARRAY:
						propvals[multi_index].pvalue =
							((LONGLONG_ARRAY*)pmultival)->pll + j;
						break;
					case PROPVAL_TYPE_STRING_ARRAY:
					case PROPVAL_TYPE_WSTRING_ARRAY:
						propvals[multi_index].pvalue =
							((STRING_ARRAY*)pmultival)->ppstr[j];
						break;
					case PROPVAL_TYPE_GUID_ARRAY:
						propvals[multi_index].pvalue =
							((GUID_ARRAY*)pmultival)->pguid + j;
						break;
					case PROPVAL_TYPE_BINARY_ARRAY:
						propvals[multi_index].pvalue =
							((BINARY_ARRAY*)pmultival)->pbin + j;
						break;
					}
				} else {
					inst_num = 0;
				}
				row_id = 0;
				row_id1 = 0;
				parent_id = 0;
				b_break = FALSE;
				for (i=0; i<ptable->psorts->ccategories; i++) {
					if (0x3000 == (ptable->psorts->psort[i].type & 0x3000)) {
						type = ptable->psorts->psort[i].type & (~0x3000);
					} else {
						type = ptable->psorts->psort[i].type;
					}
					sqlite3_reset(pstmt);
					sqlite3_bind_int64(pstmt, 1, (-1)*row_id1);
					while (SQLITE_ROW == sqlite3_step(pstmt)) {
						row_id = row_id1;
						row_id1 = sqlite3_column_int64(pstmt, 0);
						pvalue = common_util_column_sqlite_statement(
													pstmt, 2, type);
						result = db_engine_compare_propval(
							type, propvals[i].pvalue, pvalue);
						if (0 == result) {
							goto MATCH_SUB_HEADER;
						}
						if (0 == ptable->extremum_tag ||
							i != ptable->psorts->ccategories - 1) {
							if (TABLE_SORT_ASCEND ==
								ptable->psorts->psort[i].table_sort) {
								if (result < 0) {
									b_break = TRUE;
									break;
								}
							} else {
								if (result > 0) {
									b_break = TRUE;
									break;	
								}
							}
						}
						sqlite3_reset(pstmt);
						sqlite3_bind_int64(pstmt, 1, row_id1);
					}
					if (FALSE == b_break) {
						row_id = row_id1;
						row_id1 = 0;
						b_break = TRUE;
					}
					break;
MATCH_SUB_HEADER:
					parent_id = row_id1;
				}
				if (TRUE == b_break) {
					if (FALSE == db_engine_insert_categories(
						pdb->tables.psqlite, i, parent_id, row_id,
						row_id1, ptable->psorts, propvals, pstmt1, pstmt2,
						&ptable->header_id, &notify_list, &parent_id)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
				}
				row_id = 0;
				row_id1 = 0;
				if (ptable->psorts->count >
					ptable->psorts->ccategories) {
					b_break = FALSE;
				} else {
					b_break = TRUE;
				}
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, (-1)*parent_id);
				while (SQLITE_ROW == sqlite3_step(pstmt)) {
					row_id = row_id1;
					row_id1 = sqlite3_column_int64(pstmt, 0);
					inst_id = sqlite3_column_int64(pstmt, 1);
					for (i=ptable->psorts->ccategories;
						i<ptable->psorts->count; i++) {
						if (FALSE == common_util_get_property(
							MESSAGE_PROPERTIES_TABLE, inst_id,
							ptable->cpid, pdb->psqlite,
							propvals[i].proptag, &pvalue)) {
							sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
							goto ADD_CONTENT_ROW_FAIL;
						}
						result = db_engine_compare_propval(
								ptable->psorts->psort[i].type,
								propvals[i].pvalue, pvalue);
						if (TABLE_SORT_ASCEND ==
							ptable->psorts->psort[i].table_sort) {
							if (result < 0) {
								b_break = TRUE;
								break;
							} else if (result > 0) {
								break;
							}
						} else {
							if (result > 0) {
								b_break = TRUE;
								break;	
							} else if (result < 0) {
								break;	
							}
						}
					}
					if (TRUE == b_break) {
						break;
					}
					sqlite3_reset(pstmt);
					sqlite3_bind_int64(pstmt, 1, row_id1);
				}
				if (FALSE == b_break) {
					row_id = row_id1;
					row_id1 = 0;
				}
				if (0 == ptable->instance_tag) {
					type = 0;
					pvalue = NULL;
				} else {
					type = ptable->psorts->psort[
						multi_index].type & (~0x3000);
					pvalue = propvals[multi_index].pvalue;
				}
				if (FALSE == db_engine_insert_message(
					pdb->tables.psqlite, message_id, b_read,
					ptable->psorts->ccategories, inst_num,
					type, pvalue, parent_id, row_id, row_id1,
					pstmt1, pstmt2, &notify_list, &row_id)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
				parent_id = 0;
				while (TRUE) {
					sqlite3_bind_int64(pstmt3, 1, row_id);
					if (SQLITE_ROW != sqlite3_step(pstmt3)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
					row_id = sqlite3_column_int64(pstmt3, 6);
					sqlite3_reset(pstmt3);
					if (0 == row_id) {
						break;
					}
					if (0 == parent_id) {
						parent_id = row_id;
					}
					if (TRUE == b_read) {
						sprintf(sql_string, "UPDATE t%u SET count=count+1 "
							"WHERE row_id=%llu", ptable->table_id, row_id);
					} else {
						sprintf(sql_string, "UPDATE t%u SET count=count+1,"
							" unread=unread+1 WHERE row_id=%llu",
							ptable->table_id, row_id);
					}
					if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
						sql_string, NULL, NULL, NULL)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
					db_engine_append_rowinfo_node(&notify_list, row_id);
				}
				if (0 == ptable->extremum_tag) {
					continue;
				}
				row_id = parent_id;
				type = ptable->psorts->psort[
					ptable->psorts->ccategories].type;
				sqlite3_bind_int64(pstmt3, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt3)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
				parent_id = sqlite3_column_int64(pstmt3, 6);
				pvalue = common_util_column_sqlite_statement(
											pstmt3, 12, type);
				sqlite3_reset(pstmt3);
				result = db_engine_compare_propval(type, pvalue,
					propvals[ptable->psorts->ccategories].pvalue);
				table_sort = ptable->psorts->psort[
					ptable->psorts->ccategories].table_sort;
				if (TABLE_SORT_MAXIMUM_CATEGORY == table_sort) {
					if (result >= 0) {
						continue;
					}
				} else {
					if (NULL == pvalue && NULL != propvals[
						ptable->psorts->ccategories].pvalue &&
						TRUE == db_engine_check_new_header(
						&notify_list, row_id)) {
						/* extremum should be written */
					} else if (result <= 0) {
						continue;
					}
				}
				pvalue = propvals[ptable->psorts->ccategories].pvalue;
				if (NULL == pvalue) {
					sqlite3_bind_null(pstmt4, 1);
				} else {
					if (FALSE == common_util_bind_sqlite_statement(
						pstmt4, 1, type, pvalue)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
				}
				sqlite3_bind_int64(pstmt4, 2, row_id);
				if (SQLITE_DONE != sqlite3_step(pstmt4)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
				sqlite3_reset(pstmt4);
				table_sort = ptable->psorts->psort[
					ptable->psorts->ccategories - 1].table_sort;
				prev_id = (-1)*parent_id;
				row_id1 = 0;
				b_break = FALSE;
				sqlite3_reset(pstmt);
				sqlite3_bind_int64(pstmt, 1, prev_id);
				while (SQLITE_ROW == sqlite3_step(pstmt)) {
					if (sqlite3_column_int64(pstmt, 0) != row_id
						&& 0 != row_id1 && row_id != row_id1) {
						prev_id = row_id1;
					}
					row_id1 = sqlite3_column_int64(pstmt, 0);
					if (row_id1 != row_id) {
						pvalue = common_util_column_sqlite_statement(
													pstmt, 2, type);
						result = db_engine_compare_propval(
							type, pvalue, propvals[
							ptable->psorts->ccategories].pvalue);
						if (TABLE_SORT_ASCEND == table_sort) {
							if (result > 0) {
								b_break = TRUE;
								break;
							}
						} else {
							if (result < 0) {
								b_break = TRUE;
								break;	
							}
						}
					}
					sqlite3_reset(pstmt);
					sqlite3_bind_int64(pstmt, 1, row_id1);
				}
				if (row_id == row_id1) {
					continue;
				}
				if (FALSE == b_break) {
					prev_id = row_id1;
					row_id1 = 0;
				}
				sqlite3_bind_int64(pstmt3, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt3)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
				prev_id1 = sqlite3_column_int64(pstmt3, 2);
				sqlite3_reset(pstmt3);
				if (prev_id == prev_id1) {
					continue;
				}
				/* position within the list has been changed */
				if (FALSE == db_engine_check_new_header(
					&notify_list, row_id)) {
					b_resorted = TRUE;
				}
				if (0 != row_id1) {
					sqlite3_bind_null(pstmt2, 1);
					sqlite3_bind_int64(pstmt2, 2, row_id1);
					if (SQLITE_DONE != sqlite3_step(pstmt2)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
					sqlite3_reset(pstmt2);
				}
				sqlite3_bind_int64(pstmt2, 1, prev_id);
				sqlite3_bind_int64(pstmt2, 2, row_id);
				if (SQLITE_DONE != sqlite3_step(pstmt2)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
				sqlite3_reset(pstmt2);
				sprintf(sql_string, "UPDATE t%u SET prev_id=%lld"
						" WHERE prev_id=%lld", ptable->table_id,
						prev_id1, row_id);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;	
				}
				if (0 != row_id1) {
					sqlite3_bind_int64(pstmt2, 1, row_id);
					sqlite3_bind_int64(pstmt2, 2, row_id1);
					if (SQLITE_DONE != sqlite3_step(pstmt2)) {
						sqlite3_exec(pdb->tables.psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						goto ADD_CONTENT_ROW_FAIL;
					}
					sqlite3_reset(pstmt2);
				}
			}
			sqlite3_finalize(pstmt);
			pstmt = NULL;
			sqlite3_finalize(pstmt1);
			pstmt1 = NULL;
			sqlite3_finalize(pstmt2);
			pstmt2 = NULL;
			if (NULL != pstmt4) {
				sqlite3_finalize(pstmt4);
				pstmt4 = NULL;
			}
			sprintf(sql_string, "UPDATE t%u SET idx=NULL", ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				goto ADD_CONTENT_ROW_FAIL;
			}
			sql_len = sprintf(sql_string, "SELECT row_id, row_stat"
			" FROM t%u WHERE prev_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				goto ADD_CONTENT_ROW_FAIL;
			}
			sql_len = sprintf(sql_string, "UPDATE t%u SET"
				" idx=? WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				goto ADD_CONTENT_ROW_FAIL;
			}
			idx = 0;
			sqlite3_bind_int64(pstmt, 1, 0);
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (FALSE == common_util_indexing_sub_contents(
					ptable->psorts->ccategories, pstmt, pstmt1, &idx)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					goto ADD_CONTENT_ROW_FAIL;
				}
			}
			sqlite3_finalize(pstmt);
			pstmt = NULL;
			sqlite3_finalize(pstmt1);
			pstmt1 = NULL;
			sqlite3_exec(pdb->tables.psqlite,
				"COMMIT TRANSACTION", NULL, NULL, NULL);
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				sqlite3_finalize(pstmt3);
				pstmt3 = NULL;
				continue;
			}
			datagram.id_array.pl = &ptable->table_id;
			datagram1.id_array.pl = &ptable->table_id;
			if (TRUE == b_resorted) {
				if (FALSE == ptable->b_search) {
					datagram1.db_notify.type =
						DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED;
				} else {
					datagram1.db_notify.type =
						DB_NOTIFY_TYPE_SEARCH_TABLE_CHANGED;
				}
				notification_agent_backward_notify(
					ptable->remote_id, &datagram1);
			} else {
				sql_len = sprintf(sql_string, "SELECT * FROM"
						" t%u WHERE idx=?", ptable->table_id);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt, NULL)) {
					sqlite3_finalize(pstmt3);
					pstmt3 = NULL;
					continue;
				}
				while (pnode1=double_list_get_from_head(&notify_list)) {
					row_id = ((ROWINFO_NODE*)pnode1->pdata)->row_id;
					sqlite3_bind_int64(pstmt3, 1, row_id);
					if (SQLITE_ROW != sqlite3_step(pstmt3)) {
						sqlite3_reset(pstmt3);
						continue;
					}
					if (SQLITE_NULL == sqlite3_column_type(pstmt3, 1)) {
						sqlite3_reset(pstmt3);
						continue;
					}
					idx = sqlite3_column_int64(pstmt3, 1);
					if (1 == idx) {
						inst_id = 0;
						inst_num = 0;
						inst_folder_id = 0;
					} else {
						sqlite3_bind_int64(pstmt, 1, idx - 1);
						if (SQLITE_ROW != sqlite3_step(pstmt)) {
							sqlite3_reset(pstmt);
							sqlite3_reset(pstmt3);
							continue;
						}
						inst_id = sqlite3_column_int64(pstmt, 3);
						inst_num = sqlite3_column_int64(pstmt, 10);
						if (CONTENT_ROW_HEADER ==
							sqlite3_column_int64(pstmt, 4)) {
							inst_folder_id = folder_id;	
						} else {
							if (FALSE == common_util_get_message_parent_folder(
								pdb->psqlite, inst_id, &inst_folder_id)) {
								sqlite3_reset(pstmt);
								sqlite3_reset(pstmt3);
								continue;
							}
						}
						sqlite3_reset(pstmt);
					}
					if (TRUE == ((ROWINFO_NODE*)pnode1->pdata)->b_added) {
						if (CONTENT_ROW_HEADER ==
							sqlite3_column_int64(pstmt3, 4)) {
							padded_row1->row_message_id = 
								sqlite3_column_int64(pstmt3, 3);
							padded_row1->after_row_id = inst_id;
							padded_row1->after_folder_id = inst_folder_id;
							padded_row1->after_instance = inst_num;
							if (FALSE == ptable->b_search) {
								datagram1.db_notify.type =
									DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED;
							} else {
								datagram1.db_notify.type =
									DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_ADDED;
							}
							notification_agent_backward_notify(
								ptable->remote_id, &datagram1);
						} else {
							padded_row->row_instance =
								sqlite3_column_int64(pstmt3, 10);
							padded_row->after_row_id = inst_id;
							padded_row->after_folder_id = inst_folder_id;
							padded_row->after_instance = inst_num;
							if (FALSE == ptable->b_search) {
								datagram.db_notify.type =
									DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_ADDED;
							} else {
								datagram.db_notify.type =
									DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_ADDED;
							}
							notification_agent_backward_notify(
								ptable->remote_id, &datagram);
						}
					} else {
						padded_row1->row_message_id =
							sqlite3_column_int64(pstmt3, 3);
						padded_row1->after_row_id = inst_id;
						padded_row1->after_folder_id = inst_folder_id;
						padded_row1->after_instance = inst_num;
						if (FALSE == ptable->b_search) {
							datagram1.db_notify.type =
								DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED;
						} else {
							datagram1.db_notify.type =
								DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED;
						}
						notification_agent_backward_notify(
							ptable->remote_id, &datagram1);
					}
					sqlite3_reset(pstmt3);
				}
				sqlite3_finalize(pstmt);
				pstmt = NULL;
			}
			sqlite3_finalize(pstmt3);
			pstmt3 = NULL;
		}
	}
ADD_CONTENT_ROW_FAIL:
	if (NULL != padded_row) {
		common_util_end_message_optimize();
	}
	if (NULL != pstmt) {
		sqlite3_finalize(pstmt);
	}
	if (NULL != pstmt1) {
		sqlite3_finalize(pstmt1);
	}
	if (NULL != pstmt2) {
		sqlite3_finalize(pstmt2);
	}
	if (NULL != pstmt3) {
		sqlite3_finalize(pstmt3);
	}
	if (NULL != pstmt4) {
		sqlite3_finalize(pstmt4);
	}
}

void db_engine_transport_new_mail(DB_ITEM *pdb, uint64_t folder_id,
	uint64_t message_id, uint32_t message_flags, const char *pstr_class)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_NEW_MAIL *pnew_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (NOTIFICATION_TYPE_NEWMAIL
			&pnsub->notificaton_type)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_NEW_MAIL;
		pnew_mail = common_util_alloc(
			sizeof(DB_NOTIFY_NEW_MAIL));
		if (NULL == pnew_mail) {
			return;
		}
		datagram.db_notify.pdata = pnew_mail;
		pnew_mail->folder_id = folder_id;
		pnew_mail->message_id = message_id;
		pnew_mail->message_flags = message_flags;
		pnew_mail->pmessage_class = pstr_class;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
}
	

void db_engine_notify_new_mail(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id)
{
	int i;
	void *pvalue;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_NEW_MAIL *pnew_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (NOTIFICATION_TYPE_NEWMAIL
			&pnsub->notificaton_type)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_NEW_MAIL;
		pnew_mail = common_util_alloc(
			sizeof(DB_NOTIFY_NEW_MAIL));
		if (NULL == pnew_mail) {
			return;
		}
		datagram.db_notify.pdata = pnew_mail;
		pnew_mail->folder_id = folder_id;
		pnew_mail->message_id = message_id;
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id,
			0, pdb->psqlite, PROP_TAG_MESSAGEFLAGS,
			&pvalue) || NULL == pvalue) {
			return;
		}
		pnew_mail->message_flags = *(uint32_t*)pvalue;
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id,
			0, pdb->psqlite, PROP_TAG_MESSAGECLASS,
			&pvalue) || NULL == pvalue) {
			return;
		}
		pnew_mail->pmessage_class = pvalue;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_add_row(
		pdb, folder_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id);
}

void db_engine_notify_message_creation(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_MESSAGE_CREATED *pcreated_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTCREATED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_MESSAGE_CREATED;
		pcreated_mail = common_util_alloc(
			sizeof(DB_NOTIFY_MESSAGE_CREATED));
		if (NULL == pcreated_mail) {
			return;
		}
		datagram.db_notify.pdata = pcreated_mail;
		pcreated_mail->folder_id = folder_id;
		pcreated_mail->message_id = message_id;
		pcreated_mail->proptags.count = 0;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_add_row(
		pdb, folder_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id);
}

void db_engine_notify_link_creation(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t message_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	uint64_t folder_id;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_LINK_CREATED *plinked_mail;
	
	if (FALSE == common_util_get_message_parent_folder(
		pdb->psqlite, message_id, &folder_id)) {
		return;
	}
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTCREATED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_LINK_CREATED;
		plinked_mail = common_util_alloc(
			sizeof(DB_NOTIFY_LINK_CREATED));
		if (NULL == plinked_mail) {
			return;
		}
		datagram.db_notify.pdata = plinked_mail;
		plinked_mail->folder_id = folder_id;
		plinked_mail->message_id = message_id;
		plinked_mail->parent_id = parent_id;
		plinked_mail->proptags.count = 0;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_add_row(
		pdb, parent_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id);
}

static void db_engine_notify_hierarchy_table_add_row(
	DB_ITEM *pdb, uint64_t parent_id, uint64_t folder_id)
{
	int sql_len;
	uint32_t idx;
	uint32_t depth;
	BOOL b_included;
	TABLE_NODE *ptable;
	uint64_t folder_id1;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	const GUID *phandle_guid;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *padded_row;
	
	padded_row = NULL;
	pstmt = NULL;
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_HIERARCHY != ptable->type) {
			continue;
		}
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (folder_id == ptable->folder_id ||
				FALSE == common_util_check_decendant(
				pdb->psqlite, folder_id, ptable->folder_id,
				&b_included) || FALSE == b_included) {
				continue;
			}
		} else {
			if (parent_id != ptable->folder_id) {
				continue;
			}
		}
		if (NULL != ptable->prestriction &&
			FALSE == common_util_evaluate_folder_restriction(
			pdb->psqlite, folder_id, ptable->prestriction)) {
			continue;
		}
		if (NULL == padded_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED;
			padded_row = common_util_alloc(sizeof(
				DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED));
			if (NULL == padded_row) {
				if (NULL != pstmt) {
					sqlite3_finalize(pstmt);
				}
				return;
			}
			datagram.db_notify.pdata = padded_row;
		}
		if ((ptable->table_flags & TABLE_FLAG_DEPTH) &&
			ptable->folder_id != parent_id) {
			if (NULL == pstmt) {
				sql_len = sprintf(sql_string, "SELECT parent_id "
								"FROM folders WHERE folder_id=?");
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
					sql_string, sql_len, &pstmt, NULL)) {
					pstmt = NULL;
					continue;
				}
			}
			depth = 1;
			folder_id1 = parent_id;
			while (TRUE) {
				sqlite3_bind_int64(pstmt, 1, folder_id1);
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					depth = 0;
					break;
				}
				depth ++;
				folder_id1 = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
				if (folder_id1 == ptable->folder_id) {
					break;
				}
			}
			if (0 == depth) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT idx FROM t%u"
						" WHERE folder_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				continue;
			}
			idx = 0;
			folder_id1 = parent_id;
			while (TRUE) {
				sqlite3_bind_int64(pstmt1, 1, folder_id1);
				if (SQLITE_ROW == sqlite3_step(pstmt1)) {
					idx = sqlite3_column_int64(pstmt1, 0);
					break;
				}
				sqlite3_reset(pstmt1);
				sqlite3_bind_int64(pstmt, 1, folder_id1);
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					break;
				}
				folder_id1 = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
				if (folder_id1 == ptable->folder_id) {
					break;
				}
			}
			sqlite3_finalize(pstmt1);
			if (0 == idx) {
				goto APPEND_END_OF_TABLE;
			}
			sqlite3_exec(pdb->tables.psqlite,
				"BEGIN TRANSACTION", NULL, NULL, NULL);
			sprintf(sql_string, "UPDATE t%u SET idx=-(idx+1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sqlite3_exec(pdb->tables.psqlite,
				"COMMIT TRANSACTION", NULL, NULL, NULL);
			sprintf(sql_string, "INSERT INTO t%u (idx, "
				"folder_id, depth) VALUES (%u, %llu, %u)",
				ptable->table_id, idx + 1, folder_id, depth);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				phandle_guid = exmdb_server_get_handle();
				if (NULL != phandle_guid && 0 == guid_compare(
					phandle_guid, &ptable->handle_guid)) {
					continue;
				}
			}
			padded_row->after_folder_id = folder_id1;
		} else {
			depth = 1;
APPEND_END_OF_TABLE:
			sprintf(sql_string, "INSERT INTO t%u (folder_id,"
				" depth) VALUES (%llu, %u)", ptable->table_id,
				folder_id, depth);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				phandle_guid = exmdb_server_get_handle();
				if (NULL != phandle_guid && 0 == guid_compare(
					phandle_guid, &ptable->handle_guid)) {
					continue;
				}
			}
			idx = sqlite3_last_insert_rowid(pdb->tables.psqlite);
			if (1 == idx) {
				padded_row->after_folder_id = 0;
			} else {
				sql_len = sprintf(sql_string, "SELECT folder_id FROM "
					"t%u WHERE idx=%u", ptable->table_id, idx - 1);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt1, NULL)) {
					continue;
				}
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					sqlite3_finalize(pstmt1);
					continue;
				}
				padded_row->after_folder_id = sqlite3_column_int64(pstmt1, 0);
				sqlite3_finalize(pstmt1);
			}
		}
		datagram.id_array.pl = &ptable->table_id;
		padded_row->row_folder_id = folder_id;
		notification_agent_backward_notify(
			ptable->remote_id, &datagram);
	}
	if (NULL != pstmt) {
		sqlite3_finalize(pstmt);
	}
}

void db_engine_notify_folder_creation(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_FOLDER_CREATED *pcreated_folder;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTCREATED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == parent_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_FOLDER_CREATED;
		pcreated_folder = common_util_alloc(
			sizeof(DB_NOTIFY_FOLDER_CREATED));
		if (NULL == pcreated_folder) {
			return;
		}
		datagram.db_notify.pdata = pcreated_folder;
		pcreated_folder->folder_id = folder_id;
		pcreated_folder->parent_id = parent_id;
		pcreated_folder->proptags.count = 0;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_hierarchy_table_add_row(
		pdb, parent_id, folder_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id);
}

static void db_engine_update_prev_id(DOUBLE_LIST *plist,
	int64_t prev_id, uint64_t original_prev_id)
{
	ROWDEL_NODE *pdelnode;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pdelnode = (ROWDEL_NODE*)pnode->pdata;
		if (original_prev_id == pdelnode->prev_id) {
			pdelnode->prev_id = prev_id;
			break;
		}
	}
}

static void* db_engine_get_extremum_value(DB_ITEM *pdb,
	uint32_t cpid, uint32_t table_id, uint32_t extremum_tag,
	uint64_t parent_id, uint8_t table_sort)
{
	int result;
	int sql_len;
	BOOL b_first;
	void *pvalue;
	void *pvalue1;
	uint64_t message_id;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	
	sql_len = sprintf(sql_string, "SELECT inst_id FROM t%u "
				"WHERE parent_id=%llu", table_id, parent_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return NULL;
	}
	pvalue = NULL;
	b_first = FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		message_id = sqlite3_column_int64(pstmt, 0);
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, message_id,
			cpid, pdb->psqlite, extremum_tag, &pvalue1)) {
			continue;	
		}
		if (FALSE == b_first) {
			pvalue = pvalue1;
			b_first = TRUE;
			continue;
		}
		result = db_engine_compare_propval(
			extremum_tag & 0xFFFF, pvalue, pvalue1);
		if (TABLE_SORT_MAXIMUM_CATEGORY == table_sort) {
			if (result < 0) {
				pvalue = pvalue1;
			}
		} else {
			if (result > 0) {
				pvalue = pvalue1;
			}
		}
	}
	sqlite3_finalize(pstmt);
	return pvalue;
}

static void db_engine_notify_content_table_delete_row(
	DB_ITEM *pdb, uint64_t folder_id, uint64_t message_id)
{
	int i;
	int result;
	int sql_len;
	BOOL b_index;
	BOOL b_break;
	uint32_t idx;
	uint8_t type;
	void *pvalue;
	void *pvalue1;
	BOOL b_resorted;
	int64_t prev_id;
	uint64_t row_id;
	int64_t prev_id1;
	uint64_t row_id1;
	uint64_t inst_id;
	uint32_t inst_num;
	uint8_t table_sort;
	uint64_t parent_id;
	TABLE_NODE *ptable;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	sqlite3_stmt *pstmt4;
	sqlite3_stmt *pstmt5;
	DOUBLE_LIST tmp_list;
	ROWINFO_NODE *prnode;
	ROWDEL_NODE *pdelnode;
	char sql_string[1024];
	DOUBLE_LIST notify_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_DATAGRAM datagram1;
	DB_NOTIFY_CONTENT_TABLE_ROW_DELETED *pdeleted_row;
	DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *pmodified_row;
	
	pdeleted_row = NULL;
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_CONTENT != ptable->type ||
			folder_id != ptable->folder_id) {
			continue;
		}
		if (TRUE == pdb->tables.b_batch && TRUE == ptable->b_hint) {
			continue;
		}
		if (0 == ptable->instance_tag) {
			sql_len = sprintf(sql_string, "SELECT row_id "
				"FROM t%u WHERE inst_id=%llu AND inst_num=0",
				ptable->table_id, message_id);
		} else {
			sql_len = sprintf(sql_string, "SELECT row_id"
							" FROM t%u WHERE inst_id=%llu",
							ptable->table_id, message_id);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			continue;
		}
		sqlite3_finalize(pstmt);
		if (TRUE == pdb->tables.b_batch) {
			ptable->b_hint = TRUE;
			continue;
		}
		if (NULL == pdeleted_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			pdeleted_row = common_util_alloc(sizeof(
				DB_NOTIFY_CONTENT_TABLE_ROW_DELETED));
			if (NULL == pdeleted_row) {
				return;
			}
			datagram.db_notify.pdata = pdeleted_row;
			pmodified_row = common_util_alloc(sizeof(
				DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED));
			if (NULL == pmodified_row) {
				return;
			}
			datagram1.dir = (char*)exmdb_server_get_dir();
			datagram1.b_table = TRUE;
			datagram1.id_array.count = 1;
			pmodified_row->row_folder_id = folder_id;
			pmodified_row->row_instance = 0;
			pmodified_row->after_folder_id = folder_id;
			datagram1.db_notify.pdata = pmodified_row;
		}
		if (NULL == ptable->psorts || 0 == ptable->psorts->ccategories) {
			sql_len = sprintf(sql_string, "SELECT row_id, idx,"
					" prev_id FROM t%u WHERE inst_id=%llu AND "
					"inst_num=0", ptable->table_id, message_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			row_id = sqlite3_column_int64(pstmt, 0);
			idx = sqlite3_column_int64(pstmt, 1);
			prev_id = sqlite3_column_int64(pstmt, 2);
			sqlite3_finalize(pstmt);
			sqlite3_exec(pdb->tables.psqlite,
				"BEGIN TRANSACTION", NULL, NULL, NULL);
			sprintf(sql_string, "DELETE FROM t%u WHERE "
				"row_id=%llu", ptable->table_id, row_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sprintf(sql_string, "UPDATE t%u SET prev_id=%llu WHERE"
					" idx=%u", ptable->table_id, prev_id, idx + 1);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sprintf(sql_string, "UPDATE t%u SET idx=-(idx-1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sprintf(sql_string, "UPDATE sqlite_sequence SET seq="
				"(SELECT count(*) FROM t%u) WHERE name='t%u'",
				ptable->table_id, ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sqlite3_exec(pdb->tables.psqlite,
				"COMMIT TRANSACTION", NULL, NULL, NULL);
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			datagram.id_array.pl = &ptable->table_id;
			if (FALSE == common_util_get_message_parent_folder(
				pdb->psqlite, message_id, &pdeleted_row->row_folder_id)) {
				continue;
			}
			pdeleted_row->row_message_id = message_id;
			pdeleted_row->row_instance = 0;
			if (FALSE == ptable->b_search) {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED;
			} else {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_DELETED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram);
			continue;
		}
		b_index = FALSE;
		b_resorted = FALSE;
		double_list_init(&tmp_list);
		if (0 == ptable->instance_tag) {
			sql_len = sprintf(sql_string, "SELECT * FROM t%u"
						" WHERE inst_id=%llu AND inst_num=0",
						ptable->table_id, message_id);
		} else {
			sql_len = sprintf(sql_string, "SELECT * FROM t%u "
						"WHERE inst_id=%llu", ptable->table_id,
						message_id);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			pdelnode = common_util_alloc(sizeof(ROWDEL_NODE));
			if (NULL == pdelnode) {
				sqlite3_finalize(pstmt);
				return;
			}
			pdelnode->node.pdata = pdelnode;
			pdelnode->row_id = sqlite3_column_int64(pstmt, 0);
			/* will get 0 if SQLITE_NULL in 'idx' field */ 
			pdelnode->idx = sqlite3_column_int64(pstmt, 1);
			if (0 != pdelnode->idx) {
				b_index = TRUE;
			}
			pdelnode->prev_id = sqlite3_column_int64(pstmt, 2);
			pdelnode->inst_id = sqlite3_column_int64(pstmt, 3);
			pdelnode->parent_id = sqlite3_column_int64(pstmt, 6);
			pdelnode->depth = sqlite3_column_int64(pstmt, 7);
			pdelnode->inst_num = sqlite3_column_int64(pstmt, 10);
			if (0 == sqlite3_column_int64(pstmt, 12)) {
				pdelnode->b_read = FALSE;
			} else {
				pdelnode->b_read = TRUE;
			}
			double_list_append_as_tail(&tmp_list, &pdelnode->node);
		}
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->tables.psqlite,
			"BEGIN TRANSACTION", NULL, NULL, NULL);
		sql_len = sprintf(sql_string, "SELECT * FROM"
			" t%u WHERE row_id=?", ptable->table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;
		}
		sql_len = sprintf(sql_string, "DELETE FROM t%u "
					"WHERE row_id=?", ptable->table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			continue;
		}
		if (0 != ptable->extremum_tag) {
			sql_len = sprintf(sql_string, "UPDATE t%u SET "
				"extremum=? WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt2, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				continue;
			}
			sql_len = sprintf(sql_string, "UPDATE t%u SET "
				"prev_id=? WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt3, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT row_id, inst_id, "
				"extremum FROM t%u WHERE prev_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt4, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				sqlite3_finalize(pstmt3);
				continue;
			}
		}
		double_list_init(&notify_list);
		for (pnode1=double_list_get_head(&tmp_list); NULL!=pnode1;
			pnode1=double_list_get_after(&tmp_list, pnode1)) {
			pdelnode = (ROWDEL_NODE*)pnode1->pdata;
			if (0 != ptable->extremum_tag && pdelnode->depth
				== ptable->psorts->ccategories) {
				
			}
			/* delete the row first */
			sqlite3_bind_int64(pstmt1, 1, pdelnode->row_id);
			if (SQLITE_DONE != sqlite3_step(pstmt1)) {
				break;
			}
			sqlite3_reset(pstmt1);
			sprintf(sql_string, "UPDATE t%u SET prev_id=%lld"
				" WHERE prev_id=%lld", ptable->table_id,
				pdelnode->prev_id, pdelnode->row_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				break;
			}
			if (pdelnode->depth == ptable->psorts->ccategories
				&& 0 != ptable->instance_tag) {
				db_engine_update_prev_id(&tmp_list,
					pdelnode->prev_id, pdelnode->row_id);
			}
			if (0 == pdelnode->parent_id) {
				continue;
			}
			sqlite3_bind_int64(pstmt, 1, pdelnode->parent_id);
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				break;
			}
			if (1 == sqlite3_column_int64(pstmt, 8)) {
				pdelnode = common_util_alloc(sizeof(ROWDEL_NODE));
				if (NULL == pdelnode) {
					break;
				}
				pdelnode->node.pdata = pdelnode;
				pdelnode->row_id = sqlite3_column_int64(pstmt, 0);
				pdelnode->idx = sqlite3_column_int64(pstmt, 1);
				if (0 != pdelnode->idx) {
					b_index = TRUE;
				}
				pdelnode->prev_id = sqlite3_column_int64(pstmt, 2);
				pdelnode->inst_id = sqlite3_column_int64(pstmt, 3);
				pdelnode->parent_id = sqlite3_column_int64(pstmt, 6);
				pdelnode->depth = sqlite3_column_int64(pstmt, 7);
				pdelnode->inst_num = 0;
				pdelnode->b_read = ((ROWDEL_NODE*)pnode1->pdata)->b_read;
				double_list_append_as_tail(&tmp_list, &pdelnode->node);
				sqlite3_reset(pstmt);
				continue;
			}
			if (TRUE == pdelnode->b_read) {
				sprintf(sql_string, "UPDATE t%u SET count=count-1"
							" WHERE row_id=%llu", ptable->table_id,
							pdelnode->parent_id);
			} else {
				sprintf(sql_string, "UPDATE t%u SET count=count-1,"
							" unread=unread-1 WHERE row_id=%llu",
							ptable->table_id, pdelnode->parent_id);
			}
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				break;
			}
			prnode = common_util_alloc(sizeof(ROWINFO_NODE));
			if (NULL == prnode) {
				break;
			}
			prnode->node.pdata = prnode;
			prnode->b_added = FALSE;
			prnode->row_id = pdelnode->parent_id;
			double_list_append_as_tail(&notify_list, &prnode->node);
			if (0 == ptable->extremum_tag ||
				pdelnode->depth != ptable->psorts->ccategories) {
				sqlite3_reset(pstmt);
				continue;
			}
			/* compare the extremum value of header
				row and message property value */
			row_id = pdelnode->parent_id;
			type = ptable->psorts->psort[
				ptable->psorts->ccategories].type;
			parent_id = sqlite3_column_int64(pstmt, 6);
			pvalue = common_util_column_sqlite_statement(
										pstmt, 12, type);
			sqlite3_reset(pstmt);
			table_sort = ptable->psorts->psort[
				ptable->psorts->ccategories].table_sort;
			pvalue1 = db_engine_get_extremum_value(pdb, ptable->cpid,
							ptable->table_id, ptable->extremum_tag,
							pdelnode->parent_id, table_sort);
			if (0 == db_engine_compare_propval(
				type, pvalue, pvalue1)) {
				continue;
			}
			if (NULL == pvalue1) {
				sqlite3_bind_null(pstmt2, 1);
			} else {
				if (FALSE == common_util_bind_sqlite_statement(
					pstmt2, 1, type, pvalue1)) {
					break;
				}
			}
			sqlite3_bind_int64(pstmt2, 2, row_id);
			if (SQLITE_DONE != sqlite3_step(pstmt2)) {
				break;
			}
			sqlite3_reset(pstmt2);
			table_sort = ptable->psorts->psort[
				ptable->psorts->ccategories - 1].table_sort;
			prev_id = (-1)*parent_id;
			row_id1 = 0;
			b_break = FALSE;
			sqlite3_bind_int64(pstmt4, 1, prev_id);
			while (SQLITE_ROW == sqlite3_step(pstmt4)) {
				if (sqlite3_column_int64(pstmt4, 0) != row_id
					&& 0 != row_id1 && row_id != row_id1) {
					prev_id = row_id1;
				}
				row_id1 = sqlite3_column_int64(pstmt4, 0);
				if (row_id1 != row_id) {
					pvalue = common_util_column_sqlite_statement(
												pstmt4, 2, type);
					result = db_engine_compare_propval(
								type, pvalue, pvalue1);
					if (TABLE_SORT_ASCEND == table_sort) {
						if (result > 0) {
							b_break = TRUE;
							break;
						}
					} else {
						if (result < 0) {
							b_break = TRUE;
							break;	
						}
					}
				}
				sqlite3_reset(pstmt4);
				sqlite3_bind_int64(pstmt4, 1, row_id1);
			}
			sqlite3_reset(pstmt4);
			if (row_id == row_id1) {
				continue;
			}
			if (FALSE == b_break) {
				prev_id = row_id1;
				row_id1 = 0;
			}
			sqlite3_bind_int64(pstmt, 1, row_id);
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				break;
			}
			prev_id1 = sqlite3_column_int64(pstmt, 2);
			sqlite3_reset(pstmt);
			if (prev_id == prev_id1) {
				continue;
			}
			b_resorted = TRUE;
			/* position within the list has been changed */
			if (0 != row_id1) {
				sqlite3_bind_null(pstmt3, 1);
				sqlite3_bind_int64(pstmt3, 2, row_id1);
				if (SQLITE_DONE != sqlite3_step(pstmt3)) {
					break;
				}
				sqlite3_reset(pstmt3);
			}
			sqlite3_bind_int64(pstmt3, 1, prev_id);
			sqlite3_bind_int64(pstmt3, 2, row_id);
			if (SQLITE_DONE != sqlite3_step(pstmt3)) {
				break;
			}
			sqlite3_reset(pstmt3);
			sprintf(sql_string, "UPDATE t%u SET prev_id=%lld"
					" WHERE prev_id=%lld", ptable->table_id,
					prev_id1, row_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				break;
			}
			if (0 != row_id1) {
				sqlite3_bind_int64(pstmt3, 1, row_id);
				sqlite3_bind_int64(pstmt3, 2, row_id1);
				if (SQLITE_DONE != sqlite3_step(pstmt3)) {
					break;
				}
				sqlite3_reset(pstmt3);
			}
		}
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		if (0 != ptable->extremum_tag) {
			sqlite3_finalize(pstmt2);
			sqlite3_finalize(pstmt3);
			sqlite3_finalize(pstmt4);
		}
		if (NULL != pnode1) {
			sqlite3_exec(pdb->tables.psqlite,
				"ROLLBACK", NULL, NULL, NULL);
			continue;
		}
		if (TRUE == b_index) {
			sprintf(sql_string, "UPDATE t%u SET idx=NULL", ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT row_id, row_stat"
					" FROM t%u WHERE prev_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				continue;
			}
			sql_len = sprintf(sql_string, "UPDATE t%u SET"
				" idx=? WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_exec(pdb->tables.psqlite,
					"ROLLBACK", NULL, NULL, NULL);
				sqlite3_finalize(pstmt);
				continue;
			}
			idx = 0;
			sqlite3_bind_int64(pstmt, 1, 0);
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (FALSE == common_util_indexing_sub_contents(
					ptable->psorts->ccategories, pstmt, pstmt1, &idx)) {
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					continue;
				}
			}
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
		}
		sqlite3_exec(pdb->tables.psqlite,
			"COMMIT TRANSACTION", NULL, NULL, NULL);
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
			continue;
		}
		if (TRUE == b_resorted) {
			datagram1.id_array.pl = &ptable->table_id;
			if (FALSE == ptable->b_search) {
				datagram1.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED;
			} else {
				datagram1.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_CHANGED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram1);
		} else {
			for (pnode1=double_list_get_head(&tmp_list); NULL!=pnode1;
				pnode1=double_list_get_after(&tmp_list, pnode1)) {
				pdelnode = (ROWDEL_NODE*)pnode1->pdata;
				if (0 == pdelnode->idx) {
					continue;
				}
				datagram.id_array.pl = &ptable->table_id;
				if (FALSE == ptable->b_search) {
					pdeleted_row->row_folder_id = folder_id;
				} else {
					if (0 == (0xFF00000000000000ULL & pdelnode->inst_id)) {
						if (FALSE == common_util_get_message_parent_folder(
							pdb->psqlite, pdelnode->inst_id,
							&pdeleted_row->row_folder_id)) {
							continue;	
						}
					} else {
						pdeleted_row->row_folder_id = folder_id;
					}
				}
				pdeleted_row->row_message_id = pdelnode->inst_id;
				pdeleted_row->row_instance = pdelnode->inst_num;
				if (FALSE == ptable->b_search) {
					datagram.db_notify.type =
						DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_DELETED;
				} else {
					datagram.db_notify.type =
						DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_DELETED;
				}
				notification_agent_backward_notify(
					ptable->remote_id, &datagram);
			}
			if (0 == double_list_get_nodes_num(&notify_list)) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM"
					" t%u WHERE idx=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM "
					"t%u WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			while (pnode1=double_list_get_from_head(&notify_list)) {
				row_id = ((ROWINFO_NODE*)pnode1->pdata)->row_id;
				sqlite3_bind_int64(pstmt1, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					sqlite3_reset(pstmt1);
					continue;
				}
				if (SQLITE_NULL == sqlite3_column_type(pstmt1, 1)) {
					sqlite3_reset(pstmt1);
					continue;
				}
				idx = sqlite3_column_int64(pstmt1, 1);
				if (1 == idx) {
					inst_id = 0;
					inst_num = 0;
				} else {
					sqlite3_bind_int64(pstmt, 1, idx - 1);
					if (SQLITE_ROW != sqlite3_step(pstmt)) {
						sqlite3_reset(pstmt);
						sqlite3_reset(pstmt1);
						continue;
					}
					inst_id = sqlite3_column_int64(pstmt, 3);
					inst_num = sqlite3_column_int64(pstmt, 10);
					sqlite3_reset(pstmt);
				}
				datagram1.id_array.pl = &ptable->table_id;
				pmodified_row->row_message_id =
					sqlite3_column_int64(pstmt1, 3);
				pmodified_row->after_row_id = inst_id;
				pmodified_row->after_instance = inst_num;
				if (FALSE == ptable->b_search) {
					datagram1.db_notify.type =
						DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED;
				} else {
					datagram1.db_notify.type =
						DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED;
				}
				notification_agent_backward_notify(
					ptable->remote_id, &datagram1);
				sqlite3_reset(pstmt1);
			}
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
		}
	}
}

void db_engine_notify_message_deletion(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_MESSAGE_DELETED *pdeleted_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTDELETED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id &&
			message_id == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_MESSAGE_DELETED;
		pdeleted_mail = common_util_alloc(
			sizeof(DB_NOTIFY_MESSAGE_DELETED));
		if (NULL == pdeleted_mail) {
			return;
		}
		datagram.db_notify.pdata = pdeleted_mail;
		pdeleted_mail->folder_id = folder_id;
		pdeleted_mail->message_id = message_id;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_delete_row(
		pdb, folder_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id);
}

void db_engine_notify_link_deletion(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t message_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	uint64_t folder_id;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_LINK_DELETED *punlinked_mail;
	
	if (FALSE == common_util_get_message_parent_folder(
		pdb->psqlite, message_id, &folder_id)) {
		return;
	}
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTDELETED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id &&
			message_id == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_LINK_DELETED;
		punlinked_mail = common_util_alloc(
			sizeof(DB_NOTIFY_LINK_DELETED));
		if (NULL == punlinked_mail) {
			return;
		}
		datagram.db_notify.pdata = punlinked_mail;
		punlinked_mail->folder_id = folder_id;
		punlinked_mail->message_id = message_id;
		punlinked_mail->parent_id = parent_id;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_delete_row(
		pdb, parent_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id);
}

static void db_engine_notify_hierarchy_table_delete_row(
	DB_ITEM *pdb, uint64_t parent_id, uint64_t folder_id)
{
	int idx;
	int sql_len;
	BOOL b_included;
	TABLE_NODE *ptable;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	const GUID *phandle_guid;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *pdeleted_row;
	
	pdeleted_row = NULL;
	for (pnode=double_list_get_head(&pdb->tables.table_list);
		NULL!=pnode; pnode=double_list_get_after(
		&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_HIERARCHY != ptable->type) {
			continue;
		}
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (FALSE == common_util_check_decendant(
				pdb->psqlite, parent_id, ptable->folder_id,
				&b_included) || FALSE == b_included) {
				continue;
			}
		} else {
			if (parent_id != ptable->folder_id) {
				continue;
			}
		}
		sql_len = sprintf(sql_string, "SELECT idx FROM t%u "
			"WHERE folder_id=%llu", ptable->table_id, folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;	
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			continue;
		}
		idx = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		sprintf(sql_string, "DELETE FROM t%u WHERE "
			"folder_id=%llu", ptable->table_id, folder_id);
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			continue;
		}
		sprintf(sql_string, "UPDATE t%u SET idx=-(idx-1)"
			" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
			" idx<0", ptable->table_id, idx, ptable->table_id);
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			continue;
		}
		sprintf(sql_string, "UPDATE sqlite_sequence SET seq="
			"(SELECT count(*) FROM t%u) WHERE name='t%u'",
			ptable->table_id, ptable->table_id);
		sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL);
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
			continue;
		}
		if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
			phandle_guid = exmdb_server_get_handle();
			if (NULL != phandle_guid && 0 == guid_compare(
				phandle_guid, &ptable->handle_guid)) {
				continue;
			}
		}
		if (NULL == pdeleted_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED;
			pdeleted_row = common_util_alloc(sizeof(
				DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED));
			if (NULL == pdeleted_row) {
				return;
			}
			datagram.db_notify.pdata = pdeleted_row;
			pdeleted_row->row_folder_id = folder_id;
		}
		datagram.id_array.pl = &ptable->table_id;
		notification_agent_backward_notify(
			ptable->remote_id, &datagram);
	}
}	

void db_engine_notify_folder_deletion(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_FOLDER_DELETED *pdeleted_folder;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTDELETED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == parent_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_FOLDER_DELETED;
		pdeleted_folder = common_util_alloc(
			sizeof(DB_NOTIFY_FOLDER_DELETED));
		if (NULL == pdeleted_folder) {
			return;
		}
		datagram.db_notify.pdata = pdeleted_folder;
		pdeleted_folder->parent_id = parent_id;
		pdeleted_folder->folder_id = folder_id;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_hierarchy_table_delete_row(
		pdb, parent_id, folder_id);
}

static void db_engine_notify_content_table_modify_row(
	DB_ITEM *pdb, uint64_t folder_id, uint64_t message_id)
{
	int i, j;
	int result;
	int sql_len;
	int row_type;
	BOOL b_error;
	uint32_t idx;
	void *pvalue;
	void *pvalue1;
	uint16_t type;
	void *pmultival;
	int64_t prev_id;
	uint64_t row_id;
	uint64_t row_id1;
	uint64_t inst_id;
	uint64_t inst_id1;
	uint8_t read_byte;
	uint32_t inst_num;
	uint64_t parent_id;
	uint32_t multi_num;
	TABLE_NODE *ptable;
	TABLE_NODE *ptnode;
	int8_t unread_delta;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	ROWINFO_NODE *prnode;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST tmp_list1;
	char sql_string[1024];
	uint64_t row_folder_id;
	DOUBLE_LIST notify_list;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DB_NOTIFY_DATAGRAM datagram;
	TAGGED_PROPVAL propvals[MAXIMUM_SORT_COUNT];
	DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED *pmodified_row;
	
	pmodified_row = NULL;
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_CONTENT != ptable->type ||
			folder_id != ptable->folder_id) {
			continue;
		}
		if (0 == ptable->instance_tag) {
			sql_len = sprintf(sql_string, "SELECT count(*) "
				"FROM t%u WHERE inst_id=%llu AND inst_num=0",
				ptable->table_id, message_id);
		} else {
			sql_len = sprintf(sql_string, "SELECT count(*)"
							" FROM t%u WHERE inst_id=%llu",
							ptable->table_id, message_id);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt) ||
			0 == sqlite3_column_int64(pstmt, 0)) {
			sqlite3_finalize(pstmt);
			continue;
		}
		sqlite3_finalize(pstmt);
		if (NULL == pmodified_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			pmodified_row = common_util_alloc(sizeof(
				DB_NOTIFY_CONTENT_TABLE_ROW_MODIFIED));
			if (NULL == pmodified_row) {
				return;
			}
			datagram.db_notify.pdata = pmodified_row;
			if (FALSE == common_util_get_message_parent_folder(
				pdb->psqlite, message_id, &row_folder_id)) {
				return;
			}
		}
		if (NULL == ptable->psorts) {
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			datagram.id_array.pl = &ptable->table_id;
			pmodified_row->row_folder_id = row_folder_id;
			pmodified_row->row_message_id = message_id;
			pmodified_row->row_instance = 0;
			sql_len = sprintf(sql_string, "SELECT idx FROM "
					"t%u WHERE inst_id=%llu AND inst_num=0",
					ptable->table_id, message_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			idx = sqlite3_column_int64(pstmt, 0);
			sqlite3_finalize(pstmt);
			if (1 == idx) {
				pmodified_row->after_row_id = 0;
				pmodified_row->after_folder_id = 0;
			} else {
				sql_len = sprintf(sql_string, "SELECT inst_id FROM "
					"t%u WHERE idx=%u", ptable->table_id, idx - 1);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt, NULL)) {
					continue;
				}
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					sqlite3_finalize(pstmt);
					continue;
				}
				pmodified_row->after_row_id =
					sqlite3_column_int64(pstmt, 0);
				if (FALSE == common_util_get_message_parent_folder(
					pdb->psqlite, pmodified_row->after_row_id,
					&pmodified_row->after_folder_id)) {
					sqlite3_finalize(pstmt);
					continue;
				}
				sqlite3_finalize(pstmt);
			}
			pmodified_row->after_instance = 0;
			if (FALSE == ptable->b_search) {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED;
			} else {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram);
		} else if (0 == ptable->psorts->ccategories) {
			for (i=0; i<ptable->psorts->count; i++) {
				propvals[i].proptag = ptable->psorts->psort[i].propid;
				propvals[i].proptag <<= 16;
				propvals[i].proptag |= ptable->psorts->psort[i].type;
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					ptable->cpid, pdb->psqlite, propvals[i].proptag,
					&propvals[i].pvalue)) {
					break;
				}
			}
			if (i < ptable->psorts->count) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT idx FROM "
					"t%u WHERE inst_id=%llu AND inst_num=0",
					ptable->table_id, message_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			idx = sqlite3_column_int64(pstmt, 0);
			sqlite3_finalize(pstmt);
			sql_len = sprintf(sql_string, "SELECT inst_id"
				" FROM t%u WHERE idx=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (1 == idx) {
				inst_id = 0;
			} else {
				sqlite3_bind_int64(pstmt, 1, idx - 1);
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					sqlite3_finalize(pstmt);
					continue;
				}
				inst_id = sqlite3_column_int64(pstmt, 0);
				sqlite3_reset(pstmt);
			}
			sqlite3_bind_int64(pstmt, 1, idx + 1);
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				inst_id1 = 0;
			} else {
				inst_id1 = sqlite3_column_int64(pstmt, 0);
			}
			sqlite3_finalize(pstmt);
			b_error = FALSE;
			for (i=0; i<ptable->psorts->count; i++) {
				if (0 != inst_id) {
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, inst_id,
						ptable->cpid, pdb->psqlite,
						propvals[i].proptag, &pvalue)) {
						b_error = TRUE;
						break;
					}
					result = db_engine_compare_propval(
						ptable->psorts->psort[i].type,
						propvals[i].pvalue, pvalue);
					if (TABLE_SORT_ASCEND ==
						ptable->psorts->psort[i].table_sort) {
						if (result < 0) {
							goto REFRESH_TABLE;
						} else if (result > 0) {
							break;
						}
					} else {
						if (result > 0) {
							goto REFRESH_TABLE;
						} else if (result < 0) {
							break;
						}
					}
				}
			}
			if (TRUE == b_error) {
				continue;
			}
			for (i=0; i<ptable->psorts->count; i++) {
				if (0 != inst_id1) {
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, inst_id1,
						ptable->cpid, pdb->psqlite,
						propvals[i].proptag, &pvalue)) {
						b_error = TRUE;
						break;
					}
					result = db_engine_compare_propval(
						ptable->psorts->psort[i].type,
						propvals[i].pvalue, pvalue);
					if (TABLE_SORT_ASCEND ==
						ptable->psorts->psort[i].table_sort) {
						if (result > 0) {
							goto REFRESH_TABLE;
						} else if (result < 0) {
							break;
						}
					} else {
						if (result < 0) {
							goto REFRESH_TABLE;
						} else if (result > 0) {
							break;
						}
					}
				}
			}
			if (TRUE == b_error) {
				continue;
			}
			datagram.id_array.pl = &ptable->table_id;
			pmodified_row->row_folder_id = row_folder_id;
			pmodified_row->row_message_id = message_id;
			pmodified_row->row_instance = 0;
			pmodified_row->after_row_id = inst_id;
			if (0 == pmodified_row->after_row_id) {
				pmodified_row->after_folder_id = 0;
			} else {
				if (FALSE == common_util_get_message_parent_folder(
					pdb->psqlite, pmodified_row->after_row_id,
					&pmodified_row->after_folder_id)) {
					continue;
				}
			}
			pmodified_row->after_instance = 0;
			if (FALSE == ptable->b_search) {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED;
			} else {
				datagram.db_notify.type =
					DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED;
			}
			notification_agent_backward_notify(
				ptable->remote_id, &datagram);
		} else {
			/* check if the multiple instance value is changed */ 
			if (0 != ptable->instance_tag) {
				type = ptable->instance_tag & 0xFFFF & (~0x3000);
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, message_id,
					ptable->cpid, pdb->psqlite,
					ptable->instance_tag & (~0x2000),
					&pmultival)) {
					continue;
				}
				if (NULL != pmultival) {
					switch (type) {
					case PROPVAL_TYPE_SHORT:
						multi_num = ((SHORT_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_LONG:
						multi_num = ((LONG_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_LONGLONG:
						multi_num = ((LONGLONG_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_STRING:
					case PROPVAL_TYPE_WSTRING:
						multi_num = ((STRING_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_GUID:
						multi_num = ((GUID_ARRAY*)pmultival)->count;
						break;
					case PROPVAL_TYPE_BINARY:
						multi_num = ((BINARY_ARRAY*)pmultival)->count;
						break;
					}
					if (0 == multi_num) {
						pmultival = NULL;
						multi_num = 1;
					}
				} else {
					multi_num = 1;
				}
				sql_len = sprintf(sql_string, "SELECT value, "
						"inst_num FROM t%u WHERE inst_id=%llu",
						ptable->table_id, message_id);
				if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
					sql_string, sql_len, &pstmt, NULL)) {
					continue;
				}
				while (SQLITE_ROW == sqlite3_step(pstmt)) {
					pvalue = common_util_column_sqlite_statement(
												pstmt, 0, type);
					inst_num = sqlite3_column_int64(pstmt, 1);
					if (NULL == pmultival) {
						if (0 != inst_num) {
							sqlite3_finalize(pstmt);
							goto REFRESH_TABLE;
						}
					} else {
						if (0 == inst_num || inst_num > multi_num) {
							sqlite3_finalize(pstmt);
							goto REFRESH_TABLE;
						}
						switch (type) {
						case PROPVAL_TYPE_SHORT:
							pvalue1 = &((SHORT_ARRAY*)
								pmultival)->ps[inst_num - 1];
							break;
						case PROPVAL_TYPE_LONG:
							pvalue1 = &((LONG_ARRAY*)
								pmultival)->pl[inst_num - 1];
							break;
						case PROPVAL_TYPE_LONGLONG:
							pvalue1 = &((LONGLONG_ARRAY*)
								pmultival)->pll[inst_num - 1];
							break;
						case PROPVAL_TYPE_STRING:
						case PROPVAL_TYPE_WSTRING:
							pvalue1 = ((STRING_ARRAY*)
								pmultival)->ppstr[inst_num - 1];
							break;
						case PROPVAL_TYPE_GUID:
							pvalue1 = &((GUID_ARRAY*)
								pmultival)->pguid[inst_num - 1];
							break;
						case PROPVAL_TYPE_BINARY:
							pvalue1 = &((BINARY_ARRAY*)
								pmultival)->pbin[inst_num - 1];
							break;
						}
						if (0 != db_engine_compare_propval(
							type, pvalue, pvalue1)) {
							sqlite3_finalize(pstmt);
							goto REFRESH_TABLE;
						}
					}
				}
				sqlite3_finalize(pstmt);
			} else {
				multi_num = 1;
			}
			for (i=0; i<ptable->psorts->count; i++) {
				propvals[i].proptag = ptable->psorts->psort[i].propid;
				propvals[i].proptag <<= 16;
				propvals[i].proptag |= ptable->psorts->psort[i].type;
				if (propvals[i].proptag == ptable->instance_tag) {
					propvals[i].pvalue = NULL;
				} else {
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, message_id,
						ptable->cpid, pdb->psqlite, propvals[i].proptag,
						&propvals[i].pvalue)) {
						break;
					}
				}
			}
			if (i < ptable->psorts->count) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT parent_id, value "
						"FROM t%u WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT row_id, prev_id,"
						" extremum FROM t%u WHERE inst_id=%llu AND"
						" inst_num=?", ptable->table_id, message_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			b_error = FALSE;
			double_list_init(&notify_list);
			for (i=0; i<multi_num; i++) {
				if (0 == ptable->instance_tag) {
					inst_num = 0;
				} else {
					if (NULL == pmultival) {
						inst_num = 0;
					} else {
						inst_num = i + 1;
					}
				}
				sqlite3_bind_int64(pstmt1, 1, inst_num);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					b_error = TRUE;
					break;
				}
				row_id = sqlite3_column_int64(pstmt1, 0);
				prev_id = sqlite3_column_int64(pstmt1, 1);
				read_byte = sqlite3_column_int64(pstmt1, 2);
				sqlite3_reset(pstmt1);
				row_id1 = row_id;
				sqlite3_bind_int64(pstmt, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt)) {
					b_error = TRUE;
					break;
				}
				row_id = sqlite3_column_int64(pstmt, 0);
				parent_id = row_id;
				sqlite3_reset(pstmt);
				for (j=ptable->psorts->ccategories-1; j>=0; j--) {
					sqlite3_bind_int64(pstmt, 1, row_id);
					if (SQLITE_ROW != sqlite3_step(pstmt)) {
						b_error = TRUE;
						break;
					}
					row_id = sqlite3_column_int64(pstmt, 0);
					if (propvals[j].proptag == ptable->instance_tag) {
						sqlite3_reset(pstmt);
						continue;
					}
					pvalue = common_util_column_sqlite_statement(
						pstmt, 1, ptable->psorts->psort[j].type);
					sqlite3_reset(pstmt);
					if (0 != db_engine_compare_propval(
						ptable->psorts->psort[j].type,
						pvalue, propvals[j].pvalue)) {
						sqlite3_finalize(pstmt);	
						sqlite3_finalize(pstmt1);
						goto REFRESH_TABLE;
					}
				}
				if (TRUE == b_error) {
					break;
				}
				if (0 != ptable->extremum_tag) {
					sql_len = sprintf(sql_string, "SELECT extremum FROM t%u"
						" WHERE row_id=%llu", ptable->table_id, parent_id);
					if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
						sql_string, sql_len, &pstmt2, NULL)) {
						b_error = TRUE;
						break;
					}
					if (SQLITE_ROW != sqlite3_step(pstmt2)) {
						sqlite3_finalize(pstmt2);
						b_error = TRUE;
						break;
					}
					pvalue = common_util_column_sqlite_statement(
						pstmt2, 0, ptable->extremum_tag & 0xFFFF);
					sqlite3_finalize(pstmt2);
					result = db_engine_compare_propval(
						ptable->extremum_tag & 0xFFFF, pvalue,
						propvals[ptable->psorts->ccategories].pvalue);
					if (TABLE_SORT_MAXIMUM_CATEGORY == ptable->psorts->psort[
						ptable->psorts->ccategories].table_sort) {
						if (result < 0) {
							sqlite3_finalize(pstmt);	
							sqlite3_finalize(pstmt1);
							goto REFRESH_TABLE;
						}
					} else {
						if (result > 0) {
							sqlite3_finalize(pstmt);	
							sqlite3_finalize(pstmt1);
							goto REFRESH_TABLE;
						}
					}
				}
				if (0 == ptable->extremum_tag) {
					i = ptable->psorts->ccategories;
				} else {
					i = ptable->psorts->ccategories + 1;
				}
				if (ptable->psorts->count > i) {
					if (prev_id <= 0) {
						inst_id = 0;
					} else {
						sql_len = sprintf(sql_string, "SELECT inst_id FROM"
								" t%u WHERE row_id=%lld", ptable->table_id,
								prev_id);
						if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
							sql_string, sql_len, &pstmt2, NULL)) {
							b_error = TRUE;
							break;
						}
						if (SQLITE_ROW != sqlite3_step(pstmt2)) {
							sqlite3_finalize(pstmt2);
							b_error = TRUE;
							break;
						}
						inst_id = sqlite3_column_int64(pstmt2, 0);
						sqlite3_finalize(pstmt2);
					}
					sql_len = sprintf(sql_string, "SELECT inst_id FROM t%u"
						" WHERE prev_id=%llu", ptable->table_id, row_id1);
					if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
						sql_string, sql_len, &pstmt2, NULL)) {
						b_error = TRUE;
						break;
					}
					if (SQLITE_ROW != sqlite3_step(pstmt2)) {
						inst_id1 = 0;
					} else {
						inst_id1 = sqlite3_column_int64(pstmt2, 0);
					}
					sqlite3_finalize(pstmt2);
				}
				for (; i<ptable->psorts->count; i++) {
					if (0 != inst_id) {
						if (FALSE == common_util_get_property(
							MESSAGE_PROPERTIES_TABLE, inst_id,
							ptable->cpid, pdb->psqlite,
							propvals[i].proptag, &pvalue)) {
							b_error = TRUE;
							break;
						}
						result = db_engine_compare_propval(
							ptable->psorts->psort[i].type,
							propvals[i].pvalue, pvalue);
						if (TABLE_SORT_ASCEND ==
							ptable->psorts->psort[i].table_sort) {
							if (result < 0) {
								sqlite3_finalize(pstmt);
								sqlite3_finalize(pstmt1);
								goto REFRESH_TABLE;
							} else if (result > 0) {
								break;
							}
						} else {
							if (result > 0) {
								sqlite3_finalize(pstmt);
								sqlite3_finalize(pstmt1);
								goto REFRESH_TABLE;
							} else if (result < 0) {
								break;
							}
						}
					}
				}
				if (TRUE == b_error) {
					break;
				}
				if (0 == ptable->extremum_tag) {
					i = ptable->psorts->ccategories;
				} else {
					i = ptable->psorts->ccategories + 1;
				}
				for (; i<ptable->psorts->count; i++) {
					if (0 != inst_id1) {
						if (FALSE == common_util_get_property(
							MESSAGE_PROPERTIES_TABLE, inst_id1,
							ptable->cpid, pdb->psqlite,
							propvals[i].proptag, &pvalue)) {
							b_error = TRUE;
							break;
						}
						result = db_engine_compare_propval(
							ptable->psorts->psort[i].type,
							propvals[i].pvalue, pvalue);
						if (TABLE_SORT_ASCEND ==
							ptable->psorts->psort[i].table_sort) {
							if (result > 0) {
								sqlite3_finalize(pstmt);
								sqlite3_finalize(pstmt1);
								goto REFRESH_TABLE;
							} else if (result < 0) {
								break;
							}
						} else {
							if (result < 0) {
								sqlite3_finalize(pstmt);
								sqlite3_finalize(pstmt1);
								goto REFRESH_TABLE;
							} else if (result > 0) {
								break;
							}
						}
					}
				}
				if (TRUE == b_error) {
					break;
				}
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, message_id, 0,
					pdb->psqlite, PROP_TAG_READ, &pvalue) ||
					NULL == pvalue) {
					b_error = TRUE;
					break;
				}
				if (0 == *(uint8_t*)pvalue && 0 != read_byte) {
					unread_delta = 1;
					sprintf(sql_string, "UPDATE t%u SET extremum=0 "
						"WHERE row_id=%llu", ptable->table_id, row_id1);
				} else if (0 != *(uint8_t*)pvalue && 0 == read_byte) {
					unread_delta = -1;
					sprintf(sql_string, "UPDATE t%u SET extremum=1 "
						"WHERE row_id=%llu", ptable->table_id, row_id1);
				} else {
					unread_delta = 0;
				}
				if (0 != unread_delta) {
					if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
						sql_string, NULL, NULL, NULL)) {
						b_error = TRUE;
						break;
					}
				}
				row_id = row_id1;
				while (0 != unread_delta) {
					sqlite3_bind_int64(pstmt, 1, row_id);
					if (SQLITE_ROW != sqlite3_step(pstmt)) {
						b_error = TRUE;
						break;
					}
					row_id = sqlite3_column_int64(pstmt, 0);
					sqlite3_reset(pstmt);
					if (0 == row_id) {
						break;
					}
					if (unread_delta > 0) {
						sprintf(sql_string, "UPDATE t%u SET unread=unread+1"
							" WHERE row_id=%llu", ptable->table_id, row_id);
					} else {
						sprintf(sql_string, "UPDATE t%u SET unread=unread-1"
							" WHERE row_id=%llu", ptable->table_id, row_id);
					}
					if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
						sql_string, NULL, NULL, NULL)) {
						b_error = TRUE;
						break;
					}
					prnode = common_util_alloc(sizeof(ROWINFO_NODE));
					if (NULL == prnode) {
						sqlite3_finalize(pstmt);
						sqlite3_finalize(pstmt1);
						return;
					}
					prnode->node.pdata = prnode;
					prnode->b_added = FALSE;
					prnode->row_id = row_id;
					double_list_append_as_tail(&notify_list, &prnode->node);
				}
				if (TRUE == b_error) {
					break;
				}
				prnode = common_util_alloc(sizeof(ROWINFO_NODE));
				if (NULL == prnode) {
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					return;
				}
				prnode->node.pdata = prnode;
				prnode->b_added = FALSE;
				prnode->row_id = row_id1;
				double_list_append_as_tail(&notify_list, &prnode->node);
			}
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			if (TRUE == b_error) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM"
					" t%u WHERE idx=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM "
					"t%u WHERE row_id=?", ptable->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			while (pnode1=double_list_get_from_head(&notify_list)) {
				row_id = ((ROWINFO_NODE*)pnode1->pdata)->row_id;
				sqlite3_bind_int64(pstmt1, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					sqlite3_reset(pstmt1);
					continue;
				}
				/* row does not have an idx, it's invisible */
				if (SQLITE_NULL == sqlite3_column_type(pstmt1, 1)) {
					sqlite3_reset(pstmt1);
					continue;
				}
				idx = sqlite3_column_int64(pstmt1, 1);
				if (1 == idx) {
					inst_id = 0;
					inst_num = 0;
				} else {
					sqlite3_bind_int64(pstmt, 1, idx - 1);
					if (SQLITE_ROW != sqlite3_step(pstmt)) {
						sqlite3_reset(pstmt);
						sqlite3_reset(pstmt1);
						continue;
					}
					inst_id = sqlite3_column_int64(pstmt, 3);
					row_type = sqlite3_column_int64(pstmt, 4);
					inst_num = sqlite3_column_int64(pstmt, 10);
					sqlite3_reset(pstmt);
				}
				datagram.id_array.pl = &ptable->table_id;
				pmodified_row->row_message_id =
					sqlite3_column_int64(pstmt1, 3);
				pmodified_row->row_instance =
					sqlite3_column_int64(pstmt1, 10);
				if (CONTENT_ROW_MESSAGE ==
					sqlite3_column_int64(pstmt1, 4)) {
					pmodified_row->row_folder_id = row_folder_id;
				} else {
					pmodified_row->row_folder_id = folder_id;
				}
				pmodified_row->after_row_id = inst_id;
				if (0 == inst_id) {
					pmodified_row->after_folder_id = 0;
				} else {
					if (CONTENT_ROW_MESSAGE == row_type) {
						if (FALSE == common_util_get_message_parent_folder(
							pdb->psqlite, pmodified_row->after_row_id,
							&pmodified_row->after_folder_id)) {
							sqlite3_reset(pstmt1);
							continue;
						}
					} else {
						pmodified_row->after_folder_id = folder_id;
					}
				}
				pmodified_row->after_instance = inst_num;
				if (FALSE == ptable->b_search) {
					datagram.db_notify.type =
						DB_NOTIFY_TYPE_CONTENT_TABLE_ROW_MODIFIED;
				} else {
					datagram.db_notify.type =
						DB_NOTIFY_TYPE_SEARCH_TABLE_ROW_MODIFIED;
				}
				notification_agent_backward_notify(
					ptable->remote_id, &datagram);
				sqlite3_reset(pstmt1);
			}
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
		}
		continue;
REFRESH_TABLE:
		ptnode = common_util_alloc(sizeof(TABLE_NODE));
		if (NULL == ptnode) {
			return;
		}
		*ptnode = *ptable;
		if (0 != ptable->psorts->ccategories) {
			ptnode->table_flags |= TABLE_FLAG_NONOTIFICATIONS;
		}
		ptnode->node.pdata = ptnode;
		double_list_append_as_tail(&tmp_list, &ptnode->node);
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		tmp_list1 = pdb->tables.table_list;
		pdb->tables.table_list = tmp_list;
		db_engine_notify_content_table_delete_row(
			pdb, folder_id, message_id);
		db_engine_notify_content_table_add_row(
			pdb, folder_id, message_id);
		pdb->tables.table_list = tmp_list1;
		for (pnode=double_list_get_head(&tmp_list); NULL!=pnode;
			pnode=double_list_get_after(&tmp_list, pnode)) {
			ptable = (TABLE_NODE*)pnode->pdata;
			for (pnode1=double_list_get_head(
				&pdb->tables.table_list); NULL!=pnode1;
				pnode1=double_list_get_after(
				&pdb->tables.table_list, pnode1)) {
				ptnode = (TABLE_NODE*)pnode1->pdata;
				if (ptable->table_id == ptnode->table_id) {
					ptnode->header_id = ptable->header_id;
					if (0 != ptable->psorts->ccategories &&
						0 == (ptnode->table_flags &
						TABLE_FLAG_NONOTIFICATIONS)) {
						if (FALSE == ptnode->b_search) {
							datagram.db_notify.type =
								DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED;
						} else {
							datagram.db_notify.type =
								DB_NOTIFY_TYPE_SEARCH_TABLE_CHANGED;
						}
						datagram.id_array.pl = &ptable->table_id;
						notification_agent_backward_notify(
							ptable->remote_id, &datagram);
					}
					break;
				}
			}
		}
	}
}

void db_engine_notify_message_modification(DB_ITEM *pdb,
	uint64_t folder_id, uint64_t message_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_MESSAGE_MODIFIED *pmodified_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTMODIFIED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id &&
			message_id == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_MESSAGE_MODIFIED;
		pmodified_mail = common_util_alloc(
			sizeof(DB_NOTIFY_MESSAGE_MODIFIED));
		if (NULL == pmodified_mail) {
			return;
		}
		datagram.db_notify.pdata = pmodified_mail;
		pmodified_mail->folder_id = folder_id;
		pmodified_mail->message_id = message_id;
		pmodified_mail->proptags.count = 0;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_content_table_modify_row(
		pdb, folder_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id);
}

static void db_engine_notify_hierarchy_table_modify_row(
	DB_ITEM *pdb, uint64_t parent_id, uint64_t folder_id)
{
	int idx;
	int sql_len;
	BOOL b_included;
	TABLE_NODE *ptable;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	const GUID *phandle_guid;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_DATAGRAM datagram1;
	DB_NOTIFY_DATAGRAM datagram2;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED *padded_row;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED *pdeleted_row;
	DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED *pmodified_row;
	
	padded_row = NULL;
	pdeleted_row = NULL;
	pmodified_row = NULL;
	for (pnode=double_list_get_head(&pdb->tables.table_list);
		NULL!=pnode; pnode=double_list_get_after(
		&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TABLE_TYPE_HIERARCHY != ptable->type) {
			continue;
		}
		if (TABLE_FLAG_DEPTH & ptable->table_flags) {
			if (folder_id == ptable->folder_id ||
				FALSE == common_util_check_decendant(
				pdb->psqlite, folder_id, ptable->folder_id,
				&b_included) || FALSE == b_included) {
				continue;
			}
		} else {
			if (parent_id != ptable->folder_id) {
				continue;
			}
		}
		sql_len = sprintf(sql_string, "SELECT idx FROM t%u "
			"WHERE folder_id=%llu", ptable->table_id, folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			continue;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			if (NULL != ptable->prestriction &&
				TRUE == common_util_evaluate_folder_restriction(
				pdb->psqlite, folder_id, ptable->prestriction)) {
				if (NULL == padded_row) {
					datagram2.dir = (char*)exmdb_server_get_dir();
					datagram2.b_table = TRUE;
					datagram2.id_array.count = 1;
					datagram2.db_notify.type =
						DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_ADDED;
					padded_row = common_util_alloc(sizeof(
						DB_NOTIFY_HIERARCHY_TABLE_ROW_ADDED));
					if (NULL == padded_row) {
						return;
					}
					datagram2.db_notify.pdata = padded_row;
				}
				sprintf(sql_string, "INSERT INTO t%u (folder_id)"
					" VALUES (%llu)", ptable->table_id, folder_id);
				if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
					sql_string, NULL, NULL, NULL)) {
					continue;
				}
				if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
					continue;
				}
				if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
					phandle_guid = exmdb_server_get_handle();
					if (NULL != phandle_guid && 0 == guid_compare(
						phandle_guid, &ptable->handle_guid)) {
						continue;
					}
				}
				idx = sqlite3_last_insert_rowid(pdb->tables.psqlite);
				if (1 == idx) {
					padded_row->after_folder_id = 0;
				} else {
					sql_len = sprintf(sql_string, "SELECT "
						"folder_id FROM t%u WHERE idx=%u",
						ptable->table_id, idx - 1);
					if (SQLITE_OK != sqlite3_prepare_v2(
						pdb->tables.psqlite, sql_string,
						sql_len, &pstmt, NULL)) {
						continue;
					}
					if (SQLITE_ROW != sqlite3_step(pstmt)) {
						sqlite3_finalize(pstmt);
						continue;
					}
					padded_row->after_folder_id =
						sqlite3_column_int64(pstmt, 0);
					sqlite3_finalize(pstmt);
				}
				datagram2.id_array.pl = &ptable->table_id;
				padded_row->row_folder_id = folder_id;
				notification_agent_backward_notify(
					ptable->remote_id, &datagram2);
			}
			continue;
		}
		idx = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		if (NULL != ptable->prestriction &&
			FALSE == common_util_evaluate_folder_restriction(
			pdb->psqlite, folder_id, ptable->prestriction)) {
			sprintf(sql_string, "DELETE FROM t%u WHERE "
				"folder_id=%llu", ptable->table_id, folder_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				continue;
			}
			sprintf(sql_string, "UPDATE t%u SET idx=-(idx-1)"
				" WHERE idx>%u;UPDATE t%u SET idx=-idx WHERE"
				" idx<0", ptable->table_id, idx, ptable->table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				continue;
			}
			sprintf(sql_string, "UPDATE sqlite_sequence SET seq="
				"(SELECT count(*) FROM t%u) WHERE name='t%u'",
				ptable->table_id, ptable->table_id);
			sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL);
			if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
				continue;
			}
			if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
				phandle_guid = exmdb_server_get_handle();
				if (NULL != phandle_guid && 0 == guid_compare(
					phandle_guid, &ptable->handle_guid)) {
					continue;
				}
			}
			if (NULL == pdeleted_row) {
				datagram1.dir = (char*)exmdb_server_get_dir();
				datagram1.b_table = TRUE;
				datagram1.id_array.count = 1;
				datagram1.db_notify.type =
					DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_DELETED;
				pdeleted_row = common_util_alloc(sizeof(
					DB_NOTIFY_HIERARCHY_TABLE_ROW_DELETED));
				if (NULL == pdeleted_row) {
					return;
				}
				datagram1.db_notify.pdata = pdeleted_row;
				pdeleted_row->row_folder_id = folder_id;
			}
			datagram1.id_array.pl = &ptable->table_id;
			notification_agent_backward_notify(
				ptable->remote_id, &datagram1);
			continue;
		}
		if (ptable->table_flags & TABLE_FLAG_NONOTIFICATIONS) {
			continue;
		}
		if (ptable->table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
			phandle_guid = exmdb_server_get_handle();
			if (NULL != phandle_guid && 0 == guid_compare(
				phandle_guid, &ptable->handle_guid)) {
				continue;
			}
		}
		if (NULL == pmodified_row) {
			datagram.dir = (char*)exmdb_server_get_dir();
			datagram.b_table = TRUE;
			datagram.id_array.count = 1;
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_HIERARCHY_TABLE_ROW_MODIFIED;
			pmodified_row = common_util_alloc(sizeof(
				DB_NOTIFY_HIERARCHY_TABLE_ROW_MODIFIED));
			if (NULL == pmodified_row) {
				return;
			}
			datagram.db_notify.pdata = pmodified_row;
			pmodified_row->row_folder_id = folder_id;
		}
		if (1 == idx) {
			pmodified_row->after_folder_id = 0;
		} else {
			sql_len = sprintf(sql_string, "SELECT folder_id FROM "
				"t%u WHERE idx=%u", ptable->table_id, idx - 1);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				continue;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				continue;
			}
			pmodified_row->after_folder_id =
				sqlite3_column_int64(pstmt, 0);
			sqlite3_finalize(pstmt);
		}
		datagram.id_array.pl = &ptable->table_id;
		notification_agent_backward_notify(
			ptable->remote_id, &datagram);
	}
}

void db_engine_notify_folder_modification(DB_ITEM *pdb,
	uint64_t parent_id, uint64_t folder_id)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_FOLDER_MODIFIED *pmodified_folder;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (0 == (pnsub->notificaton_type &
			NOTIFICATION_TYPE_OBJECTMODIFIED)) {
			continue;
		}
		if (TRUE == pnsub->b_whole ||
			(pnsub->folder_id == folder_id
			&& 0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		datagram.db_notify.type =
			DB_NOTIFY_TYPE_FOLDER_MODIFIED;
		pmodified_folder = common_util_alloc(
			sizeof(DB_NOTIFY_FOLDER_MODIFIED));
		if (NULL == pmodified_folder) {
			return;
		}
		datagram.db_notify.pdata = pmodified_folder;
		pmodified_folder->folder_id = folder_id;
		pmodified_folder->ptotal = NULL;
		pmodified_folder->punread = NULL;
		pmodified_folder->proptags.count = 0;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	db_engine_notify_hierarchy_table_modify_row(
		pdb, parent_id, folder_id);
}

void db_engine_notify_message_movecopy(DB_ITEM *pdb,
	BOOL b_copy, uint64_t folder_id, uint64_t message_id,
	uint64_t old_fid, uint64_t old_mid)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_MESSAGE_MVCP *pmvcp_mail;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (TRUE == b_copy) {
			if (0 == (pnsub->notificaton_type &
				NOTIFICATION_TYPE_OBJECTCOPIED)) {
				continue;
			}
		} else {
			if (0 == (pnsub->notificaton_type &
				NOTIFICATION_TYPE_OBJECTMOVED)) {
				continue;
			}
		}
		if (TRUE == pnsub->b_whole || (pnsub->folder_id == old_fid
			&& pnsub->message_id == old_mid)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		if (TRUE == b_copy) {
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_MESSAGE_COPIED;
		} else {
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_MESSAGE_MOVED;
		}
		pmvcp_mail = common_util_alloc(
			sizeof(DB_NOTIFY_MESSAGE_MVCP));
		if (NULL == pmvcp_mail) {
			return;
		}
		datagram.db_notify.pdata = pmvcp_mail;
		pmvcp_mail->folder_id = folder_id;
		pmvcp_mail->message_id = message_id;
		pmvcp_mail->old_folder_id = old_fid;
		pmvcp_mail->old_message_id = old_mid;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	if (FALSE == b_copy) {
		db_engine_notify_content_table_delete_row(
			pdb, old_fid, old_mid);
		db_engine_notify_folder_modification(
			pdb, common_util_get_folder_parent_fid(
			pdb->psqlite, old_fid), old_fid);
	}
	db_engine_notify_content_table_add_row(
		pdb, folder_id, message_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, folder_id), folder_id);
}

void db_engine_notify_folder_movecopy(DB_ITEM *pdb,
	BOOL b_copy, uint64_t parent_id, uint64_t folder_id, 
	uint64_t old_pid, uint64_t old_fid)
{
	int i;
	const char *dir;
	NSUB_NODE *pnsub;
	ID_NODE *pidnode;
	ID_ARRAYS *parrays;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	DB_NOTIFY_FOLDER_MVCP *pmvcp_folder;
	
	dir = exmdb_server_get_dir();
	double_list_init(&tmp_list);
	for (pnode=double_list_get_head(&pdb->nsub_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->nsub_list, pnode)) {
		pnsub = (NSUB_NODE*)pnode->pdata;
		if (TRUE == b_copy) {
			if (0 == (pnsub->notificaton_type &
				NOTIFICATION_TYPE_OBJECTCOPIED)) {
				continue;
			}
		} else {
			if (0 == (pnsub->notificaton_type &
				NOTIFICATION_TYPE_OBJECTMOVED)) {
				continue;
			}
		}
		if (TRUE == pnsub->b_whole || (pnsub->folder_id == folder_id &&
			0 == pnsub->message_id) || (pnsub->folder_id == old_fid &&
			0 == pnsub->message_id)) {
			pidnode = common_util_alloc(sizeof(ID_NODE));
			if (NULL == pidnode) {
				return;
			}
			pidnode->node.pdata = pidnode;
			pidnode->remote_id = pnsub->remote_id;
			pidnode->id = pnsub->sub_id;
			double_list_append_as_tail(
				&tmp_list, &pidnode->node);
		}
	}
	if (double_list_get_nodes_num(&tmp_list) > 0) {
		datagram.dir = (char*)dir;
		datagram.b_table = FALSE;
		if (TRUE == b_copy) {
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_FOLDER_COPIED;
		} else {
			datagram.db_notify.type =
				DB_NOTIFY_TYPE_FOLDER_MOVED;
		}
		pmvcp_folder = common_util_alloc(
			sizeof(DB_NOTIFY_FOLDER_MVCP));
		if (NULL == pmvcp_folder) {
			return;
		}
		datagram.db_notify.pdata = pmvcp_folder;
		pmvcp_folder->folder_id = folder_id;
		pmvcp_folder->parent_id = parent_id;
		pmvcp_folder->old_folder_id = old_fid;
		pmvcp_folder->old_parent_id = old_pid;
		parrays = db_engine_classify_id_array(&tmp_list);
		if (NULL == parrays) {
			return;
		}
		for (i=0; i<parrays->count; i++) {
			datagram.id_array = parrays->parray[i];
			notification_agent_backward_notify(
				parrays->remote_ids[i], &datagram);
		}
	}
	if (FALSE == b_copy) {
		db_engine_notify_hierarchy_table_delete_row(
			pdb, old_pid, old_fid);
		db_engine_notify_folder_modification(
			pdb, common_util_get_folder_parent_fid(
			pdb->psqlite, old_pid), old_pid);
	}
	db_engine_notify_hierarchy_table_add_row(
		pdb, parent_id, folder_id);
	db_engine_notify_folder_modification(
		pdb, common_util_get_folder_parent_fid(
		pdb->psqlite, parent_id), parent_id);
}

void db_engine_notify_content_table_reload(
	DB_ITEM *pdb, uint32_t table_id)
{
	TABLE_NODE *ptable;
	DOUBLE_LIST_NODE *pnode;
	DB_NOTIFY_DATAGRAM datagram;
	
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		return;
	}
	ptable = (TABLE_NODE*)pnode->pdata;
	datagram.dir = (char*)exmdb_server_get_dir();
	if (FALSE == ptable->b_search) {
		datagram.db_notify.type = DB_NOTIFY_TYPE_CONTENT_TABLE_CHANGED;
	} else {
		datagram.db_notify.type = DB_NOTIFY_TYPE_SEARCH_TABLE_CHANGED;
	}
	datagram.db_notify.pdata = NULL;
	datagram.b_table = TRUE;
	datagram.id_array.count = 1;
	datagram.id_array.pl = &table_id;
	notification_agent_backward_notify(
		ptable->remote_id, &datagram);
}

void db_engine_begin_batch_mode(DB_ITEM *pdb)
{
	pdb->tables.b_batch = TRUE;
}

void db_engine_commit_batch_mode(DB_ITEM *pdb)
{
	int table_num;
	const char *dir;
	TABLE_NODE *ptable;
	uint32_t *ptable_ids;
	DOUBLE_LIST_NODE *pnode;
	
	table_num = double_list_get_nodes_num(&pdb->tables.table_list);
	if (table_num > 0) {
		ptable_ids = common_util_alloc(sizeof(uint32_t)*table_num);
	} else {
		ptable_ids = NULL;
	}
	table_num = 0;
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		if (TRUE == ptable->b_hint) {
			if (NULL != ptable_ids) {
				ptable_ids[table_num] = ptable->table_id;
				table_num ++;
			}
			ptable->b_hint = FALSE;
		}
	}
	pdb->tables.b_batch = FALSE;
	db_engine_put_db(pdb);
	dir = exmdb_server_get_dir();
	while (0 != table_num) {
		table_num --;
		exmdb_server_reload_content_table(
			dir, ptable_ids[table_num]);
	}
}

void db_engine_cancel_batch_mode(DB_ITEM *pdb)
{
	TABLE_NODE *ptable;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		ptable = (TABLE_NODE*)pnode->pdata;
		ptable->b_hint = FALSE;
	}
	pdb->tables.b_batch = FALSE;
}

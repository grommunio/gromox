#include "proptag_array.h"
#include "sortorder_set.h"
#include "exmdb_server.h"
#include "restriction.h"
#include "common_util.h"
#include "ext_buffer.h"
#include "db_engine.h"
#include "int_hash.h"
#include "rop_util.h"
#include "propval.h"
#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <iconv.h>
#include <stdio.h>

typedef struct _CONDITION_NODE {
	DOUBLE_LIST_NODE node;
	uint32_t proptag;
	void *pvalue;
} CONDITION_NODE;

typedef struct _CONTENT_ROW_PARAM {
	uint32_t cpid;
	sqlite3 *psqlite;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	uint64_t folder_id;
	uint64_t inst_id;
	int row_type;
	const SORTORDER_SET *psorts;
	uint32_t instance_tag;
	uint32_t extremum_tag;
} CONTENT_ROW_PARAM;

typedef struct _HIERARCHY_ROW_PARAM {
	uint32_t cpid;
	sqlite3 *psqlite;
	sqlite3_stmt *pstmt;
	uint64_t folder_id;
} HIERARCHY_ROW_PARAM;

typedef BOOL (*TABLE_GET_ROW_PROPERTY)(void*, uint32_t, void **);

static BOOL table_sum_table_count(DB_ITEM *pdb,
	uint32_t table_id, uint32_t *prows)
{
	int sql_len;
	sqlite3_stmt *pstmt;
	char sql_string[128];
	
	sql_len = sprintf(sql_string, "SELECT "
			"count(idx) FROM t%u", table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		return FALSE;
	}
	*prows = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	return TRUE;
}

static uint32_t table_sum_hierarchy(sqlite3 *psqlite,
	uint64_t folder_id, const char *username, BOOL b_depth)
{
	int sql_len;
	uint32_t count;
	sqlite3_stmt *pstmt;
	uint32_t permission;
	char sql_string[128];
	
	if (FALSE == b_depth) {
		if (NULL == username) {
			sql_len = sprintf(sql_string, "SELECT count(*) FROM"
					" folders WHERE parent_id=%llu", folder_id);
			if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				return 0;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				sqlite3_finalize(pstmt);
				return 0;
			}
			count = sqlite3_column_int64(pstmt, 0);
		} else {
			count = 0;
			sql_len = sprintf(sql_string, "SELECT folder_id FROM "
						"folders WHERE parent_id=%llu", folder_id);
			if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				return 0;
			}
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (FALSE == common_util_check_folder_permission(
					psqlite, sqlite3_column_int64(pstmt, 0),
					username, &permission)) {
					continue;
				}
				if (0 == (permission & PERMISSION_READANY) &&
					0 == (permission & PERMISSION_FOLDERVISIBLE) &&
					0 == (permission & PERMISSION_FOLDEROWNER)) {
					continue;
				}
				count ++;
			}
		}
	} else {
		count = 0;
		sql_len = sprintf(sql_string, "SELECT folder_id FROM "
					"folders WHERE parent_id=%llu", folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return 0;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			if (NULL != username) {
				if (FALSE == common_util_check_folder_permission(
					psqlite, sqlite3_column_int64(pstmt, 0),
					username, &permission)) {
					continue;
				}
				if (0 == (permission & PERMISSION_READANY) &&
					0 == (permission & PERMISSION_FOLDERVISIBLE) &&
					0 == (permission & PERMISSION_FOLDEROWNER)) {
					continue;
				}
			}
			count += table_sum_hierarchy(psqlite,
				sqlite3_column_int64(pstmt, 0), username, TRUE);
			count ++;
		}
	}
	sqlite3_finalize(pstmt);
	return count;
}

static BOOL table_load_hierarchy(sqlite3 *psqlite,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, sqlite3_stmt *pstmt, int depth,
	uint32_t *prow_count)
{
	int i;
	int sql_len;
	uint64_t folder_id1;
	uint32_t permission;
	char sql_string[256];
	sqlite3_stmt *pstmt1;
	
	if (TRUE == exmdb_server_check_private()) {
		if (table_flags & TABLE_FLAG_SOFTDELETES) {
			sql_len = sprintf(sql_string, "SELECT"
				" folder_id FROM folders WHERE 0");
		} else {
			sql_len = sprintf(sql_string, "SELECT folder_id "
				"FROM folders WHERE parent_id=%llu", folder_id);
		}
	} else {
		if (table_flags & TABLE_FLAG_SOFTDELETES) {
			sql_len = sprintf(sql_string, "SELECT folder_id FROM"
				" folders WHERE parent_id=%llu AND is_deleted=1",
				folder_id);
		} else {
			sql_len = sprintf(sql_string, "SELECT folder_id FROM"
				" folders WHERE parent_id=%llu AND is_deleted=0",
				folder_id);
		}
	}
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		folder_id1 = sqlite3_column_int64(pstmt1, 0);
		if (NULL != username) {
			if (FALSE == common_util_check_folder_permission(
				psqlite, folder_id1, username, &permission)) {
				continue;
			}
			if (0 == (permission & PERMISSION_READANY) &&
				0 == (permission & PERMISSION_FOLDERVISIBLE) &&
				0 == (permission & PERMISSION_FOLDEROWNER)) {
				continue;
			}
		}
		if (NULL != prestriction) {
			if (FALSE == common_util_evaluate_folder_restriction(
				psqlite, folder_id1, prestriction)) {
				goto LOAD_SUBFOLDER;
			}
		}
		sqlite3_bind_int64(pstmt, 1, folder_id1);
		sqlite3_bind_int64(pstmt, 2, depth);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		(*prow_count) ++;
		sqlite3_reset(pstmt);
LOAD_SUBFOLDER:
		if (table_flags & TABLE_FLAG_DEPTH) {
			if (FALSE == table_load_hierarchy(
				psqlite, folder_id1, username, table_flags,
				prestriction, pstmt, depth + 1, prow_count)) {
				sqlite3_finalize(pstmt1);
				return FALSE;
			}
		}
	}
	sqlite3_finalize(pstmt1);
	return TRUE;
}

BOOL exmdb_server_sum_hierarchy(const char *dir,
	uint64_t folder_id, const char *username,
	BOOL b_depth, uint32_t *pcount)
{
	DB_ITEM *pdb;
	uint64_t fid_val;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	*pcount = table_sum_hierarchy(pdb->psqlite,
					fid_val, username, b_depth);
	db_engine_put_db(pdb);
	return TRUE;
}
	
BOOL exmdb_server_load_hierarchy_table(const char *dir,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, uint32_t *ptable_id,
	uint32_t *prow_count)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t fid_val;
	uint32_t table_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	uint32_t tmp_proptag;
	const char *remote_id;
	const GUID *phandle_guid;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (NULL == pdb->tables.psqlite) {
		if (SQLITE_OK != sqlite3_open_v2(":memory:", &pdb->tables.psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	pdb->tables.last_id ++;
	table_id = pdb->tables.last_id;
	/* begin the transaction */
	sqlite3_exec(pdb->tables.psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE t%u "
		"(idx INTEGER PRIMARY KEY AUTOINCREMENT, "
		"folder_id INTEGER UNIQUE NOT NULL, "
		"depth INTEGER NOT NULL)", table_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	ptnode = malloc(sizeof(TABLE_NODE));
	if (NULL == ptnode) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	memset(ptnode, 0, sizeof(TABLE_NODE));
	ptnode->node.pdata = ptnode;
	ptnode->table_id = table_id;
	remote_id = exmdb_server_get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (NULL == ptnode->remote_id) {
			free(ptnode);
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	ptnode->type = TABLE_TYPE_HIERARCHY;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	if (table_flags & TABLE_FLAG_SUPPRESSNOTIFICATIONS) {
		phandle_guid = exmdb_server_get_handle();
		if (NULL == phandle_guid) {
			memset(&ptnode->handle_guid, 0, sizeof(GUID));
		} else {
			ptnode->handle_guid = *phandle_guid;
		}
	}
	if (NULL != prestriction) {
		ptnode->prestriction = restriction_dup(prestriction);
		if (NULL == ptnode->prestriction) {
			if (NULL != ptnode->remote_id) {
				free(ptnode->remote_id);
			}
			free(ptnode);
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sql_len = sprintf(sql_string, "INSERT INTO t%u (folder_id,"
					" depth) VALUES (?, ?)", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		if (NULL != ptnode->prestriction) {
			restriction_free(ptnode->prestriction);
		}
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	*prow_count = 0;
	if (FALSE == table_load_hierarchy(pdb->psqlite,
		fid_val, username, table_flags, prestriction,
		pstmt, 1, prow_count)) {
		sqlite3_finalize(pstmt);
		if (NULL != ptnode->prestriction) {
			restriction_free(ptnode->prestriction);
		}
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(pdb->tables.psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	double_list_append_as_tail(&pdb->tables.table_list, &ptnode->node);
	*ptable_id = ptnode->table_id;
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_sum_content(const char *dir, uint64_t folder_id,
	BOOL b_fai, BOOL b_deleted, uint32_t *pcount)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t fid_val;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (TRUE == exmdb_server_check_private()) {
		if (FALSE == b_fai) {
			sql_len = sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"is_associated=0", fid_val);
		} else {
			sql_len = sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"is_associated=1", fid_val);
		}
	} else {
		if (FALSE == b_fai) {
			sql_len = sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"(is_associated=0 AND ", fid_val);
		} else {
			sql_len = sprintf(sql_string, "SELECT count(*)"
				" FROM messages WHERE parent_fid=%llu AND "
				"(is_associated=1 AND ", fid_val);
		}
		if (FALSE == b_deleted) {
			sql_len += sprintf(sql_string + sql_len, "is_deleted=0)");
		} else {
			sql_len += sprintf(sql_string + sql_len, "is_deleted=1)");
		}
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pcount = sqlite3_column_int64(pstmt, 0);
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

static void table_condition_list_to_where_clause(
	DOUBLE_LIST *pcondition_list, char *where_clause, int length)
{
	int offset;
	CONDITION_NODE *pcnode;
	DOUBLE_LIST_NODE *pnode;
	
	offset = 0;
	for (pnode=double_list_get_head(pcondition_list); NULL!=pnode;
		pnode=double_list_get_after(pcondition_list, pnode)) {
		pcnode = (CONDITION_NODE*)pnode->pdata;
		if (0 == offset) {
			offset = snprintf(where_clause, length, "WHERE ");
		} else {
			offset += snprintf(where_clause + offset,
						length - offset, " AND ");
		}
		if (NULL == pcnode->pvalue) {
			offset += snprintf(where_clause + offset,
					length - offset, "v%x IS NULL",
					pcnode->proptag);
		} else {
			offset += snprintf(where_clause + offset,
				length - offset, "v%x=?", pcnode->proptag);
		}
	}
	where_clause[offset] = '\0';
}

static BOOL table_load_content(DB_ITEM *pdb, sqlite3 *psqlite,
	const SORTORDER_SET *psorts, int depth, uint64_t parent_id,
	DOUBLE_LIST *pcondition_list, sqlite3_stmt *pstmt_insert,
	uint32_t *pheader_id, sqlite3_stmt *pstmt_update,
	uint32_t *punread_count)
{
	int i;
	int sql_len;
	void *pvalue;
	uint16_t type;
	BOOL b_orderby;
	int bind_index;
	int multi_index;
	int64_t prev_id;
	BOOL b_extremum;
	uint64_t header_id;
	sqlite3_stmt *pstmt;
	uint32_t tmp_proptag;
	uint32_t tmp_proptag1;
	char sql_string[1024];
	uint32_t unread_count;
	char where_clause[1024];
	DOUBLE_LIST_NODE *pnode;
	CONDITION_NODE tmp_cnode;
	
	prev_id = (-1)*parent_id;
	table_condition_list_to_where_clause(pcondition_list,
					where_clause, sizeof(where_clause));
	if (depth == psorts->ccategories) {
		multi_index = -1;
		for (i=0; i<psorts->ccategories; i++) {
			if (0x3000 == (psorts->psort[i].type & 0x3000)) {
				tmp_proptag = psorts->psort[i].propid;
				tmp_proptag <<= 16;
				tmp_proptag |= psorts->psort[i].type;
				multi_index = i;
				break;
			}
		}
		if (-1 == multi_index) {
			if (psorts->ccategories > 0) {
				sql_len = snprintf(sql_string, sizeof(sql_string),
					"SELECT message_id, read_state FROM stbl %s",
					where_clause);
			} else {
				sql_len = snprintf(sql_string, sizeof(sql_string),
					"SELECT message_id FROM stbl %s", where_clause);
			}
		} else {
			sql_len = snprintf(sql_string, sizeof(sql_string),
				"SELECT message_id, read_state, inst_num, v%x"
				" FROM stbl %s", tmp_proptag, where_clause);
		}
		b_orderby = FALSE;
		for (i=psorts->ccategories; i<psorts->count; i++) {
			tmp_proptag = psorts->psort[i].propid;
			tmp_proptag <<= 16;
			tmp_proptag |= psorts->psort[i].type;
			if (TABLE_SORT_MAXIMUM_CATEGORY ==
				psorts->psort[i].table_sort ||
				TABLE_SORT_MINIMUM_CATEGORY ==
				psorts->psort[i].table_sort) {
				continue;
			}
			if (FALSE == b_orderby) {
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							" ORDER BY v%x ", tmp_proptag);
				b_orderby = TRUE;
			} else {
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							", v%x ", tmp_proptag);
			}
			if (TABLE_SORT_ASCEND ==
				psorts->psort[i].table_sort) {
				sql_len += snprintf(sql_string + sql_len,
					sizeof(sql_string) - sql_len, " ASC");
			} else {
				sql_len += snprintf(sql_string + sql_len,
					sizeof(sql_string) - sql_len, " DESC");
			}
		}
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		bind_index = 1;
		for (i=0,pnode=double_list_get_head(pcondition_list); NULL!=pnode;
			pnode=double_list_get_after(pcondition_list, pnode),i++) {
			if (NULL != ((CONDITION_NODE*)pnode->pdata)->pvalue) {
				if (0x3000 == (psorts->psort[i].type & 0x3000)) {
					type = psorts->psort[i].type & (~0x3000);
				} else {
					type = psorts->psort[i].type;
				}
				if (FALSE == common_util_bind_sqlite_statement(
					pstmt, bind_index, type,
					((CONDITION_NODE*)pnode->pdata)->pvalue)) {
					sqlite3_finalize(pstmt);
					return FALSE;
				}
				bind_index ++;
			}
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			if (psorts->ccategories > 0) {
				if (0 == sqlite3_column_int64(pstmt, 1)) {
					(*punread_count) ++;
					/* unread(0) in extremum for message row */
					sqlite3_bind_int64(pstmt_insert, 9, 0);
				} else {
					/* read(1) in extremum for message row */
					sqlite3_bind_int64(pstmt_insert, 9, 1);
				}
			} else {
				sqlite3_bind_null(pstmt_insert, 9);
			}
			sqlite3_bind_int64(pstmt_insert, 1,
				sqlite3_column_int64(pstmt, 0));
			sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_MESSAGE);
			sqlite3_bind_null(pstmt_insert, 3);
			sqlite3_bind_int64(pstmt_insert, 4, parent_id);
			sqlite3_bind_int64(pstmt_insert, 5, depth);
			sqlite3_bind_null(pstmt_insert, 6);
			if (-1 != multi_index) {
				sqlite3_bind_int64(pstmt_insert, 7,
					sqlite3_column_int64(pstmt, 2));
				type = psorts->psort[multi_index].type & (~0x3000);
				pvalue = common_util_column_sqlite_statement(pstmt, 3, type);
				if (NULL == pvalue) {
					sqlite3_bind_null(pstmt_insert, 8);
				} else {
					if (FALSE == common_util_bind_sqlite_statement(
						pstmt_insert, 8, type, pvalue)) {
						sqlite3_finalize(pstmt);
						return FALSE;
					}
				}
			} else {
				sqlite3_bind_int64(pstmt_insert, 7, 0);
				sqlite3_bind_null(pstmt_insert, 8);
			}
			sqlite3_bind_int64(pstmt_insert, 10, prev_id);
			if (SQLITE_DONE != sqlite3_step(pstmt_insert)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
			prev_id = sqlite3_last_insert_rowid(pdb->tables.psqlite);
			sqlite3_reset(pstmt_insert);
		}
		sqlite3_finalize(pstmt);
		return TRUE;
	}
	tmp_proptag = psorts->psort[depth].propid;
	tmp_proptag <<= 16;
	tmp_proptag |= psorts->psort[depth].type;
	if (depth == psorts->ccategories - 1 &&
		psorts->count > psorts->ccategories
		&& (TABLE_SORT_MAXIMUM_CATEGORY ==
		psorts->psort[depth + 1].table_sort ||
		TABLE_SORT_MINIMUM_CATEGORY ==
		psorts->psort[depth + 1].table_sort)) {
		b_extremum = TRUE;
		tmp_proptag1 = psorts->psort[depth + 1].propid;
		tmp_proptag1 <<= 16;
		tmp_proptag1 |= psorts->psort[depth + 1].type;
		if (TABLE_SORT_MAXIMUM_CATEGORY ==
			psorts->psort[depth + 1].table_sort) {
			sql_len = snprintf(sql_string, sizeof(sql_string),
					"SELECT v%x, count(*), max(v%x) AS max_field "
					"FROM stbl %s GROUP BY v%x ORDER BY max_field",
					tmp_proptag, tmp_proptag1, where_clause,
					tmp_proptag);
		} else {
			sql_len = snprintf(sql_string, sizeof(sql_string),
					"SELECT v%x, count(*), min(v%x) AS max_field "
					"FROM stbl %s GROUP BY v%x ORDER BY max_field",
					tmp_proptag, tmp_proptag1, where_clause,
					tmp_proptag);	
		}
	} else {
		b_extremum = FALSE;
		sql_len = snprintf(sql_string, sizeof(sql_string),
				"SELECT v%x, count(*) FROM stbl %s GROUP"
				" BY v%x ORDER BY v%x", tmp_proptag,
				where_clause, tmp_proptag, tmp_proptag);
	}
	if (TABLE_SORT_ASCEND == psorts->psort[depth].table_sort) {
		sql_len += snprintf(sql_string + sql_len,
			sizeof(sql_string) - sql_len, " ASC");
	} else {
		sql_len += snprintf(sql_string + sql_len,
			sizeof(sql_string) - sql_len, " DESC");
	}
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		return FALSE;
	}
	bind_index = 1;
	for (i=0,pnode=double_list_get_head(pcondition_list); NULL!=pnode;
		pnode=double_list_get_after(pcondition_list, pnode),i++) {
		if (NULL != ((CONDITION_NODE*)pnode->pdata)->pvalue) {
			if (0x3000 == (psorts->psort[i].type & 0x3000)) {
				type = psorts->psort[i].type & (~0x3000);
			} else {
				type = psorts->psort[i].type;
			}
			if (FALSE == common_util_bind_sqlite_statement(
				pstmt, bind_index, type,
				((CONDITION_NODE*)pnode->pdata)->pvalue)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
			bind_index ++;
		}
	}
	tmp_cnode.node.pdata = &tmp_cnode;
	double_list_append_as_tail(pcondition_list, &tmp_cnode.node);
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		(*pheader_id) ++;
		header_id = *pheader_id | 0x100000000000000ULL;
		sqlite3_bind_int64(pstmt_insert, 1, header_id);
		sqlite3_bind_int64(pstmt_insert, 2, CONTENT_ROW_HEADER);
		if (depth < psorts->cexpanded) {
			sqlite3_bind_int64(pstmt_insert, 3, 1);
		} else {
			sqlite3_bind_int64(pstmt_insert, 3, 0);
		}
		sqlite3_bind_int64(pstmt_insert, 4, parent_id);
		sqlite3_bind_int64(pstmt_insert, 5, depth);
		/* total messages */
		sqlite3_bind_int64(pstmt_insert, 6,
			sqlite3_column_int64(pstmt, 1));
		sqlite3_bind_int64(pstmt_insert, 7, 0);
		if (0x3000 == (psorts->psort[depth].type & 0x3000)) {
			type = psorts->psort[depth].type & (~0x3000);
		} else {
			type = psorts->psort[depth].type;
		}
		if (TRUE == b_extremum && NULL != 
			(pvalue = common_util_column_sqlite_statement(
			pstmt, 2, psorts->psort[depth + 1].type))) {
			if (FALSE == common_util_bind_sqlite_statement(pstmt_insert,
				9, psorts->psort[depth + 1].type, pvalue)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
		} else {
			sqlite3_bind_null(pstmt_insert, 9);
		}
		/* pvalue will be recorded in condition list */
		pvalue = common_util_column_sqlite_statement(pstmt, 0, type);
		if (NULL == pvalue) {
			sqlite3_bind_null(pstmt_insert, 8);
		} else {
			if (FALSE == common_util_bind_sqlite_statement(
				pstmt_insert, 8, type, pvalue)) {
				sqlite3_finalize(pstmt);
				return FALSE;
			}
		}
		sqlite3_bind_int64(pstmt_insert, 10, prev_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_insert)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		prev_id = sqlite3_last_insert_rowid(pdb->tables.psqlite);
		sqlite3_reset(pstmt_insert);
		tmp_cnode.proptag = tmp_proptag;
		unread_count = 0;
		tmp_cnode.pvalue = pvalue;
		if (FALSE == table_load_content(pdb, psqlite, psorts,
			depth + 1, prev_id, pcondition_list, pstmt_insert,
			pheader_id, pstmt_update, &unread_count)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sqlite3_bind_int64(pstmt_update, 1, unread_count);
		sqlite3_bind_int64(pstmt_update, 2, prev_id);
		if (SQLITE_DONE != sqlite3_step(pstmt_update)) {
			sqlite3_finalize(pstmt);
			return FALSE;
		}
		sqlite3_reset(pstmt_update);
		*punread_count += unread_count;
	}
	double_list_remove(pcondition_list, &tmp_cnode.node);
	sqlite3_finalize(pstmt);
	return TRUE;
}

/* under public mode username always available for read state */
static BOOL table_load_content_table(DB_ITEM *pdb, uint32_t cpid,
	uint64_t fid_val, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	int i, j;
	int depth;
	int sql_len;
	void *pvalue;
	uint16_t type;
	int tag_count;
	BOOL b_search;
	int multi_index;
	uint64_t row_id;
	uint64_t prev_id;
	sqlite3 *psqlite;
	uint64_t mid_val;
	uint32_t table_id;
	TABLE_NODE *ptnode;
	BOOL b_conversation;
	uint64_t parent_fid;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	uint64_t last_row_id;
	uint32_t tmp_proptag;
	char tmp_string[128];
	char sql_string[1024];
	uint32_t unread_count;
	const char *remote_id;
	DOUBLE_LIST value_list;
	uint32_t tmp_proptags[16];
	RESTRICTION_PROPERTY *pres;
	
	b_conversation = FALSE;
	if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
		if (NULL != prestriction && RESTRICTION_TYPE_PROPERTY
			== prestriction->rt && (pres = prestriction->pres) &&
			RELOP_EQ == pres->relop && PROP_TAG_CONVERSATIONID ==
			pres->proptag && 16 == ((BINARY*)pres->propval.pvalue)->cb) {
			b_conversation = TRUE;
		}
	}
	if (NULL != psorts && psorts->count >
		sizeof(tmp_proptags)/sizeof(uint32_t)) {
		return FALSE;	
	}
	b_search = FALSE;
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	} else {
		sql_len = sprintf(sql_string, "SELECT is_search FROM"
					" folders WHERE folder_id=%llu", fid_val);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			return TRUE;
		}
		if (0 != sqlite3_column_int64(pstmt, 0)) {
			b_search = TRUE;
		}
		sqlite3_finalize(pstmt);
	}
	if (NULL == pdb->tables.psqlite) {
		if (SQLITE_OK != sqlite3_open_v2(":memory:", &pdb->tables.psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			return FALSE;
		}
	}
	if (0 == *ptable_id) {
		pdb->tables.last_id ++;
		table_id = pdb->tables.last_id;
	} else {
		table_id = *ptable_id;
	}
	sqlite3_exec(pdb->tables.psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE t%u "
		"(row_id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"idx INTEGER UNIQUE DEFAULT NULL, "
		"prev_id INTEGER UNIQUE DEFAULT NULL, "
		"inst_id INTEGER NOT NULL, "
		"row_type INTEGER NOT NULL, "
		"row_stat INTEGER DEFAULT NULL, "	/* expanded(1) or collapsed(0) */
		"parent_id INTEGER DEFAULT NULL, "
		"depth INTEGER NOT NULL, "
		"count INTEGER DEFAULT NULL, "
		"unread INTEGER DEFAULT NULL, "
		"inst_num INTEGER NOT NULL, "
		"value NONE DEFAULT NULL, "
		"extremum NONE DEFAULT NULL)",		/* read(unread) for message row */
		table_id, table_id, table_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	if (NULL != psorts && psorts->ccategories > 0) {
		sprintf(sql_string, "CREATE UNIQUE INDEX t%u_1 ON "
			"t%u (inst_id, inst_num)", table_id, table_id);
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "CREATE INDEX t%u_2 ON"
			" t%u (parent_id)", table_id, table_id);
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		sprintf(sql_string, "CREATE INDEX t%u_3 ON t%u"
			" (parent_id, value)", table_id, table_id);
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
	}
	ptnode = malloc(sizeof(TABLE_NODE));
	if (NULL == ptnode) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		return FALSE;
	}
	pstmt = NULL;
	pstmt1 = NULL;
	psqlite = NULL;
	memset(ptnode, 0, sizeof(TABLE_NODE));
	ptnode->node.pdata = ptnode;
	ptnode->table_id = table_id;
	remote_id = exmdb_server_get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (NULL == ptnode->remote_id) {
			goto LOAD_CONTENT_FAIL;
		}
	}
	ptnode->type = TABLE_TYPE_CONTENT;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	ptnode->b_search = b_search;
	ptnode->cpid = cpid;
	if (FALSE == exmdb_server_check_private()) {
		ptnode->username = strdup(username);
		if (NULL == ptnode->username) {
			goto LOAD_CONTENT_FAIL;
		}
	}
	if (NULL != prestriction) {
		ptnode->prestriction = restriction_dup(prestriction);
		if (NULL == ptnode->prestriction) {
			goto LOAD_CONTENT_FAIL;
		}
	}
	if (NULL != psorts) {
		ptnode->psorts = sortorder_set_dup(psorts);
		if (NULL == ptnode->psorts) {
			goto LOAD_CONTENT_FAIL;
		}
		if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
		sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		sql_len = sprintf(sql_string, "CREATE"
			" TABLE stbl (message_id INTEGER");
		tag_count = 0;
		for (i=0; i<psorts->count; i++) {
			tmp_proptag = psorts->psort[i].propid;
			tmp_proptag <<= 16;
			tmp_proptag |= psorts->psort[i].type;
			if (TABLE_SORT_MAXIMUM_CATEGORY ==
				psorts->psort[i].table_sort ||
				TABLE_SORT_MINIMUM_CATEGORY ==
				psorts->psort[i].table_sort) {
				ptnode->extremum_tag = tmp_proptag;
			}
			tmp_proptags[tag_count] = tmp_proptag;
			/* check if proptag is already in the field list */
			if (i >= psorts->ccategories) {
				for (j=tag_count-1; j>=0; j--) {
					if (tmp_proptags[j] == tmp_proptag) {
						break;
					}
				}
				if (j >= 0) {
					continue;
				}
			}
			tag_count ++;
			if (0x3000 == (psorts->psort[i].type & 0x3000)) {
				ptnode->instance_tag = tmp_proptag;
				multi_index = i + 2;
				type = psorts->psort[i].type & (~0x3000);
			} else {
				type = psorts->psort[i].type;
			}
			switch (type) {
			case PROPVAL_TYPE_STRING:
			case PROPVAL_TYPE_WSTRING:
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							", v%x TEXT COLLATE NOCASE", tmp_proptag);
				break;
			case PROPVAL_TYPE_FLOAT:
			case PROPVAL_TYPE_DOUBLE:
			case PROPVAL_TYPE_FLOATINGTIME:
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							", v%x REAL", tmp_proptag);
				break;
			case PROPVAL_TYPE_CURRENCY:
			case PROPVAL_TYPE_LONGLONG:
			case PROPVAL_TYPE_FILETIME:
			case PROPVAL_TYPE_SHORT:
			case PROPVAL_TYPE_LONG:
			case PROPVAL_TYPE_BYTE:
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							", v%x INTEGER", tmp_proptag);
				break;
			case PROPVAL_TYPE_GUID:
			case PROPVAL_TYPE_SVREID:
			case PROPVAL_TYPE_OBJECT:
			case PROPVAL_TYPE_BINARY:
				sql_len += snprintf(sql_string + sql_len,
							sizeof(sql_string) - sql_len,
							", v%x BLOB", tmp_proptag);
				break;
			default:
				goto LOAD_CONTENT_FAIL;
			}
		}
		if (psorts->ccategories > 0) {
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", read_state INTEGER");
		}
		if (0 != ptnode->instance_tag) {
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", inst_num INTEGER");
		}
		sql_string[sql_len] = ')';
		sql_len ++;
		sql_string[sql_len] = '\0';
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
		for (i=0; i<tag_count; i++) {
			tmp_proptag = tmp_proptags[i];
			sprintf(sql_string, "CREATE INDEX stbl_%d"
					" ON stbl (v%x)", i, tmp_proptag);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				goto LOAD_CONTENT_FAIL;
			}
		}
		if (0 == ptnode->instance_tag) {
			sprintf(sql_string, "CREATE UNIQUE INDEX t%u_4 "
					"ON t%u (inst_id)", table_id, table_id);
		} else {
			sprintf(sql_string, "CREATE INDEX t%u_4 "
				"ON t%u (inst_id)", table_id, table_id);
		}
		if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
			sql_string, NULL, NULL, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
		sql_len = sprintf(sql_string, "INSERT INTO stbl VALUES (?");
		for (i=0; i<tag_count; i++) {
			sql_len += snprintf(sql_string + sql_len,
				sizeof(sql_string) - sql_len, ", ?");
		}
		if (psorts->ccategories > 0) {
			sql_len += snprintf(sql_string + sql_len,
				sizeof(sql_string) - sql_len, ", ?");
		}
		if (0 != ptnode->instance_tag) {
			sql_len += snprintf(sql_string + sql_len,
				sizeof(sql_string) - sql_len, ", ?");
		}
		sql_string[sql_len] = ')';
		sql_len ++;
		sql_string[sql_len] = '\0';
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
	} else {
		sql_len = sprintf(sql_string, "INSERT INTO t%u (inst_id,"
			" prev_id, row_type, depth, inst_num, idx) VALUES "
			"(?, ?, %u, 0, 0, ?)", table_id, CONTENT_ROW_MESSAGE);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
	}
	if (TRUE == exmdb_server_check_private()) {
		if (table_flags & TABLE_FLAG_SOFTDELETES) {
			sql_len = sprintf(sql_string, "SELECT "
				"message_id FROM messages WHERE 0");
		} else {
			if (table_flags & TABLE_FLAG_ASSOCIATED) {
				if (FALSE == b_search) {
					sql_len = sprintf(sql_string, "SELECT message_id "
								"FROM messages WHERE parent_fid=%llu "
								"AND is_associated=1", fid_val);
				} else {
					sql_len = sprintf(sql_string, "SELECT "
						"messages.message_id FROM messages"
						" JOIN search_result ON "
						"search_result.folder_id=%llu AND "
						"search_result.message_id=messages.message_id"
						" AND messages.is_associated=1", fid_val);
				}
			} else {
				if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
					if (TRUE == b_conversation) {
						encode_hex_binary(((BINARY*)pres->propval.pvalue)->pb,
										16, tmp_string, sizeof(tmp_string));
						sql_len = sprintf(sql_string, "SELECT message_id "
							"FROM message_properties WHERE proptag=%u AND"
							" propval=x'%s'", PROP_TAG_CONVERSATIONID,
							tmp_string);
					} else {
						sql_len = sprintf(sql_string, "SELECT message_id"
							" FROM messages WHERE parent_fid IS NOT NULL"
							" AND is_associated=0");
					}
				} else {
					if (FALSE == b_search) {
						sql_len = sprintf(sql_string, "SELECT message_id "
									"FROM messages WHERE parent_fid=%llu "
									"AND is_associated=0", fid_val);
					} else {
						sql_len = sprintf(sql_string, "SELECT "
							"messages.message_id FROM messages"
							" JOIN search_result ON "
							"search_result.folder_id=%llu AND "
							"search_result.message_id=messages.message_id"
							" AND messages.is_associated=0", fid_val);
					}
				}
			}
		}
	} else {
		if (table_flags & TABLE_FLAG_CONVERSATIONMEMBERS) {
			if (TRUE == b_conversation) {
				encode_hex_binary(((BINARY*)pres->propval.pvalue)->pb,
									16, tmp_string, sizeof(tmp_string));
				if (table_flags & TABLE_FLAG_SOFTDELETES) {
					sql_len = sprintf(sql_string,
						"SELECT message_properties.message_id "
						"FROM message_properties JOIN messages ON "
						"messages.message_id=message_properties.message_id"
						" WHERE message_properties.proptag=%u AND"
						" message_properties.propval=x'%s' AND "
						"messages.is_deleted=1", PROP_TAG_CONVERSATIONID,
						tmp_string);
				} else {
					sql_len = sprintf(sql_string,
						"SELECT message_properties.message_id "
						"FROM message_properties JOIN messages ON "
						"messages.message_id=message_properties.message_id"
						" WHERE message_properties.proptag=%u AND"
						" message_properties.propval=x'%s' AND "
						"messages.is_deleted=0", PROP_TAG_CONVERSATIONID,
						tmp_string);
				}
			} else {
				if (table_flags & TABLE_FLAG_SOFTDELETES) {
					sql_len = sprintf(sql_string, "SELECT message_id"
						" FROM messages WHERE parent_fid IS NOT NULL"
						" AND is_associated=0 AND is_deleted=1");
				} else {
					sql_len = sprintf(sql_string, "SELECT message_id"
						" FROM messages WHERE parent_fid IS NOT NULL"
						" AND is_associated=0 AND is_deleted=0");
				}
			}
		} else {
			sql_len = sprintf(sql_string, "SELECT message_id "
				"FROM messages WHERE parent_fid=%llu", fid_val);
			if (table_flags & TABLE_FLAG_SOFTDELETES) {
				sql_len += sprintf(sql_string + sql_len,
								" AND is_deleted=1");
			} else {
				sql_len += sprintf(sql_string + sql_len,
								" AND is_deleted=0");
			}
			if (table_flags & TABLE_FLAG_ASSOCIATED) {
				sql_len += sprintf(sql_string + sql_len,
								" AND is_associated=1");
			} else {
				sql_len += sprintf(sql_string + sql_len,
								" AND is_associated=0");
			}
		}
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		goto LOAD_CONTENT_FAIL;
	}
	last_row_id = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		mid_val = sqlite3_column_int64(pstmt, 0);
		if (TRUE == b_conversation) {
			if (TRUE == common_util_check_message_associated(
				pdb->psqlite, mid_val)) {
				continue;
			}
			if (FALSE == common_util_get_message_parent_folder(
				pdb->psqlite, mid_val, &parent_fid)) {
				goto LOAD_CONTENT_FAIL;
			}
			if (0 == parent_fid) {
				continue;
			}
		} else {
			if (NULL != prestriction) {
				if (FALSE == common_util_evaluate_message_restriction(
					pdb->psqlite, cpid, mid_val, prestriction)) {
					continue;
				}
			}
		}
		sqlite3_bind_int64(pstmt1, 1, mid_val);
		if (NULL != psorts) {
			for (i=0; i<tag_count; i++) {
				tmp_proptag = tmp_proptags[i];
				if (tmp_proptag == ptnode->instance_tag) {
					continue;
				}
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, mid_val,
					cpid, pdb->psqlite, tmp_proptag,
					&pvalue)) {
					goto LOAD_CONTENT_FAIL;
				}
				if (NULL == pvalue) {
					sqlite3_bind_null(pstmt1, i + 2);
				} else {
					if (FALSE == common_util_bind_sqlite_statement(
						pstmt1, i + 2, tmp_proptag & 0xFFFF,
						pvalue)) {
						goto LOAD_CONTENT_FAIL;	
					}
				}
			}
			if (psorts->ccategories > 0) {
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, mid_val, 0,
					pdb->psqlite, PROP_TAG_READ, &pvalue)) {
					goto LOAD_CONTENT_FAIL;
				}
				if (NULL == pvalue || 0 == *(uint8_t*)pvalue) {
					sqlite3_bind_int64(pstmt1, tag_count + 2, 0);
				} else {
					sqlite3_bind_int64(pstmt1, tag_count + 2, 1);
				}
			}
			/* inssert all instances into stbl */
			if (0 != ptnode->instance_tag) {
				type = ptnode->instance_tag & 0xFFFF;
				type &= ~0x2000;
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, mid_val, cpid, pdb->psqlite,
					ptnode->instance_tag & (~0x2000), &pvalue)) {
					goto LOAD_CONTENT_FAIL;
				}
				if (NULL == pvalue) {
BIND_NULL_INSTANCE:
					sqlite3_bind_null(pstmt1, multi_index);
					sqlite3_bind_int64(pstmt1, tag_count + 3, 0);
					if (SQLITE_DONE != sqlite3_step(pstmt1)) {
						goto LOAD_CONTENT_FAIL;
					}
					sqlite3_reset(pstmt1);
					continue;
				}
				switch (type) {
				case PROPVAL_TYPE_SHORT_ARRAY:
					if (0 == ((SHORT_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((SHORT_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_SHORT,
							((SHORT_ARRAY*)pvalue)->ps + i)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				case PROPVAL_TYPE_LONG_ARRAY:
					if (0 == ((LONG_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((LONG_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_LONG,
							((LONG_ARRAY*)pvalue)->pl + i)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				case PROPVAL_TYPE_LONGLONG_ARRAY:
					if (0 == ((LONGLONG_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((LONGLONG_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_LONGLONG,
							((LONGLONG_ARRAY*)pvalue)->pll + i)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				case PROPVAL_TYPE_STRING_ARRAY:
				case PROPVAL_TYPE_WSTRING_ARRAY:
					if (0 == ((STRING_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_STRING,
							((STRING_ARRAY*)pvalue)->ppstr[i])) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				case PROPVAL_TYPE_GUID_ARRAY:
					if (0 == ((GUID_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((GUID_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_GUID,
							((GUID_ARRAY*)pvalue)->pguid + i)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				case PROPVAL_TYPE_BINARY_ARRAY:
					if (0 == ((BINARY_ARRAY*)pvalue)->count) {
						goto BIND_NULL_INSTANCE;
					}
					for (i=0; i<((BINARY_ARRAY*)pvalue)->count; i++) {
						if (FALSE == common_util_bind_sqlite_statement(
							pstmt1, multi_index, PROPVAL_TYPE_BINARY,
							((BINARY_ARRAY*)pvalue)->pbin + i)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_bind_int64(pstmt1,
							tag_count + 3, i + 1);
						if (SQLITE_DONE != sqlite3_step(pstmt1)) {
							goto LOAD_CONTENT_FAIL;
						}
						sqlite3_reset(pstmt1);
					}
					break;
				default:
					goto LOAD_CONTENT_FAIL;
				}
				continue;
			}
		} else {
			sqlite3_bind_int64(pstmt1, 2, last_row_id);
			sqlite3_bind_int64(pstmt1, 3, last_row_id + 1);
		}
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			goto LOAD_CONTENT_FAIL;
		}
		if (NULL == psorts) {
			last_row_id = sqlite3_last_insert_rowid(pdb->tables.psqlite);
		}
		sqlite3_reset(pstmt1);
	}
	if (NULL != psorts) {
		sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	}
	sqlite3_finalize(pstmt);
	pstmt = NULL;
	sqlite3_finalize(pstmt1);
	pstmt1 = NULL;
	if (NULL != psorts) {
		sql_len = sprintf(sql_string, "INSERT INTO t%u "
			"(inst_id, row_type, row_stat, parent_id, depth, "
			"count, inst_num, value, extremum, prev_id) VALUES"
			" (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
		sql_len = sprintf(sql_string, "UPDATE t%u SET"
				" unread=? WHERE row_id=?", table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			goto LOAD_CONTENT_FAIL;
		}
		double_list_init(&value_list);
		if (FALSE == table_load_content(pdb,
			psqlite, psorts, 0, 0, &value_list, pstmt,
			&ptnode->header_id, pstmt1, &unread_count)) {
			goto LOAD_CONTENT_FAIL;	
		}
		sqlite3_finalize(pstmt);
		pstmt = NULL;
		sqlite3_finalize(pstmt1);
		pstmt1 = NULL;
		sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		psqlite = NULL;
		/* index the content table */
		if (psorts->ccategories > 0) {
			sql_len = sprintf(sql_string, "SELECT row_id,"
				" row_type, row_stat, depth, prev_id FROM"
				" t%u ORDER BY row_id", table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt, NULL)) {
				goto LOAD_CONTENT_FAIL;
			}
			sql_len = sprintf(sql_string, "UPDATE t%u SET "
					"idx=? WHERE row_id=?", table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				goto LOAD_CONTENT_FAIL;
			}
			i = 1;
			prev_id = 0;
			while (SQLITE_ROW == sqlite3_step(pstmt)) {
				if (0 != prev_id &&
					depth < sqlite3_column_int64(pstmt, 3) &&
					prev_id != sqlite3_column_int64(pstmt, 4)) {
					continue;
				}
				row_id = sqlite3_column_int64(pstmt, 0);
				if (CONTENT_ROW_HEADER == sqlite3_column_int64(pstmt, 1)) {
					if (0 == sqlite3_column_int64(pstmt, 2)) {
						prev_id = row_id;
						depth = sqlite3_column_int64(pstmt, 3);
					} else {
						prev_id = 0;
					}
				}
				sqlite3_bind_int64(pstmt1, 1, i);
				sqlite3_bind_int64(pstmt1, 2, row_id);
				if (SQLITE_DONE != sqlite3_step(pstmt1)) {
					goto LOAD_CONTENT_FAIL;
				}
				sqlite3_reset(pstmt1);
				i ++;
			}
			sqlite3_finalize(pstmt);
			pstmt = NULL;
			sqlite3_finalize(pstmt1);
			pstmt1 = NULL;
		} else {
			sprintf(sql_string, "UPDATE t%u SET idx=row_id", table_id);
			if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
				sql_string, NULL, NULL, NULL)) {
				goto LOAD_CONTENT_FAIL;	
			}
		}
	}
	sqlite3_exec(pdb->tables.psqlite,
		"COMMIT TRANSACTION", NULL, NULL, NULL);
	double_list_append_as_tail(&pdb->tables.table_list, &ptnode->node);
	if (0 == *ptable_id) {
		*ptable_id = table_id;
	}
	*prow_count = 0;
	table_sum_table_count(pdb, table_id, prow_count); 
	return TRUE;
	
LOAD_CONTENT_FAIL:
	if (NULL != pstmt) {
		sqlite3_finalize(pstmt);
	}
	if (NULL != pstmt1) {
		sqlite3_finalize(pstmt1);
	}
	if (NULL != psqlite) {
		sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(psqlite);
	}
	if (NULL != ptnode->psorts) {
		sortorder_set_free(ptnode->psorts);
	}
	if (NULL != ptnode->prestriction) {
		restriction_free(ptnode->prestriction);
	}
	if (NULL != ptnode->username) {
		free(ptnode->username);
	}
	if (NULL != ptnode->remote_id) {
		free(ptnode->remote_id);
	}
	free(ptnode);
	sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
	return FALSE;
}

BOOL exmdb_server_load_content_table(const char *dir, uint32_t cpid,
	uint64_t folder_id, const char *username, uint8_t table_flags,
	const RESTRICTION *prestriction, const SORTORDER_SET *psorts,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	DB_ITEM *pdb;
	uint64_t fid_val;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*ptable_id = 0;
	fid_val = rop_util_get_gc_value(folder_id);
	if (FALSE == table_load_content_table(pdb, cpid,
		fid_val, username, table_flags, prestriction,
		psorts, ptable_id, prow_count)) {
		db_engine_put_db(pdb);
		return FALSE;	
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_reload_content_table(const char *dir, uint32_t table_id)
{
	DB_ITEM *pdb;
	BOOL b_result;
	uint32_t row_count;
	TABLE_NODE *ptnode;
	char sql_string[128];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (TABLE_TYPE_CONTENT == ((TABLE_NODE*)pnode->pdata)->type
			&& table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			double_list_remove(&pdb->tables.table_list, pnode);
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	sprintf(sql_string, "DROP TABLE t%u", table_id);
	sqlite3_exec(pdb->tables.psqlite, sql_string, NULL, NULL, NULL);
	b_result = table_load_content_table(pdb, ptnode->cpid,
			ptnode->folder_id, ptnode->username, ptnode->table_flags,
			ptnode->prestriction, ptnode->psorts, &table_id,
			&row_count);
	if (NULL != ptnode->remote_id) {
		free(ptnode->remote_id);
	}
	if (NULL != ptnode->username) {
		free(ptnode->username);
	}
	if (NULL != ptnode->prestriction) {
		restriction_free(ptnode->prestriction);
	}
	if (NULL != ptnode->psorts) {
		sortorder_set_free(ptnode->psorts);
	}
	free(ptnode);
	db_engine_notify_content_table_reload(pdb, table_id);
	db_engine_put_db(pdb);
	return b_result;
}

static BOOL table_load_permissions(sqlite3 *psqlite,
	uint64_t folder_id, sqlite3_stmt *pstmt, uint32_t *prow_count)
{
	int sql_len;
	BOOL b_default;
	BOOL b_anonymous;
	uint64_t member_id;
	uint32_t permission;
	char sql_string[256];
	sqlite3_stmt *pstmt1;
	const char *pusername;
	
	sql_len = sprintf(sql_string, "SELECT member_id, username"
		" FROM permissions WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		return FALSE;
	}
	b_default = FALSE;
	b_anonymous = FALSE;
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		member_id = sqlite3_column_int64(pstmt1, 0);
		sqlite3_bind_int64(pstmt, 1, member_id);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		(*prow_count) ++;
		sqlite3_reset(pstmt);
		if (SQLITE_NULL == sqlite3_column_type(pstmt1, 1)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		pusername = sqlite3_column_text(pstmt1, 1);
		if ('\0' == pusername[0]) {
			b_anonymous = TRUE;
		} else if (0 == strcasecmp("default", pusername)) {
			b_default = TRUE;
		}
	}
	if (FALSE == b_default) {
		sqlite3_bind_int64(pstmt, 1, 0);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	if (FALSE == b_anonymous) {
		sqlite3_bind_int64(pstmt, 1, -1);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	sqlite3_finalize(pstmt1);
	return TRUE;
}

BOOL exmdb_server_load_permission_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t fid_val;
	uint32_t table_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	const char *remote_id;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (NULL == pdb->tables.psqlite) {
		if (SQLITE_OK != sqlite3_open_v2(":memory:", &pdb->tables.psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	pdb->tables.last_id ++;
	table_id = pdb->tables.last_id;
	/* begin the transaction */
	sqlite3_exec(pdb->tables.psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE t%u (idx INTEGER PRIMARY KEY "
		"AUTOINCREMENT, member_id INTEGER UNIQUE NOT NULL)", table_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	ptnode = malloc(sizeof(TABLE_NODE));
	if (NULL == ptnode) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	memset(ptnode, 0, sizeof(TABLE_NODE));
	ptnode->node.pdata = ptnode;
	ptnode->table_id = table_id;
	remote_id = exmdb_server_get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (NULL == ptnode->remote_id) {
			free(ptnode);
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	ptnode->type = TABLE_TYPE_PERMISSION;
	ptnode->folder_id = fid_val;
	ptnode->table_flags = table_flags;
	sql_len = sprintf(sql_string, "INSERT INTO t%u "
		"(member_id) VALUES (?)", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	*prow_count = 0;
	if (FALSE == table_load_permissions(pdb->psqlite,
		fid_val, pstmt, prow_count)) {
		sqlite3_finalize(pstmt);
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(pdb->tables.psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	double_list_append_as_tail(&pdb->tables.table_list, &ptnode->node);
	*ptable_id = ptnode->table_id;
	db_engine_put_db(pdb);
	return TRUE;
}

static BOOL table_evaluate_rule_restriction(sqlite3 *psqlite,
	uint64_t rule_id, const RESTRICTION *pres)
{
	int i;
	int len;
	int sql_len;
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RESTRICTION_TYPE_OR:
	case RESTRICTION_TYPE_AND:
		for (i=0; i<((RESTRICTION_AND_OR*)pres->pres)->count; i++) {
			if (FALSE == table_evaluate_rule_restriction(psqlite,
				rule_id, ((RESTRICTION_AND_OR*)pres->pres)->pres + i)) {
				return FALSE;
			}
		}
		return TRUE;
	case RESTRICTION_TYPE_NOT:
		if (TRUE == table_evaluate_rule_restriction(psqlite,
			rule_id, &((RESTRICTION_NOT*)pres->pres)->res)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_CONTENT:
		if (PROPVAL_TYPE_WSTRING != (((RESTRICTION_CONTENT*)
			pres->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if ((((RESTRICTION_CONTENT*)pres->pres)->proptag & 0xFFFF) !=
			(((RESTRICTION_CONTENT*)pres->pres)->propval.proptag & 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_CONTENT*)pres->pres)->proptag, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level & 0xFFFF) {
		case FUZZY_LEVEL_FULLSTRING:
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strcasecmp(((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strcmp(((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case FUZZY_LEVEL_SUBSTRING:
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (NULL != strstr(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		case FUZZY_LEVEL_PREFIX:
			len = strlen(((RESTRICTION_CONTENT*)pres->pres)->propval.pvalue);
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strncasecmp(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strncmp(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	case RESTRICTION_TYPE_PROPERTY:
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_PROPERTY*) pres->pres)->proptag, &pvalue)
			|| NULL == pvalue) {
			return FALSE;
		}
		if (PROP_TAG_ANR == ((RESTRICTION_PROPERTY*)pres->pres)->proptag) {
			if ((((RESTRICTION_PROPERTY*)pres->pres)->propval.proptag
				& 0xFFFF) != PROPVAL_TYPE_WSTRING) {
				return FALSE;
			}
			if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
				pres->pres)->propval.pvalue)) {
				return TRUE;
			}
			return FALSE;
		}
		return propval_compare_relop(
				((RESTRICTION_PROPERTY*)pres->pres)->relop,
				((RESTRICTION_PROPERTY*)pres->pres)->proptag&0xFFFF,
				pvalue, ((RESTRICTION_PROPERTY*)pres->pres)->propval.pvalue);
	case RESTRICTION_TYPE_PROPCOMPARE:
		if ((((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1&0xFFFF) !=
			(((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2&0xFFFF)) {
			return FALSE;
		}
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1, &pvalue)
			|| NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2, &pvalue1)
			|| NULL == pvalue1) {
			return FALSE;
		}
		return propval_compare_relop(
				((RESTRICTION_PROPCOMPARE*)pres->pres)->relop,
				((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1&0xFFFF,
				pvalue, pvalue1);
	case RESTRICTION_TYPE_BITMASK:
		if (PROPVAL_TYPE_LONG != (((RESTRICTION_BITMASK*)
			pres->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_BITMASK*)pres->pres)->proptag, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_BITMASK*)pres->pres)->bitmask_relop) {
		case BITMASK_RELOP_EQZ:
			if (0 == (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pres->pres)->mask)) {
				return TRUE;
			}
			break;
		case BITMASK_RELOP_NEZ:
			if (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pres->pres)->mask) {
				return TRUE;
			}
			break;
		}	
		return FALSE;
	case RESTRICTION_TYPE_SIZE:
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_SIZE*)pres->pres)->proptag, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		val_size = propval_size(((RESTRICTION_SIZE*)
					pres->pres)->proptag, pvalue);
		return propval_compare_relop(((RESTRICTION_SIZE*)
				pres->pres)->relop, PROPVAL_TYPE_LONG, &val_size,
				&((RESTRICTION_SIZE*)pres->pres)->size);
	case RESTRICTION_TYPE_EXIST:
		if (FALSE == common_util_get_rule_property(rule_id, psqlite,
			((RESTRICTION_EXIST*)pres->pres)->proptag, &pvalue) ||
			NULL == pvalue) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_SUBOBJ:
		return FALSE;
	case RESTRICTION_TYPE_COMMENT:
		if (NULL == ((RESTRICTION_COMMENT*)pres->pres)->pres) {
			return TRUE;
		}
		return table_evaluate_rule_restriction(psqlite, rule_id,
				((RESTRICTION_COMMENT*)pres->pres)->pres);
	case RESTRICTION_TYPE_COUNT:
		return FALSE;
	}	
	return FALSE;
}

static BOOL table_load_rules(sqlite3 *psqlite, uint64_t folder_id,
	uint8_t table_flags, const RESTRICTION *prestriction,
	sqlite3_stmt *pstmt, uint32_t *prow_count)
{
	int sql_len;
	uint64_t rule_id;
	char sql_string[80];
	uint32_t permission;
	sqlite3_stmt *pstmt1;
	
	sql_len = sprintf(sql_string, "SELECT rule_id FROM "
				"rules WHERE folder_id=%llu", folder_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		rule_id = sqlite3_column_int64(pstmt1, 0);
		if (NULL != prestriction) {
			if (FALSE == table_evaluate_rule_restriction(
				psqlite, rule_id, prestriction)) {
				continue;
			}
		}
		sqlite3_bind_int64(pstmt, 1, rule_id);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt1);
			return FALSE;
		}
		(*prow_count) ++;
		sqlite3_reset(pstmt);
	}
	sqlite3_finalize(pstmt1);
	return TRUE;
}

BOOL exmdb_server_load_rule_table(const char *dir,
	uint64_t folder_id, uint8_t table_flags,
	const RESTRICTION *prestriction,
	uint32_t *ptable_id, uint32_t *prow_count)
{
	int sql_len;
	DB_ITEM *pdb;
	uint64_t fid_val;
	uint32_t table_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	const char *remote_id;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	fid_val = rop_util_get_gc_value(folder_id);
	if (NULL == pdb->tables.psqlite) {
		if (SQLITE_OK != sqlite3_open_v2(":memory:", &pdb->tables.psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	pdb->tables.last_id ++;
	table_id = pdb->tables.last_id;
	/* begin the transaction */
	sqlite3_exec(pdb->tables.psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sprintf(sql_string, "CREATE TABLE t%u (idx INTEGER PRIMARY KEY "
		"AUTOINCREMENT, rule_id INTEGER UNIQUE NOT NULL)", table_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	ptnode = malloc(sizeof(TABLE_NODE));
	if (NULL == ptnode) {
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	memset(ptnode, 0, sizeof(TABLE_NODE));
	ptnode->node.pdata = ptnode;
	ptnode->table_id = table_id;
	remote_id = exmdb_server_get_remote_id();
	if (NULL != remote_id) {
		ptnode->remote_id = strdup(remote_id);
		if (NULL == ptnode->remote_id) {
			free(ptnode);
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	ptnode->type = TABLE_TYPE_RULE;
	ptnode->folder_id = fid_val;
	if (NULL != prestriction) {
		ptnode->prestriction = restriction_dup(prestriction);
		if (NULL == ptnode->prestriction) {
			if (NULL != ptnode->remote_id) {
				free(ptnode->remote_id);
			}
			free(ptnode);
			sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sql_len = sprintf(sql_string, "INSERT INTO t%u "
		"(rule_id) VALUES (?)", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		if (NULL != ptnode->prestriction) {
			restriction_free(ptnode->prestriction);
		}
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	*prow_count = 0;
	if (FALSE == table_load_rules(pdb->psqlite,
		fid_val, table_flags, prestriction,
		pstmt, prow_count)) {
		sqlite3_finalize(pstmt);
		if (NULL != ptnode->prestriction) {
			restriction_free(ptnode->prestriction);
		}
		if (NULL != ptnode->remote_id) {
			free(ptnode->remote_id);
		}
		free(ptnode);
		sqlite3_exec(pdb->tables.psqlite, "ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(pdb->tables.psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	double_list_append_as_tail(&pdb->tables.table_list, &ptnode->node);
	*ptable_id = ptnode->table_id;
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_unload_table(const char *dir, uint32_t table_id)
{
	DB_ITEM *pdb;
	TABLE_NODE *ptnode;
	char sql_string[128];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			double_list_remove(&pdb->tables.table_list, pnode);
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	sprintf(sql_string, "DROP TABLE t%u", table_id);
	sqlite3_exec(pdb->tables.psqlite, sql_string, NULL, NULL, NULL);
	if (NULL != ptnode->remote_id) {
		free(ptnode->remote_id);
	}
	if (NULL != ptnode->username) {
		free(ptnode->username);
	}
	if (NULL != ptnode->prestriction) {
		restriction_free(ptnode->prestriction);
	}
	if (NULL != ptnode->psorts) {
		sortorder_set_free(ptnode->psorts);
	}
	free(ptnode);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_sum_table(const char *dir,
	uint32_t table_id, uint32_t *prows)
{
	DB_ITEM *pdb;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == table_sum_table_count(pdb, table_id, prows)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

static BOOL table_column_content_tmptbl(
	sqlite3_stmt *pstmt, sqlite3_stmt *pstmt1, sqlite3_stmt *pstmt2,
	const SORTORDER_SET *psorts, uint64_t folder_id, int row_type,
	uint32_t proptag, uint32_t instance_tag, uint32_t extremum_tag,
	void **ppvalue)
{
	int i;
	int depth;
	uint64_t row_id;
	uint32_t tmp_proptag;
	
	switch (proptag) {
	case PROP_TAG_FOLDERID:
		if (CONTENT_ROW_HEADER == row_type) {
			*ppvalue = common_util_alloc(sizeof(uint64_t));
			if (NULL != *ppvalue) {
				*(uint64_t*)*ppvalue =
					rop_util_make_eid_ex(1, folder_id);
			}
			return TRUE;
		}
		break;
	case PROP_TAG_INSTID:
		*ppvalue = common_util_column_sqlite_statement(
						pstmt, 3, PROPVAL_TYPE_LONGLONG);
		if (*ppvalue != NULL) {
			if (CONTENT_ROW_MESSAGE == row_type) {
				*(uint64_t*)*ppvalue = rop_util_make_eid_ex(
									1, *(uint64_t*)*ppvalue);
			} else {
				*(uint64_t*)*ppvalue = rop_util_make_eid_ex(2,
					*(uint64_t*)*ppvalue & 0x00FFFFFFFFFFFFFFULL);
			}
		}
		return TRUE;
	case PROP_TAG_INSTANCENUM:
		*ppvalue = common_util_column_sqlite_statement(
					pstmt, 10, PROPVAL_TYPE_LONG);
		return TRUE;
	case PROP_TAG_ROWTYPE:
		if (NULL == psorts || 0 == psorts->ccategories) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return TRUE;
		}
		if (CONTENT_ROW_MESSAGE == row_type) {
			*(uint32_t*)*ppvalue = ROW_TYPE_LEAF_ROW;
		} else {
			if (0 == sqlite3_column_int64(pstmt, 8)) {
				*(uint32_t*)*ppvalue = ROW_TYPE_EMPTY_CATEGORY;
			} else {
				if (0 == sqlite3_column_int64(pstmt, 5)) {
					*(uint32_t*)*ppvalue = ROW_TYPE_COLLAPSED_CATEGORY;
				} else {
					*(uint32_t*)*ppvalue = ROW_TYPE_EXPANDED_CATEGORY;
				}
			}
		}
		return TRUE;
	case PROP_TAG_DEPTH:
		if (NULL == psorts || 0 == psorts->ccategories) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = common_util_column_sqlite_statement(
					pstmt, 7, PROPVAL_TYPE_LONG);
		return TRUE;
	case PROP_TAG_CONTENTCOUNT:
		if (CONTENT_ROW_MESSAGE == row_type) {
			*ppvalue = common_util_alloc(sizeof(uint32_t));
			if (NULL != *ppvalue) {
				*(uint32_t*)*ppvalue = 0;
			}
		} else {
			*ppvalue = common_util_column_sqlite_statement(
							pstmt, 8, PROPVAL_TYPE_LONG);
		}
		return TRUE;
	case PROP_TAG_CONTENTUNREADCOUNT:
		if (CONTENT_ROW_MESSAGE == row_type) {
			*ppvalue = common_util_alloc(sizeof(uint32_t));
			if (NULL != *ppvalue) {
				*(uint32_t*)*ppvalue = 0;
			}
		} else {
			*ppvalue = common_util_column_sqlite_statement(
							pstmt, 9, PROPVAL_TYPE_LONG);
		}
		return TRUE;
	}
	if (CONTENT_ROW_MESSAGE == row_type) {
		if (0 != instance_tag && instance_tag == proptag) {
			*ppvalue = common_util_column_sqlite_statement(
				pstmt, 11, instance_tag & 0xFFFF & (~0x3000));
			return TRUE;
		}
		return FALSE;
	}
	if (NULL == psorts || 0 == psorts->ccategories) {
		return FALSE;
	}
	if (extremum_tag == proptag) {
		*ppvalue = common_util_column_sqlite_statement(
							pstmt, 12, proptag & 0xFFFF);
		return TRUE;
	}
	for (i=psorts->ccategories-1; i>=0; i--) {
		tmp_proptag = psorts->psort[i].propid;
		tmp_proptag <<= 16;
		tmp_proptag |= psorts->psort[i].type;
		if (proptag == tmp_proptag) {
			break;
		}
	}
	if (i < 0) {
		return FALSE;
	}
	depth = sqlite3_column_int64(pstmt, 7);
	if (i > depth) {
		return FALSE;
	}
	row_id = sqlite3_column_int64(pstmt, 0);
	for (; depth>i; depth--) {
		sqlite3_bind_int64(pstmt1, 1, row_id);
		if (SQLITE_ROW != sqlite3_step(pstmt1)) {
			return FALSE;
		}
		row_id = sqlite3_column_int64(pstmt1, 0);
		sqlite3_reset(pstmt1);
	}
	sqlite3_bind_int64(pstmt2, 1, row_id);
	if (SQLITE_ROW != sqlite3_step(pstmt2)) {
		return FALSE;
	}
	if (0x3000 == (proptag & 0x3000)) {
		*ppvalue = common_util_column_sqlite_statement(
			pstmt2, 0, proptag & 0xFFFF & (~0x3000));
	} else {
		*ppvalue = common_util_column_sqlite_statement(
					pstmt2, 0, proptag & 0xFFFF);
	}
	sqlite3_reset(pstmt2);
	return TRUE;
}

static void table_truncate_string(uint32_t cpid, char *pstring)
{
	size_t in_len;
	size_t out_len;
	int string_len;
	iconv_t conv_id;
	char *pin, *pout;
	char tmp_buff[512];
	const char *charset;
	char tmp_charset[256];
	
	string_len = strlen(pstring);
	if (string_len <= 510) {
		return;
	}
	string_len ++;
	pstring[510] = '\0';
	charset = common_util_cpid_to_charset(cpid);
	if (NULL == charset) {
		return;
	}
	in_len = string_len;
	out_len = sizeof(tmp_buff);
	pin = pstring;
	pout = tmp_buff;
	memset(tmp_buff, 0, sizeof(tmp_buff));
	sprintf(tmp_charset, "%s//IGNORE", charset);
	conv_id = iconv_open(tmp_charset, charset);
	iconv(conv_id, &pin, &in_len, &pout, &out_len);
	iconv_close(conv_id);
	if (out_len < sizeof(tmp_buff)) {
		strcpy(pstring, tmp_buff);
	}
}

/* every property value returned in a row MUST
	be less than or equal to 510 bytes in size!!! */
BOOL exmdb_server_query_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint32_t start_pos, int32_t row_needed, TARRAY_SET *pset)
{
	int i;
	int count;
	int sql_len;
	DB_ITEM *pdb;
	void *pvalue;
	int row_type;
	int32_t end_pos;
	uint32_t proptag;
	uint64_t rule_id;
	uint64_t inst_id;
	uint64_t member_id;
	uint64_t folder_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	pset->count = 0;
	pset->pparray = NULL;
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	switch (ptnode->type) {
	case TABLE_TYPE_HIERARCHY:
		if (row_needed > 0) {
			end_pos = start_pos + row_needed;
			sql_len = sprintf(sql_string, "SELECT folder_id, depth FROM"
						" t%u WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
						table_id, start_pos + 1, end_pos + 1);
			pset->pparray = common_util_alloc(sizeof(void*)*row_needed);
		} else {
			end_pos = start_pos + row_needed;
			if (end_pos < 0) {
				end_pos = 0;
			}
			sql_len = sprintf(sql_string, "SELECT folder_id, depth FROM "
						"t%u WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
						table_id, end_pos + 1, start_pos + 1);
			pset->pparray = common_util_alloc(
				sizeof(void*)*(start_pos - end_pos));
		}
		if (NULL == pset->pparray) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			folder_id = sqlite3_column_int64(pstmt, 0);
			pset->pparray[pset->count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == pset->pparray[pset->count]) {
				sqlite3_finalize(pstmt);
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
			pset->pparray[pset->count]->count = 0;
			pset->pparray[pset->count]->ppropval =
				common_util_alloc(sizeof(TAGGED_PROPVAL)*pproptags->count);
			if (NULL == pset->pparray[pset->count]->ppropval) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				return FALSE;
			}
			count = 0;
			for (i=0; i<pproptags->count; i++) {
				if (PROP_TAG_DEPTH == pproptags->pproptag[i]) {
					pvalue = common_util_alloc(sizeof(uint32_t));
					if (NULL == pvalue) {
						sqlite3_finalize(pstmt);
						sqlite3_exec(pdb->psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						db_engine_put_db(pdb);
						return FALSE;
					}
					*(uint32_t*)pvalue = sqlite3_column_int64(pstmt, 1);
				} else {
					if (FALSE == common_util_get_property(
						FOLDER_PROPERTIES_TABLE, folder_id, cpid,
						pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
						sqlite3_finalize(pstmt);
						sqlite3_exec(pdb->psqlite,
							"ROLLBACK", NULL, NULL, NULL);
						db_engine_put_db(pdb);
						return FALSE;
					}
					if (NULL == pvalue) {
						continue;
					}
					switch (pproptags->pproptag[i] & 0xFFFF) {
					case PROPVAL_TYPE_WSTRING:
						utf8_truncate(pvalue, 255);
						break;
					case PROPVAL_TYPE_STRING:
						table_truncate_string(cpid, pvalue);
						break;
					case PROPVAL_TYPE_BINARY:
						if (((BINARY*)pvalue)->cb > 510) {
							((BINARY*)pvalue)->cb = 510;
						}
						break;
					}
				}
				pset->pparray[pset->count]->ppropval[count].proptag =
													pproptags->pproptag[i];
				pset->pparray[pset->count]->ppropval[count].pvalue = pvalue;
				count ++;
			}
			pset->pparray[pset->count]->count = count;
			pset->count ++;
		}
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		break;
	case TABLE_TYPE_CONTENT:
		if (row_needed > 0) {
			end_pos = start_pos + row_needed;
			sql_len = sprintf(sql_string, "SELECT * FROM t%u"
				" WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
				table_id, start_pos + 1, end_pos + 1);
			pset->pparray = common_util_alloc(sizeof(void*)*row_needed);
		} else {
			end_pos = start_pos + row_needed;
			if (end_pos < 0) {
				end_pos = 0;
			}
			sql_len = sprintf(sql_string, "SELECT * FROM t%u"
				" WHERE idx>=%u AND idx<%u ORDER BY idx DESC",
				table_id, end_pos + 1, start_pos + 1);
			pset->pparray = common_util_alloc(
				sizeof(void*)*(start_pos - end_pos));
		}
		if (NULL == pset->pparray) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
			sql_len = sprintf(sql_string, "SELECT parent_id FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			sql_len = sprintf(sql_string, "SELECT value FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt2, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				db_engine_put_db(pdb);
				return FALSE;
			}
		} else {
			pstmt1 = NULL;
			pstmt2 = NULL;
		}
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		if (FALSE == common_util_begin_message_optimize(pdb->psqlite)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			inst_id = sqlite3_column_int64(pstmt, 3);
			row_type = sqlite3_column_int64(pstmt, 4);
			pset->pparray[pset->count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == pset->pparray[pset->count]) {
				sqlite3_finalize(pstmt);
				if (NULL != pstmt1) {
					sqlite3_finalize(pstmt1);
				}
				if (NULL != pstmt2) {
					sqlite3_finalize(pstmt2);
				}
				common_util_end_message_optimize();
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
			pset->pparray[pset->count]->count = 0;
			pset->pparray[pset->count]->ppropval =
				common_util_alloc(sizeof(TAGGED_PROPVAL)*pproptags->count);
			if (NULL == pset->pparray[pset->count]->ppropval) {
				sqlite3_finalize(pstmt);
				if (NULL != pstmt1) {
					sqlite3_finalize(pstmt1);
				}
				if (NULL != pstmt2) {
					sqlite3_finalize(pstmt2);
				}
				common_util_end_message_optimize();
				sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
				db_engine_put_db(pdb);
				return FALSE;
			}
			count = 0;
			for (i=0; i<pproptags->count; i++) {
				if (FALSE == table_column_content_tmptbl(pstmt, pstmt1,
					pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
					pproptags->pproptag[i], ptnode->instance_tag,
					ptnode->extremum_tag, &pvalue)) {
					if (CONTENT_ROW_HEADER == row_type) {
						continue;
					}
					if (FALSE == common_util_get_property(
						MESSAGE_PROPERTIES_TABLE, inst_id, cpid,
						pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
						sqlite3_finalize(pstmt);
						if (NULL != pstmt1) {
							sqlite3_finalize(pstmt1);
						}
						if (NULL != pstmt2) {
							sqlite3_finalize(pstmt2);
						}
						common_util_end_message_optimize();
						sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
						db_engine_put_db(pdb);
						return FALSE;
					}
				}
				if (NULL == pvalue) {
					continue;
				}
				switch (pproptags->pproptag[i] & 0xFFFF) {
				case PROPVAL_TYPE_WSTRING:
					utf8_truncate(pvalue, 255);
					break;
				case PROPVAL_TYPE_STRING:
					table_truncate_string(cpid, pvalue);
					break;
				case PROPVAL_TYPE_BINARY:
					if (((BINARY*)pvalue)->cb > 510) {
						((BINARY*)pvalue)->cb = 510;
					}
					break;
				}
				pset->pparray[pset->count]->ppropval[count].proptag =
													pproptags->pproptag[i];
				pset->pparray[pset->count]->ppropval[count].pvalue = pvalue;
				count ++;
			}
			pset->pparray[pset->count]->count = count;
			pset->count ++;
		}
		sqlite3_finalize(pstmt);
		if (NULL != pstmt1) {
			sqlite3_finalize(pstmt1);
		}
		if (NULL != pstmt2) {
			sqlite3_finalize(pstmt2);
		}
		common_util_end_message_optimize();
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		break;
	case TABLE_TYPE_PERMISSION:
		if (row_needed > 0) {
			end_pos = start_pos + row_needed;
			sql_len = sprintf(sql_string, "SELECT member_id FROM t%u "
						"WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
						table_id, start_pos + 1, end_pos + 1);
			pset->pparray = common_util_alloc(sizeof(void*)*row_needed);
		} else {
			end_pos = start_pos + row_needed;
			if (end_pos < 0) {
				end_pos = 0;
			}
			sql_len = sprintf(sql_string, "SELECT member_id FROM t%u "
						"WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
						table_id, end_pos + 1, start_pos + 1);
			pset->pparray = common_util_alloc(
				sizeof(void*)*(start_pos - end_pos));
		}
		if (NULL == pset->pparray) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			member_id = sqlite3_column_int64(pstmt, 0);
			pset->pparray[pset->count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == pset->pparray[pset->count]) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			pset->pparray[pset->count]->count = 0;
			pset->pparray[pset->count]->ppropval =
				common_util_alloc(sizeof(TAGGED_PROPVAL)*pproptags->count);
			if (NULL == pset->pparray[pset->count]->ppropval) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			count = 0;
			for (i=0; i<pproptags->count; i++) {
				proptag = pproptags->pproptag[i];
				if (PROP_TAG_MEMBERNAME_STRING8 == proptag) {
					proptag = PROP_TAG_MEMBERNAME;
				}
				if (FALSE == common_util_get_permission_property(member_id,
					pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
					sqlite3_finalize(pstmt);
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (PROP_TAG_MEMBERRIGHTS == pproptags->pproptag[i]
					&& 0 == (ptnode->table_flags &
					PERMISSIONS_TABLE_FLAG_INCLUDEFREEBUSY)) {
					*(uint32_t*)pvalue &= ~PERMISSION_FREEBUSYSIMPLE;
					*(uint32_t*)pvalue &= ~PERMISSION_FREEBUSYDETAILED;
				}
				if (NULL == pvalue) {
					continue;
				}
				pset->pparray[pset->count]->ppropval[count].proptag =
													pproptags->pproptag[i];
				if (PROP_TAG_MEMBERNAME_STRING8 == pproptags->pproptag[i]) {
					pset->pparray[pset->count]->ppropval[count].pvalue =
							common_util_convert_copy(FALSE, cpid, pvalue);
				} else {
					pset->pparray[pset->count]->ppropval[count].pvalue =
																	pvalue;
				}
				count ++;
			}
			pset->pparray[pset->count]->count = count;
			pset->count ++;
		}
		sqlite3_finalize(pstmt);
		break;
	case TABLE_TYPE_RULE:
		if (row_needed > 0) {
			end_pos = start_pos + row_needed;
			sql_len = sprintf(sql_string, "SELECT rule_id FROM t%u "
						"WHERE idx>=%u AND idx<%u ORDER BY idx ASC",
						table_id, start_pos + 1, end_pos + 1);
			pset->pparray = common_util_alloc(sizeof(void*)*row_needed);
		} else {
			end_pos = start_pos + row_needed;
			if (end_pos < 0) {
				end_pos = 0;
			}
			sql_len = sprintf(sql_string, "SELECT rule_id FROM t%u "
						"WHERE idx>%u AND idx<=%u ORDER BY idx DESC",
						table_id, end_pos + 1, start_pos + 1);
			pset->pparray = common_util_alloc(
				sizeof(void*)*(start_pos - end_pos));
		}
		if (NULL == pset->pparray) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			rule_id = sqlite3_column_int64(pstmt, 0);
			pset->pparray[pset->count] =
				common_util_alloc(sizeof(TPROPVAL_ARRAY));
			if (NULL == pset->pparray[pset->count]) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			pset->pparray[pset->count]->count = 0;
			pset->pparray[pset->count]->ppropval =
				common_util_alloc(sizeof(TAGGED_PROPVAL)*pproptags->count);
			if (NULL == pset->pparray[pset->count]->ppropval) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			count = 0;
			for (i=0; i<pproptags->count; i++) {
				proptag = pproptags->pproptag[i];
				if (PROP_TAG_RULENAME_STRING8 == proptag) {
					proptag = PROP_TAG_RULENAME;
				} else if (PROP_TAG_RULEPROVIDER_STRING8 == proptag) {
					proptag = PROP_TAG_RULEPROVIDER;
				}
				if (FALSE == common_util_get_rule_property(
					rule_id, pdb->psqlite, proptag, &pvalue)) {
					sqlite3_finalize(pstmt);
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (NULL == pvalue) {
					continue;
				}
				pset->pparray[pset->count]->ppropval[count].proptag =
													pproptags->pproptag[i];
				if (PROP_TAG_RULENAME_STRING8 == pproptags->pproptag[i] ||
					PROP_TAG_RULEPROVIDER_STRING8 == pproptags->pproptag[i]) {
					pset->pparray[pset->count]->ppropval[count].pvalue =
							common_util_convert_copy(FALSE, cpid, pvalue);
				} else {
					pset->pparray[pset->count]->ppropval[count].pvalue =
																	pvalue;
				}
				count ++;
			}
			pset->pparray[pset->count]->count = count;
			pset->count ++;
		}
		sqlite3_finalize(pstmt);
		break;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

static BOOL table_get_content_row_property(
	 void *pparam, uint32_t proptag, void **ppvalue)
{
	uint32_t *pinst_num;
	uint64_t parent_fid;
	CONTENT_ROW_PARAM *prow_param;
	
	prow_param = (CONTENT_ROW_PARAM*)pparam;
	if (proptag == PROP_TAG_INSTANCESVREID) {
		*ppvalue = common_util_alloc(sizeof(SVREID));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((SVREID*)(*ppvalue))->pbin = NULL;
		if (CONTENT_ROW_HEADER == prow_param->row_type) {
			((SVREID*)(*ppvalue))->folder_id =
						rop_util_make_eid_ex(1,
						prow_param->folder_id);
			((SVREID*)(*ppvalue))->message_id =
						rop_util_make_eid_ex(2,
						prow_param->inst_id &
						0x00FFFFFFFFFFFFFFULL);
			((SVREID*)(*ppvalue))->instance = 0;
		} else {
			if (FALSE == common_util_get_message_parent_folder(
				prow_param->psqlite, prow_param->inst_id,
				&parent_fid)) {
				return FALSE;	
			}
			((SVREID*)(*ppvalue))->folder_id =
				rop_util_make_eid_ex(1, parent_fid);
			((SVREID*)(*ppvalue))->message_id =
							rop_util_make_eid_ex(
							1, prow_param->inst_id);
			pinst_num = common_util_column_sqlite_statement(
					prow_param->pstmt, 10, PROPVAL_TYPE_LONG);
			if (NULL == pinst_num) {
				return FALSE;
			}
			((SVREID*)(*ppvalue))->instance = *pinst_num;
		}
		return TRUE;
	}
	if (FALSE == table_column_content_tmptbl(
		prow_param->pstmt, prow_param->pstmt1,
		prow_param->pstmt2, prow_param->psorts,
		prow_param->folder_id, prow_param->row_type,
		proptag, prow_param->instance_tag,
		prow_param->extremum_tag, ppvalue)) {
		if (CONTENT_ROW_HEADER == prow_param->row_type) {
			*ppvalue = NULL;
			return TRUE;
		}
		if (FALSE == common_util_get_property(
			MESSAGE_PROPERTIES_TABLE, prow_param->inst_id,
			prow_param->cpid, prow_param->psqlite, proptag,
			ppvalue)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL table_get_hierarchy_row_property(
	 void *pparam, uint32_t proptag, void **ppvalue)
{
	HIERARCHY_ROW_PARAM *prow_param;
	
	prow_param = (HIERARCHY_ROW_PARAM*)pparam;
	if (PROP_TAG_DEPTH == proptag) {
		*ppvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		*(uint32_t*)*ppvalue = sqlite3_column_int64(prow_param->pstmt, 2);
	} else {
		if (FALSE == common_util_get_property(
			FOLDER_PROPERTIES_TABLE, prow_param->folder_id,
			prow_param->cpid, prow_param->psqlite, proptag,
			ppvalue)) {
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL table_evaluate_row_restriction(
	const RESTRICTION *pres, void *pparam,
	TABLE_GET_ROW_PROPERTY get_property)
{
	int i;
	int len;
	void *pvalue;
	void *pvalue1;
	uint32_t val_size;
	
	switch (pres->rt) {
	case RESTRICTION_TYPE_OR:
	case RESTRICTION_TYPE_AND:
		for (i=0; i<((RESTRICTION_AND_OR*)pres->pres)->count; i++) {
			if (FALSE == table_evaluate_row_restriction(
				((RESTRICTION_AND_OR*)pres->pres)->pres + i,
				pparam, get_property)) {
				return FALSE;
			}
		}
		return TRUE;
	case RESTRICTION_TYPE_NOT:
		if (TRUE == table_evaluate_row_restriction(
			&((RESTRICTION_NOT*)pres->pres)->res,
			pparam, get_property)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_CONTENT:
		if (PROPVAL_TYPE_WSTRING != (((RESTRICTION_CONTENT*)
			pres->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if ((((RESTRICTION_CONTENT*)pres->pres)->proptag & 0xFFFF) !=
			(((RESTRICTION_CONTENT*)pres->pres)->propval.proptag & 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == get_property(pparam, ((RESTRICTION_CONTENT*)
			pres->pres)->proptag, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level & 0xFFFF) {
		case FUZZY_LEVEL_FULLSTRING:
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strcasecmp(((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strcmp(((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case FUZZY_LEVEL_SUBSTRING:
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (NULL != strstr(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		case FUZZY_LEVEL_PREFIX:
			len = strlen(((RESTRICTION_CONTENT*)pres->pres)->propval.pvalue);
			if (((RESTRICTION_CONTENT*)pres->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strncasecmp(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strncmp(pvalue, ((RESTRICTION_CONTENT*)
					pres->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	case RESTRICTION_TYPE_PROPERTY:
		if (FALSE == get_property(pparam, ((RESTRICTION_PROPERTY*)
			pres->pres)->proptag, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		if (PROP_TAG_ANR == ((RESTRICTION_PROPERTY*)pres->pres)->proptag) {
			if ((((RESTRICTION_PROPERTY*)pres->pres)->propval.proptag
				& 0xFFFF) != PROPVAL_TYPE_WSTRING) {
				return FALSE;
			}
			if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
				pres->pres)->propval.pvalue)) {
				return TRUE;
			}
			return FALSE;
		}
		return propval_compare_relop(
				((RESTRICTION_PROPERTY*)pres->pres)->relop,
				((RESTRICTION_PROPERTY*)pres->pres)->proptag&0xFFFF,
				pvalue, ((RESTRICTION_PROPERTY*)pres->pres)->propval.pvalue);
	case RESTRICTION_TYPE_PROPCOMPARE:
		if ((((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1&0xFFFF) !=
			(((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag2&0xFFFF)) {
			return FALSE;
		}
		if (FALSE == get_property(pparam, ((RESTRICTION_PROPCOMPARE*)
			pres->pres)->proptag1, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == get_property(pparam, ((RESTRICTION_PROPCOMPARE*)
			pres->pres)->proptag2, &pvalue1) || NULL == pvalue1) {
			return FALSE;
		}
		return propval_compare_relop(
				((RESTRICTION_PROPCOMPARE*)pres->pres)->relop,
				((RESTRICTION_PROPCOMPARE*)pres->pres)->proptag1&0xFFFF,
				pvalue, pvalue1);
	case RESTRICTION_TYPE_BITMASK:
		if (PROPVAL_TYPE_LONG != (((RESTRICTION_BITMASK*)
			pres->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == get_property(pparam, ((RESTRICTION_BITMASK*)
			pres->pres)->proptag, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_BITMASK*)pres->pres)->bitmask_relop) {
		case BITMASK_RELOP_EQZ:
			if (0 == (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pres->pres)->mask)) {
				return TRUE;
			}
			break;
		case BITMASK_RELOP_NEZ:
			if (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pres->pres)->mask) {
				return TRUE;
			}
			break;
		}	
		return FALSE;
	case RESTRICTION_TYPE_SIZE:
		if (FALSE == get_property(pparam, ((RESTRICTION_SIZE*)
			pres->pres)->proptag, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		val_size = propval_size(((RESTRICTION_SIZE*)
					pres->pres)->proptag, pvalue);
		return propval_compare_relop(((RESTRICTION_SIZE*)
				pres->pres)->relop, PROPVAL_TYPE_LONG, &val_size,
				&((RESTRICTION_SIZE*)pres->pres)->size);
	case RESTRICTION_TYPE_EXIST:
		if (FALSE == get_property(pparam, ((RESTRICTION_EXIST*)
			pres->pres)->proptag, &pvalue) || NULL == pvalue) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_SUBOBJ:
		return FALSE;
	case RESTRICTION_TYPE_COMMENT:
		if (NULL == ((RESTRICTION_COMMENT*)pres->pres)->pres) {
			return TRUE;
		}
		return table_evaluate_row_restriction(
			((RESTRICTION_COMMENT*)pres->pres)->pres,
			pparam, get_property);
	case RESTRICTION_TYPE_COUNT:
		return FALSE;
	}	
	return FALSE;
}

BOOL exmdb_server_match_table(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, BOOL b_forward, uint32_t start_pos,
	const RESTRICTION *pres, const PROPTAG_ARRAY *pproptags,
	int32_t *pposition, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	int idx;
	int count;
	int sql_len;
	DB_ITEM *pdb;
	void *pvalue;
	int row_type;
	uint32_t proptag;
	uint64_t rule_id;
	uint64_t inst_id;
	uint64_t folder_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	CONTENT_ROW_PARAM content_param;
	HIERARCHY_ROW_PARAM hierarchy_param;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		*pposition = -1;
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	idx = 0;
	ppropvals->count = 0;
	ppropvals->ppropval = NULL;
	if (TABLE_TYPE_HIERARCHY == ptnode->type) {
		if (TRUE == b_forward) {
			sql_len = sprintf(sql_string, "SELECT folder_id,"
				" idx, depth FROM t%u WHERE idx>=%u ORDER BY"
				" idx ASC", table_id, start_pos + 1);
		} else {
			sql_len = sprintf(sql_string, "SELECT folder_id,"
				" idx, depth FROM t%u WHERE idx<=%u ORDER BY"
				" idx DESC", table_id, start_pos + 1);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			folder_id = sqlite3_column_int64(pstmt, 0);
			hierarchy_param.cpid = cpid;
			hierarchy_param.psqlite = pdb->psqlite;
			hierarchy_param.pstmt = pstmt;
			hierarchy_param.folder_id = folder_id;
			if (TRUE == table_evaluate_row_restriction(pres,
				&hierarchy_param, table_get_hierarchy_row_property)) {
				idx = sqlite3_column_int64(pstmt, 1);
				count = 0;
				ppropvals->ppropval = common_util_alloc(
					sizeof(TAGGED_PROPVAL)*pproptags->count);
				if (NULL == ppropvals->ppropval) {
					sqlite3_finalize(pstmt);
					db_engine_put_db(pdb);
					sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
					return FALSE;
				}
				for (i=0; i<pproptags->count; i++) {
					if (PROP_TAG_DEPTH == pproptags->pproptag[i]) {
						pvalue = common_util_alloc(sizeof(uint32_t));
						if (NULL == pvalue) {
							sqlite3_finalize(pstmt);
							sqlite3_exec(pdb->psqlite,
								"ROLLBACK", NULL, NULL, NULL);
							db_engine_put_db(pdb);
							return FALSE;
						}
						*(uint32_t*)pvalue = sqlite3_column_int64(pstmt, 2);
					} else {
						if (FALSE == common_util_get_property(
							FOLDER_PROPERTIES_TABLE, folder_id, cpid,
							pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
							sqlite3_finalize(pstmt);
							sqlite3_exec(pdb->psqlite,
								"ROLLBACK", NULL, NULL, NULL);
							db_engine_put_db(pdb);
							return FALSE;
						}
						if (NULL == pvalue) {
							continue;
						}
						switch (pproptags->pproptag[i] & 0xFFFF) {
						case PROPVAL_TYPE_WSTRING:
							utf8_truncate(pvalue, 255);
							break;
						case PROPVAL_TYPE_STRING:
							table_truncate_string(cpid, pvalue);
							break;
						case PROPVAL_TYPE_BINARY:
							if (((BINARY*)pvalue)->cb > 510) {
								((BINARY*)pvalue)->cb = 510;
							}
							break;
						}
					}
					ppropvals->ppropval[count].proptag = pproptags->pproptag[i];
					ppropvals->ppropval[count].pvalue = pvalue;
					count ++;
				}
				ppropvals->count = count;
				break;
			}
		}
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		*pposition = idx - 1;
	} else if (TABLE_TYPE_CONTENT == ptnode->type) {
		if (TRUE == b_forward) {
			sql_len = sprintf(sql_string, "SELECT * FROM t%u"
				" WHERE idx>=%u ORDER BY idx ASC", table_id,
				start_pos + 1);
		} else {
			sql_len = sprintf(sql_string, "SELECT * FROM t%u"
				" WHERE idx<=%u ORDER BY idx DESC", table_id,
				start_pos + 1);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
			sql_len = sprintf(sql_string, "SELECT parent_id FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			sql_len = sprintf(sql_string, "SELECT value FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt2, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				db_engine_put_db(pdb);
				return FALSE;
			}
		} else {
			pstmt1 = NULL;
			pstmt2 = NULL;
		}
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		if (FALSE == common_util_begin_message_optimize(pdb->psqlite)) {
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			inst_id = sqlite3_column_int64(pstmt, 3);
			row_type = sqlite3_column_int64(pstmt, 4);
			content_param.cpid = cpid;
			content_param.psqlite = pdb->psqlite;
			content_param.pstmt = pstmt;
			content_param.pstmt1 = pstmt1;
			content_param.pstmt2 = pstmt2;
			content_param.folder_id = ptnode->folder_id;
			content_param.inst_id = inst_id;
			content_param.row_type = row_type;
			content_param.psorts = ptnode->psorts;
			content_param.instance_tag = ptnode->instance_tag;
			content_param.extremum_tag = ptnode->extremum_tag;
			if (TRUE == table_evaluate_row_restriction(pres,
				&content_param, table_get_content_row_property)) {
				idx = sqlite3_column_int64(pstmt, 1);
				count = 0;
				ppropvals->ppropval = common_util_alloc(
					sizeof(TAGGED_PROPVAL)*pproptags->count);
				if (NULL == ppropvals->ppropval) {
					sqlite3_finalize(pstmt);
					if (NULL != pstmt1) {
						sqlite3_finalize(pstmt1);
					}
					if (NULL != pstmt2) {
						sqlite3_finalize(pstmt2);
					}
					common_util_end_message_optimize();
					sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
					db_engine_put_db(pdb);
					return FALSE;
				}
				for (i=0; i<pproptags->count; i++) {
					if (FALSE == table_column_content_tmptbl(pstmt, pstmt1,
						pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
						pproptags->pproptag[i], ptnode->instance_tag,
						ptnode->extremum_tag, &pvalue)) {
						if (CONTENT_ROW_HEADER == row_type) {
							continue;
						}
						if (FALSE == common_util_get_property(
							MESSAGE_PROPERTIES_TABLE, inst_id, cpid,
							pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
							sqlite3_finalize(pstmt);
							if (NULL != pstmt1) {
								sqlite3_finalize(pstmt1);
							}
							if (NULL != pstmt2) {
								sqlite3_finalize(pstmt2);
							}
							common_util_end_message_optimize();
							sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
							db_engine_put_db(pdb);
							return FALSE;
						}
					}
					if (NULL == pvalue) {
						continue;
					}
					switch (pproptags->pproptag[i] & 0xFFFF) {
					case PROPVAL_TYPE_WSTRING:
						utf8_truncate(pvalue, 255);
						break;
					case PROPVAL_TYPE_STRING:
						table_truncate_string(cpid, pvalue);
						break;
					case PROPVAL_TYPE_BINARY:
						if (((BINARY*)pvalue)->cb > 510) {
							((BINARY*)pvalue)->cb = 510;
						}
						break;
					}
					ppropvals->ppropval[count].proptag = pproptags->pproptag[i];
					ppropvals->ppropval[count].pvalue = pvalue;
					count ++;
				}
				ppropvals->count = count;
				break;
			}
		}
		sqlite3_finalize(pstmt);
		if (NULL != pstmt1) {
			sqlite3_finalize(pstmt1);
		}
		if (NULL != pstmt2) {
			sqlite3_finalize(pstmt2);
		}
		common_util_end_message_optimize();
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		*pposition = idx - 1;
	} else if (TABLE_TYPE_RULE == ptnode->type) {
		if (TRUE == b_forward) {
			sql_len = sprintf(sql_string, "SELECT rule_id"
					" idx FROM t%u WHERE idx>=%u ORDER BY"
					" idx ASC", table_id, start_pos + 1);
		} else {
			sql_len = sprintf(sql_string, "SELECT rule_id,"
					" idx FROM t%u WHERE idx<=%u ORDER BY"
					" idx DESC", table_id, start_pos + 1);
		}
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			rule_id = sqlite3_column_int64(pstmt, 0);
			if (TRUE == table_evaluate_rule_restriction(
				pdb->psqlite, rule_id, pres)) {
				ppropvals->count = 0;
				ppropvals->ppropval = common_util_alloc(
					sizeof(TAGGED_PROPVAL)*pproptags->count);
				if (NULL == ppropvals->ppropval) {
					sqlite3_finalize(pstmt);
					db_engine_put_db(pdb);
					return FALSE;
				}
				count = 0;
				for (i=0; i<pproptags->count; i++) {
					proptag = pproptags->pproptag[i];
					if (PROP_TAG_RULENAME_STRING8 == proptag) {
						proptag = PROP_TAG_RULENAME;
					} else if (PROP_TAG_RULEPROVIDER_STRING8 == proptag) {
						proptag = PROP_TAG_RULEPROVIDER;
					}
					if (FALSE == common_util_get_rule_property(
						rule_id, pdb->psqlite, proptag, &pvalue)) {
						sqlite3_finalize(pstmt);
						db_engine_put_db(pdb);
						return FALSE;
					}
					if (NULL == pvalue) {
						continue;
					}
					ppropvals->ppropval[count].proptag = pproptags->pproptag[i];
					if (PROP_TAG_RULENAME_STRING8 == pproptags->pproptag[i] ||
						PROP_TAG_RULEPROVIDER_STRING8 == pproptags->pproptag[i]) {
						ppropvals->ppropval[count].pvalue =
								common_util_convert_copy(FALSE, cpid, pvalue);
					} else {
						ppropvals->ppropval[count].pvalue = pvalue;
					}
					count ++;
				}
				ppropvals->count = count;
				break;
			}
		}
		sqlite3_finalize(pstmt);
		*pposition = idx - 1;
	} else {
		*pposition = -1;
	}
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_locate_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, uint32_t inst_num,
	int32_t *pposition, uint32_t *prow_type)
{
	int idx;
	int sql_len;
	DB_ITEM *pdb;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		*pposition = -1;
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	switch (ptnode->type) {
	case TABLE_TYPE_HIERARCHY:
		if (1 == rop_util_get_replid(inst_id)) {
			inst_id = rop_util_get_gc_value(inst_id);
		} else {
			inst_id = rop_util_get_replid(inst_id);
			inst_id <<= 48;
			inst_id |= rop_util_get_gc_value(inst_id);
		}
		sql_len = sprintf(sql_string, "SELECT idx FROM t%u "
			"WHERE folder_id=%llu", ptnode->table_id, inst_id);
		break;
	case TABLE_TYPE_CONTENT:
		if (1 == rop_util_get_replid(inst_id)) {
			inst_id = rop_util_get_gc_value(inst_id);
		} else {
			inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
		}
		sql_len = sprintf(sql_string, "SELECT idx, row_type "
				"FROM t%u WHERE inst_id=%llu AND inst_num=%u",
				ptnode->table_id, inst_id, inst_num);
		break;
	case TABLE_TYPE_PERMISSION:
		sql_len = sprintf(sql_string, "SELECT idx FROM t%u "
			"WHERE member_id=%llu", ptnode->table_id, inst_id);
		break;
	case TABLE_TYPE_RULE:
		inst_id = rop_util_get_gc_value(inst_id);
		sql_len = sprintf(sql_string, "SELECT idx FROM t%u "
			"WHERE rule_id=%llu", ptnode->table_id, inst_id);
		break;
	default:
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {		
		db_engine_put_db(pdb);
		return FALSE;
	}
	*prow_type = 0;
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		idx = sqlite3_column_int64(pstmt, 0);
		if (TABLE_TYPE_CONTENT == ptnode->type) {
			*prow_type = sqlite3_column_int64(pstmt, 1);
		}
	} else {
		idx = 0;
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	*pposition = idx - 1;
	return TRUE;
}

BOOL exmdb_server_read_table_row(const char *dir, const char *username,
	uint32_t cpid, uint32_t table_id, const PROPTAG_ARRAY *pproptags,
	uint64_t inst_id, uint32_t inst_num, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	int count;
	int sql_len;
	DB_ITEM *pdb;
	void *pvalue;
	int row_type;
	uint32_t depth;
	TABLE_NODE *ptnode;
	uint64_t folder_id;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	char sql_string[1024];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		ppropvals->count = 0;
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (FALSE == exmdb_server_check_private()) {
		exmdb_server_set_public_username(username);
	}
	if (TABLE_TYPE_HIERARCHY == ptnode->type) {
		if (1 == rop_util_get_replid(inst_id)) {
			folder_id = rop_util_get_gc_value(inst_id);
		} else {
			folder_id = rop_util_get_replid(inst_id);
			folder_id <<= 48;
			folder_id |= rop_util_get_gc_value(inst_id);
		}
		sql_len = sprintf(sql_string, "SELECT depth FROM t%u"
				" WHERE folder_id=%llu", table_id, folder_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			ppropvals->count = 0;
			return TRUE;
		}
		depth = sqlite3_column_int64(pstmt, 0);
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
		count = 0;
		ppropvals->ppropval = common_util_alloc(
			sizeof(TAGGED_PROPVAL)*pproptags->count);
		if (NULL == ppropvals->ppropval) {
			db_engine_put_db(pdb);
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			return FALSE;
		}
		for (i=0; i<pproptags->count; i++) {
			if (PROP_TAG_DEPTH == pproptags->pproptag[i]) {
				pvalue = common_util_alloc(sizeof(uint32_t));
				if (NULL == pvalue) {
					sqlite3_exec(pdb->psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					db_engine_put_db(pdb);
					return FALSE;
				}
				*(uint32_t*)pvalue = depth;
			} else {
				if (FALSE == common_util_get_property(
					FOLDER_PROPERTIES_TABLE, folder_id, cpid,
					pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
					sqlite3_exec(pdb->psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (NULL == pvalue) {
					continue;
				}
				switch (pproptags->pproptag[i] & 0xFFFF) {
				case PROPVAL_TYPE_WSTRING:
					utf8_truncate(pvalue, 255);
					break;
				case PROPVAL_TYPE_STRING:
					table_truncate_string(cpid, pvalue);
					break;
				case PROPVAL_TYPE_BINARY:
					if (((BINARY*)pvalue)->cb > 510) {
						((BINARY*)pvalue)->cb = 510;
					}
					break;
				}
			}
			ppropvals->ppropval[count].proptag = pproptags->pproptag[i];
			ppropvals->ppropval[count].pvalue = pvalue;
			count ++;
		}
		ppropvals->count = count;
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	} else if (TABLE_TYPE_CONTENT == ptnode->type) {
		if (1 == rop_util_get_replid(inst_id)) {
			inst_id = rop_util_get_gc_value(inst_id);
		} else {
			inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
		}
		sql_len = sprintf(sql_string, "SELECT * FROM t%u"
					" WHERE inst_id=%llu AND inst_num=%u",
					table_id, inst_id, inst_num);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			ppropvals->count = 0;
			return TRUE;
		}
		row_type = sqlite3_column_int64(pstmt, 4);
		if (NULL != ptnode->psorts && ptnode->psorts->ccategories > 0) {
			sql_len = sprintf(sql_string, "SELECT parent_id FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt1, NULL)) {
				sqlite3_finalize(pstmt);
				db_engine_put_db(pdb);
				return FALSE;
			}
			sql_len = sprintf(sql_string, "SELECT value FROM"
					" t%u WHERE row_id=?", ptnode->table_id);
			if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
				sql_string, sql_len, &pstmt2, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				db_engine_put_db(pdb);
				return FALSE;
			}
		} else {
			pstmt1 = NULL;
			pstmt2 = NULL;
		}
		sqlite3_exec(pdb->psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);			
		count = 0;
		ppropvals->ppropval = common_util_alloc(
			sizeof(TAGGED_PROPVAL)*pproptags->count);
		if (NULL == ppropvals->ppropval) {
			sqlite3_finalize(pstmt);
			if (NULL != pstmt1) {
				sqlite3_finalize(pstmt1);
			}
			if (NULL != pstmt2) {
				sqlite3_finalize(pstmt2);
			}
			sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		for (i=0; i<pproptags->count; i++) {
			if (FALSE == table_column_content_tmptbl(pstmt, pstmt1,
				pstmt2, ptnode->psorts, ptnode->folder_id, row_type,
				pproptags->pproptag[i], ptnode->instance_tag,
				ptnode->extremum_tag, &pvalue)) {
				if (CONTENT_ROW_HEADER == row_type) {
					continue;
				}
				if (FALSE == common_util_get_property(
					MESSAGE_PROPERTIES_TABLE, inst_id, cpid,
					pdb->psqlite, pproptags->pproptag[i], &pvalue)) {
					sqlite3_finalize(pstmt);
					if (NULL != pstmt1) {
						sqlite3_finalize(pstmt1);
					}
					if (NULL != pstmt2) {
						sqlite3_finalize(pstmt2);
					}
					sqlite3_exec(pdb->psqlite, "ROLLBACK", NULL, NULL, NULL);
					db_engine_put_db(pdb);
					return FALSE;
				}
			}
			if (NULL == pvalue) {
				continue;
			}
			switch (pproptags->pproptag[i] & 0xFFFF) {
			case PROPVAL_TYPE_WSTRING:
				utf8_truncate(pvalue, 255);
				break;
			case PROPVAL_TYPE_STRING:
				table_truncate_string(cpid, pvalue);
				break;
			case PROPVAL_TYPE_BINARY:
				if (((BINARY*)pvalue)->cb > 510) {
					((BINARY*)pvalue)->cb = 510;
				}
				break;
			}
			ppropvals->ppropval[count].proptag = pproptags->pproptag[i];
			ppropvals->ppropval[count].pvalue = pvalue;
			count ++;
		}
		ppropvals->count = count;
		sqlite3_finalize(pstmt);
		if (NULL != pstmt1) {
			sqlite3_finalize(pstmt1);
		}
		if (NULL != pstmt2) {
			sqlite3_finalize(pstmt2);
		}
		sqlite3_exec(pdb->psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	} else {
		ppropvals->count = 0;
	}
	db_engine_put_db(pdb);
	return TRUE;
}
	
BOOL exmdb_server_mark_table(const char *dir,
	uint32_t table_id, uint32_t position, uint64_t *pinst_id,
	uint32_t *pinst_num, uint32_t *prow_type)
{
	int sql_len;
	DB_ITEM *pdb;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*pinst_id = 0;
	*pinst_num = 0;
	*prow_type = 0;
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	switch (ptnode->type) {
	case TABLE_TYPE_HIERARCHY:
		sql_len = sprintf(sql_string, "SELECT folder_id FROM t%u"
				" WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	case TABLE_TYPE_CONTENT:
		sql_len = sprintf(sql_string, "SELECT inst_id,"
			" inst_num, row_type FROM t%u WHERE idx=%u",
			ptnode->table_id, position + 1);
		break;
	case TABLE_TYPE_PERMISSION:
		sql_len = sprintf(sql_string, "SELECT member_id FROM t%u "
			"WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	case TABLE_TYPE_RULE:
		sql_len = sprintf(sql_string, "SELECT rule_id FROM t%u "
			"WHERE idx=%u", ptnode->table_id, position + 1);
		break;
	default:
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {		
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		*pinst_id = sqlite3_column_int64(pstmt, 0);
		switch (ptnode->type) {
		case TABLE_TYPE_HIERARCHY:
			if (0 == (*pinst_id & 0xFF00000000000000ULL)) {
				*pinst_id = rop_util_make_eid_ex(1, *pinst_id);
			} else {
				*pinst_id = rop_util_make_eid_ex(*pinst_id >> 48,
							*pinst_id & 0x00FFFFFFFFFFFFFFULL);
			}
			break;
		case TABLE_TYPE_CONTENT:
			if (0 == (*pinst_id & 0xFF00000000000000ULL)) {
				*pinst_id = rop_util_make_eid_ex(1, *pinst_id);
			} else {
				*pinst_id = rop_util_make_eid_ex(
					2, *pinst_id & 0x00FFFFFFFFFFFFFFULL);
			}
			*pinst_num = sqlite3_column_int64(pstmt, 1);
			*prow_type = sqlite3_column_int64(pstmt, 2);
			break;
		case TABLE_TYPE_RULE:
			*pinst_id = rop_util_make_eid_ex(1, *pinst_id);
			break;
		}
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_get_table_all_proptags(const char *dir,
	uint32_t table_id, PROPTAG_ARRAY *pproptags)
{
	int sql_len;
	DB_ITEM *pdb;
	uint32_t proptag;
	TABLE_NODE *ptnode;
	INT_HASH_ITER *iter;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	INT_HASH_TABLE *phash;
	DOUBLE_LIST_NODE *pnode;
	uint32_t tmp_proptags[0x1000];
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		pproptags->count = 0;
		pproptags->pproptag = NULL;
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	switch (ptnode->type) {
	case TABLE_TYPE_HIERARCHY:
		phash = int_hash_init(0x1000, sizeof(int), NULL);
		if (NULL == phash) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT "
			"folder_id FROM t%u", ptnode->table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {		
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT proptag "
			"FROM folder_properties WHERE folder_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			sqlite3_bind_int64(pstmt1, 1,
				sqlite3_column_int64(pstmt, 0));
			while (SQLITE_ROW == sqlite3_step(pstmt1)) {
				proptag = sqlite3_column_int64(pstmt1, 0);
				if (NULL != int_hash_query(phash, proptag)) {
					continue;	
				}
				int_hash_add(phash, proptag, &proptag);
			}
			sqlite3_reset(pstmt1);
		}
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		iter = int_hash_iter_init(phash);
		if (NULL == iter) {
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		pproptags->count = 0;
		 for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			int_hash_iter_get_value(iter, &proptag);
			tmp_proptags[pproptags->count] = proptag;
			pproptags->count ++;
		}
		int_hash_iter_free(iter);
		int_hash_free(phash);
		tmp_proptags[pproptags->count++] = PROP_TAG_DEPTH;
		pproptags->pproptag = common_util_alloc(
			sizeof(uint32_t)*pproptags->count);
		if (NULL == pproptags->pproptag) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		memcpy(pproptags->pproptag, tmp_proptags,
			sizeof(uint32_t)*pproptags->count);
		db_engine_put_db(pdb);
		return TRUE;
	case TABLE_TYPE_CONTENT:	
		phash = int_hash_init(0x1000, sizeof(int), NULL);
		if (NULL == phash) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT inst_id,"
				" row_type FROM t%u", ptnode->table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt, NULL)) {		
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sql_len = sprintf(sql_string, "SELECT proptag "
			"FROM message_properties WHERE message_id=?");
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		while (SQLITE_ROW == sqlite3_step(pstmt)) {
			if (sqlite3_column_int64(pstmt, 1)
				!= CONTENT_ROW_MESSAGE) {
				continue;
			}
			sqlite3_bind_int64(pstmt1, 1,
				sqlite3_column_int64(pstmt, 0));
			while (SQLITE_ROW == sqlite3_step(pstmt1)) {
				proptag = sqlite3_column_int64(pstmt1, 0);
				if (NULL != int_hash_query(phash, proptag)) {
					continue;	
				}
				int_hash_add(phash, proptag, &proptag);
			}
			sqlite3_reset(pstmt1);
		}
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		iter = int_hash_iter_init(phash);
		if (NULL == iter) {
			int_hash_free(phash);
			db_engine_put_db(pdb);
			return FALSE;
		}
		pproptags->count = 0;
		 for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			int_hash_iter_get_value(iter, &proptag);
			tmp_proptags[pproptags->count] = proptag;
			pproptags->count ++;
		}
		int_hash_iter_free(iter);
		int_hash_free(phash);
		tmp_proptags[pproptags->count++] = PROP_TAG_MID;
		tmp_proptags[pproptags->count++] = PROP_TAG_MESSAGESIZE;
		tmp_proptags[pproptags->count++] = PROP_TAG_ASSOCIATED;
		tmp_proptags[pproptags->count++] = PROP_TAG_CHANGENUMBER;
		tmp_proptags[pproptags->count++] = PROP_TAG_READ;
		tmp_proptags[pproptags->count++] = PROP_TAG_HASATTACHMENTS;
		tmp_proptags[pproptags->count++] = PROP_TAG_MESSAGEFLAGS;
		tmp_proptags[pproptags->count++] = PROP_TAG_DISPLAYTO;
		tmp_proptags[pproptags->count++] = PROP_TAG_DISPLAYCC;
		tmp_proptags[pproptags->count++] = PROP_TAG_DISPLAYBCC;
		tmp_proptags[pproptags->count++] = PROP_TAG_INSTID;
		tmp_proptags[pproptags->count++] = PROP_TAG_INSTANCENUM;
		tmp_proptags[pproptags->count++] = PROP_TAG_ROWTYPE;
		tmp_proptags[pproptags->count++] = PROP_TAG_DEPTH;
		tmp_proptags[pproptags->count++] = PROP_TAG_CONTENTCOUNT;
		tmp_proptags[pproptags->count++] = PROP_TAG_CONTENTUNREADCOUNT;
		pproptags->pproptag = common_util_alloc(
			sizeof(uint32_t)*pproptags->count);
		if (NULL == pproptags->pproptag) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		memcpy(pproptags->pproptag, tmp_proptags,
			sizeof(uint32_t)*pproptags->count);
		db_engine_put_db(pdb);
		return TRUE;
	case TABLE_TYPE_PERMISSION:
		pproptags->count = 4;
		pproptags->pproptag = common_util_alloc(sizeof(uint32_t)*4);
		if (NULL == pproptags->pproptag) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		pproptags->pproptag[0] = PROP_TAG_ENTRYID;
		pproptags->pproptag[1] = PROP_TAG_MEMBERID;
		pproptags->pproptag[2] = PROP_TAG_MEMBERNAME;
		pproptags->pproptag[3] = PROP_TAG_MEMBERRIGHTS;
		db_engine_put_db(pdb);
		return TRUE;
	case TABLE_TYPE_RULE:
		pproptags->count = 10;
		pproptags->pproptag = common_util_alloc(sizeof(uint32_t)*10);
		if (NULL == pproptags->pproptag) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		pproptags->pproptag[0] = PROP_TAG_RULEID;
		pproptags->pproptag[1] = PROP_TAG_RULESEQUENCE;
		pproptags->pproptag[2] = PROP_TAG_RULESTATE;
		pproptags->pproptag[3] = PROP_TAG_RULENAME;
		pproptags->pproptag[4] = PROP_TAG_RULEPROVIDER;
		pproptags->pproptag[5] = PROP_TAG_RULELEVEL;
		pproptags->pproptag[6] = PROP_TAG_RULEUSERFLAGS;
		pproptags->pproptag[7] = PROP_TAG_RULEPROVIDERDATA;
		pproptags->pproptag[8] = PROP_TAG_RULECONDITION;
		pproptags->pproptag[9] = PROP_TAG_RULEACTIONS;
		db_engine_put_db(pdb);
		return TRUE;
	}
	db_engine_put_db(pdb);
	return FALSE;
}

static BOOL table_traverse_sub_contents(uint32_t step,
	uint64_t parent_id, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pcount)
{
	uint64_t row_id;
	DOUBLE_LIST tmp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&tmp_list);
	sqlite3_bind_int64(pstmt1, 1, parent_id);
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		(*pcount) ++;
		if (0 == sqlite3_column_int64(pstmt1, 1)) {
			continue;
		}
		row_id = sqlite3_column_int64(pstmt1, 0);
		if (1 == step) {
			sqlite3_bind_int64(pstmt, 1, row_id);
			if (SQLITE_ROW != sqlite3_step(pstmt)) {
				return FALSE;
			}
			*pcount += sqlite3_column_int64(pstmt, 0);
			sqlite3_reset(pstmt);
		} else {
			pnode = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				return FALSE;
			}
			pnode->pdata = common_util_alloc(sizeof(uint64_t));
			if (NULL == pnode->pdata) {
				return FALSE;
			}
			*(uint64_t*)pnode->pdata = row_id;
			double_list_append_as_tail(&tmp_list, pnode);
		}
	}
	sqlite3_reset(pstmt1);
	if (1 == step) {
		return TRUE;
	}
	while (pnode=double_list_get_from_head(&tmp_list)) {
		if (FALSE == table_traverse_sub_contents(step - 1,
			*(uint64_t*)pnode->pdata, pstmt, pstmt1, pcount)) {
			return FALSE;	
		}
	}
	return TRUE;
}

static BOOL table_expand_sub_contents(int depth,
	uint64_t parent_id, sqlite3_stmt *pstmt,
	sqlite3_stmt *pstmt1, uint32_t *pidx)
{
	uint64_t row_id;
	uint8_t row_stat;
	
	sqlite3_bind_int64(pstmt, 1, (-1)*parent_id);
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_reset(pstmt);
		return TRUE;
	}
	do {
		row_id = sqlite3_column_int64(pstmt, 0);
		row_stat = sqlite3_column_int64(pstmt, 1);
		sqlite3_reset(pstmt);
		(*pidx) ++;
		sqlite3_bind_int64(pstmt1, 1, *pidx);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			return FALSE;
		}
		sqlite3_reset(pstmt1);
		if (depth > 0 && 0 != row_stat) {
			if (FALSE == table_expand_sub_contents(
				depth - 1, row_id, pstmt, pstmt1, pidx)) {
				return FALSE;
			}
		}
		sqlite3_bind_int64(pstmt, 1, row_id);
	} while (SQLITE_ROW == sqlite3_step(pstmt));
	sqlite3_reset(pstmt);
	return TRUE;
}

BOOL exmdb_server_expand_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	int depth;
	int sql_len;
	DB_ITEM *pdb;
	uint32_t idx;
	uint64_t row_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (TABLE_TYPE_CONTENT != ptnode->type ||
		2 != rop_util_get_replid(inst_id)) {
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	sql_len = sprintf(sql_string, "SELECT row_id, row_type, "
			"row_stat, depth, idx FROM t%u WHERE inst_id=%llu"
			" AND inst_num=0", ptnode->table_id, inst_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		CONTENT_ROW_HEADER != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	*pb_found = TRUE;
	if (0 != sqlite3_column_int64(pstmt, 2)) {
		sqlite3_finalize(pstmt);
		*pposition = -1;
		db_engine_put_db(pdb);
		return TRUE;
	}
	row_id = sqlite3_column_int64(pstmt, 0);
	depth = sqlite3_column_int64(pstmt, 3);
	idx = sqlite3_column_int64(pstmt, 4);
	*pposition = idx - 1;
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT count(*) FROM"
			" t%u WHERE parent_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (ptnode->psorts->ccategories == depth + 1) {
		sqlite3_bind_int64(pstmt, 1, row_id);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
		*prow_count = sqlite3_column_int64(pstmt, 0);
	} else {
		sql_len = sprintf(sql_string, "SELECT row_id, row_stat "
				"FROM t%u WHERE parent_id=?", ptnode->table_id);
		if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
			sql_string, sql_len, &pstmt1, NULL)) {
			sqlite3_finalize(pstmt);
			db_engine_put_db(pdb);
			return FALSE;
		}
		*prow_count = 0;
		if (FALSE == table_traverse_sub_contents(
			ptnode->psorts->ccategories - depth - 1,
			row_id, pstmt, pstmt1, prow_count)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_finalize(pstmt1);
	}
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "UPDATE t%u SET row_stat=1 "
		"WHERE row_id=%llu", ptnode->table_id, row_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (0 == *prow_count) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	sql_len = sprintf(sql_string, "SELECT row_id "
		"FROM t%u WHERE idx>%u ORDER BY idx DESC",
		ptnode->table_id, idx);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET idx=idx+%u"
			" WHERE row_id=?", ptnode->table_id, *prow_count);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		sqlite3_bind_int64(pstmt1, 1,
			sqlite3_column_int64(pstmt, 0));
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt1);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sql_len = sprintf(sql_string, "SELECT row_id, row_stat"
			" FROM t%u WHERE prev_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (FALSE == table_expand_sub_contents(
		ptnode->psorts->ccategories - depth - 1,
		row_id, pstmt, pstmt1, &idx)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		db_engine_put_db(pdb);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_collapse_table(const char *dir,
	uint32_t table_id, uint64_t inst_id, BOOL *pb_found,
	int32_t *pposition, uint32_t *prow_count)
{
	int depth;
	int sql_len;
	DB_ITEM *pdb;
	uint32_t idx;
	uint64_t row_id;
	uint64_t prev_id;
	TABLE_NODE *ptnode;
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (TABLE_TYPE_CONTENT != ptnode->type ||
		2 != rop_util_get_replid(inst_id)) {
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	inst_id = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	sql_len = sprintf(sql_string, "SELECT row_id, row_type, "
		"row_stat, depth, idx FROM t%u WHERE inst_id=%llu AND"
		" inst_num=0", ptnode->table_id, inst_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (SQLITE_ROW != sqlite3_step(pstmt) ||
		CONTENT_ROW_HEADER != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		*pb_found = FALSE;
		db_engine_put_db(pdb);
		return TRUE;
	}
	*pb_found = TRUE;
	if (0 == sqlite3_column_int64(pstmt, 2)) {
		sqlite3_finalize(pstmt);
		*pposition = -1;
		db_engine_put_db(pdb);
		return TRUE;
	}
	row_id = sqlite3_column_int64(pstmt, 0);
	depth = sqlite3_column_int64(pstmt, 3);
	idx = sqlite3_column_int64(pstmt, 4);
	*pposition = idx - 1;
	sqlite3_finalize(pstmt);
	sprintf(sql_string, "UPDATE t%u SET row_stat=0 "
		"WHERE row_id=%llu", ptnode->table_id, row_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	*prow_count = 0;
	prev_id = row_id;
	sql_len = sprintf(sql_string, "SELECT row_id, "
			"depth, prev_id FROM t%u WHERE idx>%u "
			"ORDER BY idx ASC", ptnode->table_id, idx);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		row_id = sqlite3_column_int64(pstmt, 0);
		if (0 != prev_id &&
			(depth > sqlite3_column_int64(pstmt, 1) ||
			prev_id == sqlite3_column_int64(pstmt, 2))) {
			if (0 == *prow_count) {
				break;
			}
			prev_id = 0;
		}
		if (0 != prev_id) {
			(*prow_count) ++;
			sqlite3_bind_null(pstmt1, 1);
		} else {
			idx ++;
			sqlite3_bind_int64(pstmt1, 1, idx);
		}
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt1);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_store_table_state(const char *dir,
	uint32_t table_id, uint64_t inst_id,
	uint32_t inst_num, uint32_t *pstate_id)
{
	int i;
	int depth;
	int sql_len;
	DB_ITEM *pdb;
	void *pvalue;
	uint16_t type;
	uint64_t row_id;
	uint64_t last_id;
	sqlite3 *psqlite;
	uint64_t inst_id1;
	EXT_PUSH ext_push;
	char tmp_path[256];
	TABLE_NODE *ptnode;
	char tmp_buff[1024];
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	uint32_t tmp_proptag;
	char sql_string[1024];
	struct stat node_stat;
	DOUBLE_LIST_NODE *pnode;
	
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	*pstate_id = 0;
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (TABLE_TYPE_CONTENT != ptnode->type) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	sprintf(tmp_path, "%s/tmp/state.sqlite3", exmdb_server_get_dir());
	if (0 != stat(tmp_path, &node_stat)) {
		if (SQLITE_OK != sqlite3_open_v2(tmp_path, &psqlite,
			SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_exec(psqlite, "PRAGMA journal_mode=OFF", NULL, NULL, NULL);
		sqlite3_exec(psqlite, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
		sprintf(sql_string,
			"CREATE TABLE state_info "
			"(state_id INTEGER PRIMARY KEY AUTOINCREMENT, "
			"folder_id INTEGER NOT NULL, "
			"table_flags INTEGER NOT NULL, "
			"sorts BLOB, "
			"message_id INTEGER DEFAULT NULL, "
			"inst_num INTEGER DEFAULT NULL, "
			"header_id INTEGER DEFAULT NULL, "
			"header_stat INTEGER DEFAULT NULL)");
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_close(psqlite);
			remove(tmp_path);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sprintf(sql_string, "CREATE UNIQUE INDEX state_index"
			" ON state_info (folder_id, table_flags, sorts)");
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_close(psqlite);
			remove(tmp_path);
			db_engine_put_db(pdb);
			return FALSE;
		}
	} else {
		if (SQLITE_OK != sqlite3_open_v2(tmp_path,
			&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_exec(psqlite, "PRAGMA journal_mode=OFF", NULL, NULL, NULL);
		sqlite3_exec(psqlite, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
	}
	if (NULL != ptnode->psorts && 0 != ptnode->psorts->ccategories) {
		sql_len = sprintf(sql_string, "SELECT state_id FROM "
			"state_info WHERE folder_id=? AND table_flags=? "
			"AND sorts=?");
	} else {
		sql_len = sprintf(sql_string, "SELECT state_id FROM "
			"state_info WHERE folder_id=? AND table_flags=? "
			"AND sorts IS NULL");
	}
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_bind_int64(pstmt, 1, ptnode->folder_id);
	sqlite3_bind_int64(pstmt, 2, ptnode->table_flags);
	if (NULL != ptnode->psorts && 0 != ptnode->psorts->ccategories) {
		ext_buffer_push_init(&ext_push,
			tmp_buff, sizeof(tmp_buff), 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_sortorder_set(
			&ext_push, ptnode->psorts)) {
			sqlite3_finalize(pstmt);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_bind_blob(pstmt, 3, ext_push.data,
			ext_push.offset, SQLITE_STATIC);
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		*pstate_id = sqlite3_column_int64(pstmt, 0);
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	if (0 == *pstate_id) {
		sql_len = sprintf(sql_string, "INSERT INTO state_info"
			"(folder_id, table_flags, sorts) VALUES (?, ?, ?)");
		if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
			sql_string, sql_len, &pstmt, NULL)) {
			sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_bind_int64(pstmt, 1, ptnode->folder_id);
		sqlite3_bind_int64(pstmt, 2, ptnode->table_flags);
		if (NULL == ptnode->psorts || 0 == ptnode->psorts->ccategories) {
			sqlite3_bind_null(pstmt, 3);
		} else {
			sqlite3_bind_blob(pstmt, 3, ext_push.data,
				ext_push.offset, SQLITE_STATIC);
		}
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
		*pstate_id = sqlite3_last_insert_rowid(psqlite);
		sqlite3_finalize(pstmt);
	} else {
		if (NULL != ptnode->psorts && 0 != ptnode->psorts->ccategories) {
			sprintf(sql_string, "DROP TABLE s%u", *pstate_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(psqlite);
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
		if (1 != rop_util_get_replid(inst_id)) {
			sprintf(sql_string, "UPDATE "
				"state_info SET message_id=NULL, "
				"inst_num=NULL WHERE state_id=%u",
				*pstate_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(psqlite);
				db_engine_put_db(pdb);
				return FALSE;
			}
		}
	}
	if (1 == rop_util_get_replid(inst_id)) {
		sprintf(sql_string, "UPDATE "
			"state_info SET message_id=%llu, "
			"inst_num=%u WHERE state_id=%u",
			rop_util_get_gc_value(inst_id),
			inst_num, *pstate_id);
		if (SQLITE_OK != sqlite3_exec(psqlite,
			sql_string, NULL, NULL, NULL)) {
			sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	if (NULL == ptnode->psorts || 0 == ptnode->psorts->ccategories) {
		sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return TRUE;
	}
	sql_len = sprintf(sql_string, "CREATE TABLE s%u "
			"(depth INTEGER NOT NULL ", *pstate_id);
	for (i=0; i<ptnode->psorts->ccategories; i++) {
		tmp_proptag = ptnode->psorts->psort[i].propid;
		tmp_proptag <<= 16;
		tmp_proptag |= ptnode->psorts->psort[i].type;
		if (ptnode->instance_tag == tmp_proptag) {
			type = ptnode->psorts->psort[i].type & (~0x3000);
		} else {
			type = ptnode->psorts->psort[i].type;
		}
		switch (type) {
		case PROPVAL_TYPE_STRING:
		case PROPVAL_TYPE_WSTRING:
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", v%x TEXT", tmp_proptag);
			break;
		case PROPVAL_TYPE_FLOAT:
		case PROPVAL_TYPE_DOUBLE:
		case PROPVAL_TYPE_FLOATINGTIME:
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", v%x REAL", tmp_proptag);
			break;
		case PROPVAL_TYPE_CURRENCY:
		case PROPVAL_TYPE_LONGLONG:
		case PROPVAL_TYPE_FILETIME:
		case PROPVAL_TYPE_SHORT:
		case PROPVAL_TYPE_LONG:
		case PROPVAL_TYPE_BYTE:
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", v%x INTEGER", tmp_proptag);
			break;
		case PROPVAL_TYPE_GUID:
		case PROPVAL_TYPE_SVREID:
		case PROPVAL_TYPE_OBJECT:
		case PROPVAL_TYPE_BINARY:
			sql_len += snprintf(sql_string + sql_len,
						sizeof(sql_string) - sql_len,
						", v%x BLOB", tmp_proptag);
			break;
		default:
			sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sql_string[sql_len] = ')';
	sql_len ++;
	sql_string[sql_len] = '\0';
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT row_id, inst_id,"
			" row_stat, depth FROM t%u", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "INSERT"
		" INTO s%u VALUES (?", *pstate_id);
	for (i=0; i<ptnode->psorts->ccategories; i++) {
		sql_len += snprintf(sql_string + sql_len,
			sizeof(sql_string) - sql_len, ", ?");
	}
	sql_string[sql_len] = ')';
	sql_len ++;
	sql_string[sql_len] = '\0';
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT parent_id FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT value FROM"
			" t%u WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt3, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_finalize(pstmt2);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;
	}
	if (2 == rop_util_get_replid(inst_id)) {
		inst_id1 = rop_util_get_gc_value(inst_id) | 0x100000000000000ULL;
	} else {
		inst_id1 = 0;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		depth = sqlite3_column_int64(pstmt, 3);
		if (ptnode->psorts->ccategories == depth) {
			continue;	
		}
		if (inst_id1 == sqlite3_column_int64(pstmt, 1)) {
			last_id = sqlite3_last_insert_rowid(psqlite);
			sprintf(sql_string, "UPDATE state_info SET header_id=%llu,"
				" header_stat=%llu WHERE state_id=%u", last_id + 1,
				sqlite3_column_int64(pstmt, 2), *pstate_id);
			if (SQLITE_OK != sqlite3_exec(psqlite,
				sql_string, NULL, NULL, NULL)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				sqlite3_finalize(pstmt3);
				sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(psqlite);
				db_engine_put_db(pdb);
				return FALSE;
			}
		} else {
			if (0 == sqlite3_column_int64(pstmt, 2)) {
				if (depth >= ptnode->psorts->cexpanded) {
					continue;
				}
			} else {
				if (depth < ptnode->psorts->cexpanded) {
					continue;
				}
			}
		}
		sqlite3_bind_int64(pstmt1, 1, depth);
		row_id = sqlite3_column_int64(pstmt, 0);
		i = depth;
		while (TRUE) {
			sqlite3_bind_int64(pstmt3, 1, row_id);
			if (0x3000 == (ptnode->psorts->psort[i].type & 0x3000)) {
				type = ptnode->psorts->psort[i].type & (~0x3000);
			} else {
				type = ptnode->psorts->psort[i].type;
			}
			if (SQLITE_ROW != sqlite3_step(pstmt3)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				sqlite3_finalize(pstmt3);
				sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(psqlite);
				db_engine_put_db(pdb);
				return FALSE;
			}
			pvalue = common_util_column_sqlite_statement(pstmt3, 0, type);
			sqlite3_reset(pstmt3);
			if (NULL == pvalue) {
				sqlite3_bind_null(pstmt1, i + 2);
			} else {
				if (FALSE == common_util_bind_sqlite_statement(
					pstmt1, i + 2, type, pvalue)) {
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					sqlite3_finalize(pstmt2);
					sqlite3_finalize(pstmt3);
					sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
					sqlite3_close(psqlite);
					db_engine_put_db(pdb);
					return FALSE;	
				}
			}
			if (0 == i) {
				break;
			}
			i --;
			sqlite3_bind_int64(pstmt2, 1, row_id);
			if (SQLITE_ROW != sqlite3_step(pstmt2)) {
				sqlite3_finalize(pstmt);
				sqlite3_finalize(pstmt1);
				sqlite3_finalize(pstmt2);
				sqlite3_finalize(pstmt3);
				sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
				sqlite3_close(psqlite);
				db_engine_put_db(pdb);
				return FALSE;
			}
			row_id = sqlite3_column_int64(pstmt2, 0);
			sqlite3_reset(pstmt2);
		}
		for (i=depth+1; i<ptnode->psorts->ccategories; i++) {
			sqlite3_bind_null(pstmt1, i + 2);
		}
		if (SQLITE_DONE != sqlite3_step(pstmt1)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_finalize(pstmt2);
			sqlite3_finalize(pstmt3);
			sqlite3_exec(psqlite, "ROLLBACK", NULL, NULL, NULL);
			sqlite3_close(psqlite);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt1);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sqlite3_finalize(pstmt2);
	sqlite3_finalize(pstmt3);
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	db_engine_put_db(pdb);
	return TRUE;
}

BOOL exmdb_server_restore_table_state(const char *dir,
	uint32_t table_id, uint32_t state_id, int32_t *pposition)
{
	int i;
	int depth;
	int sql_len;
	DB_ITEM *pdb;
	void *pvalue;
	uint32_t idx;
	uint16_t type;
	uint64_t row_id;
	uint64_t row_id1;
	uint8_t row_stat;
	sqlite3 *psqlite;
	uint64_t inst_num;
	EXT_PUSH ext_push;
	char tmp_path[256];
	TABLE_NODE *ptnode;
	uint64_t header_id;
	uint64_t message_id;
	uint8_t header_stat;
	uint64_t current_id;
	char tmp_buff[1024];
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	sqlite3_stmt *pstmt2;
	sqlite3_stmt *pstmt3;
	uint32_t tmp_proptag;
	char sql_string[1024];
	struct stat node_stat;
	DOUBLE_LIST_NODE *pnode;
	
	row_id1 = 0;
	*pposition = -1;
	if (0 == state_id) {
		return TRUE;
	}
	pdb = db_engine_get_db(dir);
	if (NULL == pdb) {
		return FALSE;
	}
	if (NULL == pdb->psqlite) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pdb->tables.table_list); NULL!=pnode;
		pnode=double_list_get_after(&pdb->tables.table_list, pnode)) {
		if (table_id == ((TABLE_NODE*)pnode->pdata)->table_id) {
			break;
		}
	}
	if (NULL == pnode) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	ptnode = (TABLE_NODE*)pnode->pdata;
	if (TABLE_TYPE_CONTENT != ptnode->type) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	sprintf(tmp_path, "%s/tmp/state.sqlite3", exmdb_server_get_dir());
	if (0 != stat(tmp_path, &node_stat)) {
		db_engine_put_db(pdb);
		return TRUE;
	}
	if (SQLITE_OK != sqlite3_open_v2(tmp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		db_engine_put_db(pdb);
		return FALSE;
	}
	sqlite3_exec(psqlite, "PRAGMA journal_mode=OFF", NULL, NULL, NULL);
	sqlite3_exec(psqlite, "PRAGMA synchronous=OFF", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT folder_id, table_flags,"
			" sorts, message_id, inst_num, header_id, header_stat"
			" FROM state_info WHERE state_id=%u", state_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return FALSE;	
	}
	if (SQLITE_ROW != sqlite3_step(pstmt)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		db_engine_put_db(pdb);
		return TRUE;
	}
	message_id = sqlite3_column_int64(pstmt, 3);
	inst_num = sqlite3_column_int64(pstmt, 4);
	if (ptnode->folder_id != sqlite3_column_int64(pstmt, 0) ||
		ptnode->table_flags != sqlite3_column_int64(pstmt, 1)) {
		sqlite3_finalize(pstmt);
		goto RESTORE_POSITION;
	}
	if (NULL == ptnode->psorts || 0 == ptnode->psorts->ccategories) {
		if (SQLITE_NULL != sqlite3_column_type(pstmt, 2)) {
			sqlite3_finalize(pstmt);
			goto RESTORE_POSITION;
		}
	} else {
		ext_buffer_push_init(&ext_push,
			tmp_buff, sizeof(tmp_buff), 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_sortorder_set(
			&ext_push, ptnode->psorts)) {
			sqlite3_finalize(pstmt);
			goto RESTORE_POSITION;
		}
		if (ext_push.offset != sqlite3_column_bytes(pstmt, 2)
			|| 0 != memcmp(sqlite3_column_blob(pstmt, 2),
			ext_push.data, ext_push.offset)) {
			sqlite3_finalize(pstmt);
			goto RESTORE_POSITION;
		}
	}
	header_id = sqlite3_column_int64(pstmt, 5);
	header_stat = sqlite3_column_int64(pstmt, 6);
	sqlite3_finalize(pstmt);
	if (NULL == ptnode->psorts || 0 == ptnode->psorts->ccategories) {
		sqlite3_close(psqlite);
		goto RESTORE_POSITION;
	}
	sqlite3_exec(pdb->tables.psqlite,
		"BEGIN TRANSACTION", NULL, NULL, NULL);
	/* reset table into initial state */
	sql_len = sprintf(sql_string, "SELECT row_id, "
		"row_stat, depth FROM t%u WHERE row_type=%u",
		ptnode->table_id, CONTENT_ROW_HEADER);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET "
		"row_stat=? WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt1);
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		row_id = sqlite3_column_int64(pstmt, 0);
		row_stat = sqlite3_column_int64(pstmt, 1);
		depth = sqlite3_column_int64(pstmt, 2);
		if (depth >= ptnode->psorts->cexpanded) {
			if (0 == row_stat) {
				continue;
			}
			row_stat = 0;
		} else {
			if (0 != row_stat) {
				continue;
			}
			row_stat = 1;
		}
		sqlite3_bind_int64(pstmt1, 1, row_stat);
		sqlite3_bind_int64(pstmt1, 2, row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_close(psqlite);
			sqlite3_exec(pdb->tables.psqlite,
				"ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt1);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	/* end of resetting table */
	sql_len = sprintf(sql_string, "SELECT * FROM"
			" s%u ORDER BY ROWID ASC", state_id);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT row_id FROM t%u WHERE"
			" parent_id=? AND value IS NULL", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT row_id FROM t%u WHERE"
				" parent_id=? AND value=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt2, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET "
		"row_stat=? WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt3, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_finalize(pstmt1);
		sqlite3_finalize(pstmt2);
		sqlite3_close(psqlite);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	current_id = 0;
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		current_id ++;
		depth = sqlite3_column_int64(pstmt, 0);
		row_id = 0;
		for (i=0; i<=depth; i++) {
			if (0x3000 == (ptnode->psorts->psort[i].type & 0x3000)) {
				type = ptnode->psorts->psort[i].type& (~0x3000);
			} else {
				type = ptnode->psorts->psort[i].type;
			}
			pvalue = common_util_column_sqlite_statement(pstmt, i + 1, type);
			if (NULL == pvalue) {
				sqlite3_bind_int64(pstmt1, 1, row_id);
				if (SQLITE_ROW != sqlite3_step(pstmt1)) {
					sqlite3_reset(pstmt1);
					break;
				}
				row_id = sqlite3_column_int64(pstmt1, 0);
				sqlite3_reset(pstmt1);
			} else {
				sqlite3_bind_int64(pstmt2, 1, row_id);
				if (FALSE == common_util_bind_sqlite_statement(
					pstmt2, 2, type, pvalue)) {
					sqlite3_finalize(pstmt);
					sqlite3_finalize(pstmt1);
					sqlite3_finalize(pstmt2);
					sqlite3_finalize(pstmt3);
					sqlite3_close(psqlite);
					sqlite3_exec(pdb->tables.psqlite,
						"ROLLBACK", NULL, NULL, NULL);
					db_engine_put_db(pdb);
					return FALSE;
				}
				if (SQLITE_ROW != sqlite3_step(pstmt2)) {
					sqlite3_reset(pstmt2);
					break;
				}
				row_id = sqlite3_column_int64(pstmt2, 0);
				sqlite3_reset(pstmt2);
			}
		}
		if (i <= depth) {
			continue;
		}
		if (header_id == current_id) {
			row_stat = header_stat;
			row_id1 = row_id;
		} else {
			if (depth >= ptnode->psorts->cexpanded) {
				row_stat = 1;
			} else {
				row_stat = 0;
			}
		}
		sqlite3_bind_int64(pstmt3, 1, row_stat);
		sqlite3_bind_int64(pstmt3, 2, row_id);
		if (SQLITE_DONE != sqlite3_step(pstmt3)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_finalize(pstmt2);
			sqlite3_finalize(pstmt3);
			sqlite3_close(psqlite);
			sqlite3_exec(pdb->tables.psqlite,
				"ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
		sqlite3_reset(pstmt3);
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sqlite3_finalize(pstmt2);
	sqlite3_finalize(pstmt3);
	sqlite3_close(psqlite);
	sprintf(sql_string, "UPDATE t%u SET idx=NULL", ptnode->table_id);
	if (SQLITE_OK != sqlite3_exec(pdb->tables.psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
		return FALSE;
	}
	sql_len = sprintf(sql_string, "SELECT row_id, row_stat"
			" FROM t%u WHERE prev_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
	}
	sql_len = sprintf(sql_string, "UPDATE t%u SET"
		" idx=? WHERE row_id=?", ptnode->table_id);
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_exec(pdb->tables.psqlite,
			"ROLLBACK", NULL, NULL, NULL);
		db_engine_put_db(pdb);
	}
	idx = 0;
	sqlite3_bind_int64(pstmt, 1, 0);
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		if (FALSE == common_util_indexing_sub_contents(
			ptnode->psorts->ccategories, pstmt,
			pstmt1, &idx)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_exec(pdb->tables.psqlite,
				"ROLLBACK", NULL, NULL, NULL);
			db_engine_put_db(pdb);
			return FALSE;
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_finalize(pstmt1);
	sqlite3_exec(pdb->tables.psqlite,
		"COMMIT TRANSACTION", NULL, NULL, NULL);
RESTORE_POSITION:
	if (0 != message_id) {
		sql_len = sprintf(sql_string, "SELEC idx FROM t%u WHERE "
				"inst_id=%llu AND inst_num=%u", ptnode->table_id,
				message_id, inst_num);
	} else {
		sql_len = sprintf(sql_string, "SELEC idx FROM t%u WHERE"
					" row_id=%llu", ptnode->table_id, row_id1);
	}
	if (SQLITE_OK != sqlite3_prepare_v2(pdb->tables.psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		db_engine_put_db(pdb);
	}
	if (SQLITE_ROW == sqlite3_step(pstmt)) {
		*pposition = sqlite3_column_int64(pstmt, 0) - 1;
	} else {
		*pposition = -1;
	}
	sqlite3_finalize(pstmt);
	db_engine_put_db(pdb);
	return TRUE;
}

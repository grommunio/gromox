#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include "util.h"
#include "smtp.h"
#include "mail.h"
#include "engine.h"
#include "message.h"
#include "proptags.h"
#include "list_file.h"
#include "system_log.h"
#include "double_list.h"
#include "data_source.h"
#include "midb_client.h"
#include "locker_client.h"

#define TYPE_USER_AREA			0
#define TYPE_DOMAIN_AREA		1
#define TYPE_MEDIA_AREA		    2
#define VDIR_PER_PARTITION		200


typedef struct _PARTITION_ITEM {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
	int type;
	char master[256];
	char slave[256];
} PARTITION_ITEM;

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;

static BOOL g_created;
static int g_log_days;
static int g_valid_days;
static char g_db_name[256];
static pthread_t g_backup_id;
static char g_list_path[256];
static char g_backup_path[256];
static BOOL g_parellel_scanning;
static BOOL g_freetime_scanning;
static char g_admin_mailbox[256];
static char g_default_domain[256];
static DOUBLE_LIST g_partition_list;


static BOOL engine_clean_and_calculate_maildir(
	const char *path, const char *slave_path,
	uint64_t *pbytes, int *pfiles);
	
static BOOL engine_clean_and_calculate_homedir(
	const char *path, const char *slave_path,
	uint64_t *pbytes, int *pfiles);

static void engine_backup_dir(char *master, char *slave);

static void engine_remove_inode(const char *path);

static void engine_copy_file(char *src_file, char *dst_file, size_t size);

static int engine_compare_file(const char *file1, char *file2, size_t size);

static void engine_compress(const char *src_path, const char *dst_file);

static BOOL engine_check_format(const char *filename);

static void engine_read_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes);

static void engine_homedirlog_cleaning(const char *path);

static void *scan_work_func(void *param);

static void *backup_work_func(void *param);

static void engine_get_dirsize(const char *path,
	uint64_t *pbytes, int *pfiles)
{
	DIR *dirp;
	int temp_files;
	char temp_path[256];
	uint64_t temp_bytes;
	struct stat node_stat;
	struct dirent *direntp;

	*pbytes = 0;
	*pfiles = 0;
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		if (0 == stat(temp_path, &node_stat)) {
			if (0 != S_ISREG(node_stat.st_mode)) {
				*pbytes += node_stat.st_size;
				*pfiles += 1;
			} else if (0 != S_ISDIR(node_stat.st_mode)) {
				engine_get_dirsize(temp_path, &temp_bytes, &temp_files);
				*pbytes += temp_bytes;
				*pfiles += temp_files;
			}
		}
	}
	closedir(dirp);
	return;
}

static void engine_clean_cid(const char *path)
{
	DIR *dirp;
	int sql_len;
	time_t tmp_time;
	sqlite3 *psqlite;
	sqlite3 *psqlite1;
	char tmp_path[256];
	sqlite3_stmt *pstmt;
	sqlite3_stmt *pstmt1;
	char sql_string[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	time(&tmp_time);
	tmp_time -= 24*3600;
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return;
	}
	sprintf(sql_string, "CREATE TABLE cids (cid INTEGER PRIMARY KEY)");
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "INSERT INTO cids VALUES (?)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	sprintf(tmp_path, "%s/exmdb/exchange.sqlite3", path);
	if (SQLITE_OK != sqlite3_open_v2(tmp_path,
		&psqlite1, SQLITE_OPEN_READWRITE, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return;
	}
	sql_len = sprintf(sql_string, "SELECT propval FROM"
		" message_properties WHERE proptag IN (%u, %u,"
		" %u, %u, %u, %u)", PROP_TAG_TRANSPORTMESSAGEHEADERS,
		PROP_TAG_TRANSPORTMESSAGEHEADERS_STRING8, PROP_TAG_BODY,
		PROP_TAG_BODY_STRING8, PROP_TAG_RTFCOMPRESSED, PROP_TAG_HTML);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite1,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_close(psqlite1);
		return;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, sqlite3_column_int64(pstmt1, 0));
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_close(psqlite);
			sqlite3_close(psqlite1);
			return;
		}
	}
	sqlite3_finalize(pstmt1);
	sql_len = sprintf(sql_string, "SELECT propval FROM "
		"attachment_properties WHERE proptag IN (%u, %u)",
		PROP_TAG_ATTACHDATABINARY, PROP_TAG_ATTACHDATAOBJECT);
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite1,
		sql_string, sql_len, &pstmt1, NULL)) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_close(psqlite1);
		return;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt1)) {
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, sqlite3_column_int64(pstmt1, 0));
		if (SQLITE_DONE != sqlite3_step(pstmt)) {
			sqlite3_finalize(pstmt);
			sqlite3_finalize(pstmt1);
			sqlite3_close(psqlite);
			sqlite3_close(psqlite1);
			return;
		}
	}
	sqlite3_finalize(pstmt1);
	sqlite3_close(psqlite1);
	sqlite3_finalize(pstmt);
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT cid FROM cids WHERE cid=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	sprintf(tmp_path, "%s/cid", path);
	dirp = opendir(tmp_path);
	if (NULL == dirp) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_int64(pstmt, 1, atoll(direntp->d_name));
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sprintf(tmp_path, "%s/cid/%s", path, direntp->d_name);
			if (0 != stat(tmp_path, &node_stat) ||
				node_stat.st_mtime > tmp_time) {
				continue;	
			}
			remove(tmp_path);
		}
	}
	closedir(dirp);
	sqlite3_finalize(pstmt);
	sqlite3_close(psqlite);
}

static void engine_clean_eml_and_ext(const char *path)
{
	DIR *dirp;
	int sql_len;
	time_t tmp_time;
	sqlite3 *psqlite;
	char tmp_path[256];
	sqlite3_stmt *pstmt;
	char sql_string[256];
	struct stat node_stat;
	struct dirent *direntp;
	const char *mid_string;
	
	time(&tmp_time);
	tmp_time -= 24*3600;
	if (SQLITE_OK != sqlite3_open_v2(":memory:", &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		return;
	}
	sprintf(sql_string, "CREATE TABLE mid_strings "
					"(mid_string TEXT PRIMARY KEY)");
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "INSERT INTO mid_strings VALUES (?)");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	if (FALSE == midb_client_all_mid_strings(path, pstmt)) {
		system_log_info("[engine]: fail to get all mid strings"
			" from %s/exmdb/midb.sqlite3, sqlite3 database may"
			" be corrupted! verify it ASAP!", path);
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return;
	}
	sqlite3_finalize(pstmt);
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sql_len = sprintf(sql_string, "SELECT mid_string "
				"FROM mid_strings WHERE mid_string=?");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	sprintf(tmp_path, "%s/eml", path);
	dirp = opendir(tmp_path);
	if (NULL == dirp) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (atol(direntp->d_name) > tmp_time) {
			continue;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, direntp->d_name, -1, SQLITE_STATIC);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sprintf(tmp_path, "%s/eml/%s", path, direntp->d_name);
			remove(tmp_path);
		}
	}
	closedir(dirp);
	sprintf(tmp_path, "%s/ext", path);
	dirp = opendir(tmp_path);
	if (NULL == dirp) {
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		if (atol(direntp->d_name) > tmp_time) {
			continue;
		}
		sqlite3_reset(pstmt);
		sqlite3_bind_text(pstmt, 1, direntp->d_name, -1, SQLITE_STATIC);
		if (SQLITE_ROW != sqlite3_step(pstmt)) {
			sprintf(tmp_path, "%s/ext/%s", path, direntp->d_name);
			remove(tmp_path);
		}
	}
	closedir(dirp);
	sqlite3_finalize(pstmt);
	sql_len = sprintf(sql_string, "SELECT mid_string FROM mid_strings");
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, sql_len, &pstmt, NULL)) {
		sqlite3_close(psqlite);
		return;
	}
	while (SQLITE_ROW == sqlite3_step(pstmt)) {
		mid_string = sqlite3_column_text(pstmt, 0);
		sprintf(tmp_path, "%s/eml/%s", path, mid_string);
		if (0 != stat(tmp_path, &node_stat)) {
			midb_client_rewrite_eml(path, mid_string);
		}
	}
	sqlite3_finalize(pstmt);
	sqlite3_close(psqlite);
}

static void engine_cleaning_tmp(const char *path)
{
	DIR *dirp;
	char *pdot;
	time_t tmp_time;
	char temp_name[128];
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	time(&tmp_time);
	tmp_time -= 24*3600;
	snprintf(temp_path, 255, "%s/tmp/imap.rfc822", path);
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strncpy(temp_name, direntp->d_name, 127);
		pdot = strchr(temp_name, '.');
		if (NULL != pdot) {
			*pdot = '\0';
		}
		if (atol(temp_name) > tmp_time) {
			continue;
		}
		snprintf(temp_path, 255, "%s/ext/%s", path, direntp->d_name);
		if (0 == stat(temp_path, &node_stat)) {
			continue;
		}
		snprintf(temp_path, 255, "%s/tmp/imap.rfc822/%s",
			path, direntp->d_name);
		engine_remove_inode(temp_path);
	}
	closedir(dirp);
	snprintf(temp_path, 255, "%s/tmp/faststream", path);
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/tmp/faststream/%s",
			path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (node_stat.st_mtime > tmp_time) {
			continue;	
		}
		remove(temp_path);
	}
	closedir(dirp);
}

static BOOL engine_rebuild_exmdb(const char *path)
{
	pid_t pid;
	int status;
	char* argv[3];
	
	pid = fork();
	if (0 == pid) {
		chdir("../tools");
		argv[0] = "./rebuild";
		argv[1] = (void*)path;
		argv[2] = NULL;
		if (execve("./rebuild", argv, NULL) == -1) {
			exit(-1);
		}
	} else if (pid < 0) {
		return FALSE;
	}
	waitpid(pid, &status, 0);
	if (0 != status) {
		return FALSE;
	}
	return TRUE;
}

static BOOL engine_clean_and_calculate_maildir(
	const char *path, const char *slave_path,
	uint64_t *pbytes, int *pfiles)
{
	DIR *dirp;
	BOOL b_corrupt;
	sqlite3 *psqlite;
	char tmp_path[256];
	char tmp_path1[256];
	char tmp_path2[256];
	const char *presult;
	sqlite3_stmt *pstmt;
	int temp_files, files;
	struct stat node_stat;
	struct dirent *direntp;
	uint64_t bytes, temp_bytes;
	
	sprintf(tmp_path, "%s/exmdb/exchange.sqlite3", path);
	if (SQLITE_OK == sqlite3_open_v2(tmp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		b_corrupt = FALSE;
		if (SQLITE_OK == sqlite3_prepare_v2(psqlite,
			"PRAGMA integrity_check", -1, &pstmt, NULL )) {
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				presult = sqlite3_column_text(pstmt, 0);
				if (NULL == presult || 0 != strcmp(presult, "ok")) {
					b_corrupt = TRUE;
				}
			}
			sqlite3_finalize(pstmt);
		}
		sqlite3_close(psqlite);
		if (TRUE == b_corrupt) {
			if (TRUE == engine_rebuild_exmdb(path)) {
				system_log_info("[engine]: %s/exmdb/exchange.sqlite3"
					" is fixed OK", path);
			} else {
				sprintf(tmp_path2, "%s/exmdb.bak", path);
				if (0 != stat(tmp_path2, &node_stat)) {
					mkdir(tmp_path2, 0777);
					sprintf(tmp_path1, "%s/exmdb", slave_path);
					engine_backup_dir(tmp_path1, tmp_path2);
				}
				system_log_info("[engine]: "
					"%s/exmdb/exchange.sqlite3 is malformed,"
					" cannot be fixed, verify it ASAP!", path);
			}
		}
	}
	sprintf(tmp_path, "%s/exmdb/midb.sqlite3", path);
	if (SQLITE_OK == sqlite3_open_v2(tmp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		b_corrupt = FALSE;
		if (SQLITE_OK == sqlite3_prepare_v2(psqlite,
			"PRAGMA integrity_check", -1, &pstmt, NULL )) {
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				presult = sqlite3_column_text(pstmt, 0);
				if (NULL == presult || 0 != strcmp(presult, "ok")) {
					b_corrupt = TRUE;
				}
			}
			sqlite3_finalize(pstmt);
		}
		sqlite3_close(psqlite);	
		if (TRUE == b_corrupt) {
			sprintf(tmp_path2, "%s/exmdb/midb.sqlite3", slave_path);
			if (0 == stat(tmp_path2, &node_stat) &&
				0 != S_ISREG(node_stat.st_mode) &&
				TRUE == midb_client_unload_db(path)) {
				engine_copy_file(tmp_path2, tmp_path, node_stat.st_size);
			} else {
				system_log_info("[engine]: "
					"%s/exmdb/midb.sqlite3 is malformed,"
					" cannot be fixed, verify it ASAP!", path);
			}
		}
	}
	engine_clean_eml_and_ext(path);
	engine_clean_cid(path);
	engine_cleaning_tmp(path);
	bytes = 0;
	files = 0;
	*pbytes = 0;
	*pfiles = 0;
	dirp = opendir(path);
	if (NULL == dirp) {
		return FALSE;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(tmp_path, 255, "%s/%s", path, direntp->d_name);
		if (0 != stat(tmp_path, &node_stat)) {
			continue;
		}
		if (0 != S_ISREG(node_stat.st_mode)) {
			*pbytes += node_stat.st_size;
			*pfiles += 1;
		} else if (0 != S_ISDIR(node_stat.st_mode)) {
			engine_get_dirsize(tmp_path, &temp_bytes, &temp_files);
			*pbytes += temp_bytes;
			*pfiles += temp_files;
		}
	}
	closedir(dirp);
	return TRUE;
}

static BOOL engine_clean_and_calculate_homedir(
	const char *path, const char *slave_path,
	uint64_t *pbytes, int *pfiles)
{
	DIR *dirp;
	int sql_len;
	BOOL b_corrupt;
	sqlite3 *psqlite;
	sqlite3 *psqlite1;
	char tmp_path[256];
	char tmp_path1[256];
	char tmp_path2[256];
	const char *presult;
	sqlite3_stmt *pstmt;
	char sql_string[256];
	struct stat node_stat;
	int temp_files, files;
	struct dirent *direntp;
	uint64_t bytes, temp_bytes;
	
	sprintf(tmp_path, "%s/exmdb/exchange.sqlite3", path);
	if (SQLITE_OK == sqlite3_open_v2(tmp_path,
		&psqlite, SQLITE_OPEN_READWRITE, NULL)) {
		b_corrupt = FALSE;
		if (SQLITE_OK == sqlite3_prepare_v2(psqlite,
			"PRAGMA integrity_check", -1, &pstmt, NULL )) {
			if (SQLITE_ROW == sqlite3_step(pstmt)) {
				presult = sqlite3_column_text(pstmt, 0);
				if (NULL == presult || 0 != strcmp(presult, "ok")) {
					b_corrupt = TRUE;
				}
			}
			sqlite3_finalize(pstmt);
		}
		sqlite3_close(psqlite);
		if (TRUE == b_corrupt) {
			if (TRUE == engine_rebuild_exmdb(path)) {
				system_log_info("[engine]: %s/exmdb/exchange.sqlite3"
					" is fixed OK", path);
			} else {
				sprintf(tmp_path2, "%s/exmdb.bak", path);
				if (0 != stat(tmp_path2, &node_stat)) {
					mkdir(tmp_path2, 0777);
					sprintf(tmp_path1, "%s/exmdb", slave_path);
					engine_backup_dir(tmp_path1, tmp_path2);
				}
				system_log_info("[engine]: "
					"%s/exmdb/exchange.sqlite3 is malformed,"
					" cannot be fixed, verify it ASAP!", path);
			}
		}
	}
	engine_clean_cid(path);
	snprintf(tmp_path, 255, "%s/log", path);
	engine_homedirlog_cleaning(tmp_path);
	
	bytes = 0;
	files = 0;
	*pbytes = 0;
	*pfiles = 0;
	dirp = opendir(path);
	if (NULL == dirp) {
		return FALSE;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(tmp_path, 255, "%s/%s", path, direntp->d_name);
		if (0 != stat(tmp_path, &node_stat)) {
			continue;
		}
		if (0 != S_ISREG(node_stat.st_mode)) {
			*pbytes += node_stat.st_size;
			*pfiles += 1;
		} else if (0 != S_ISDIR(node_stat.st_mode)) {
			engine_get_dirsize(tmp_path, &temp_bytes, &temp_files);
			*pbytes += temp_bytes;
			*pfiles += temp_files;
		}
	}
	closedir(dirp);
	return TRUE;
}

static void engine_backup_dir(char *master, char *slave)
{
	int len;
	DIR *dirp;
	BOOL b_cid;
	char temp_path[256];
	char temp_path1[256];
	char link_buff[256];
	char link_buff1[256];
	struct dirent *direntp;
	struct stat node_stat;
	struct stat node_stat1;
	
	dirp = opendir(master);
	if (NULL == dirp) {
		return;
	}
	len = strlen(master);
	if (0 == strcmp(master + len - 4, "/cid")) {
		b_cid = TRUE;
	} else {
		b_cid = FALSE;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", master, direntp->d_name);
		snprintf(temp_path1, 255, "%s/%s", slave, direntp->d_name);
		if (0 != lstat(temp_path, &node_stat)) {
			continue;
		}	
		if (0 != S_ISLNK(node_stat.st_mode)) {
			if (0 == strcmp(direntp->d_name, "exmdb")) {
				if (0 != lstat(temp_path1, &node_stat1) ||
					0 == S_ISDIR(node_stat1.st_mode)) {
					engine_remove_inode(temp_path1);
					mkdir(temp_path1, 0777);
				}
				engine_backup_dir(temp_path, temp_path1);
				continue;
			}
			memset(link_buff, 0, 256);
			if (readlink(temp_path, link_buff, 256) <= 0) {
				continue;
			}
			if (0 != lstat(temp_path1, &node_stat1)) {
				symlink(link_buff, temp_path1);
				continue;
			}
			if (0 != S_ISLNK(node_stat1.st_mode)) {
				memset(link_buff1, 0, 256);
				readlink(temp_path1, link_buff1, 256);
				if (0 != strcmp(link_buff, link_buff1)) {
					remove(temp_path1);
					symlink(link_buff, temp_path1);
				}
			} else {
				engine_remove_inode(temp_path1);
				symlink(link_buff, temp_path1);
			}
		} else if (0 != S_ISDIR(node_stat.st_mode)) {
			if (0 != lstat(temp_path1, &node_stat1) ||
				0 == S_ISDIR(node_stat1.st_mode)) {
				engine_remove_inode(temp_path1);
				mkdir(temp_path1, 0777);
			}
			engine_backup_dir(temp_path, temp_path1);
		} else {
			if (0 == lstat(temp_path1, &node_stat1) &&
				0 != S_ISREG(node_stat1.st_mode) &&
				node_stat.st_size == node_stat1.st_size &&
				(TRUE == b_cid || TRUE == engine_check_format(
				direntp->d_name) || 0 == engine_compare_file(
				temp_path, temp_path1, node_stat.st_size))) {
				continue;
			}
			engine_remove_inode(temp_path1);
			engine_copy_file(temp_path, temp_path1, node_stat.st_size);
		}
	}
	closedir(dirp);
	dirp = opendir(slave);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", master, direntp->d_name);
		snprintf(temp_path1, 255, "%s/%s", slave, direntp->d_name);
		if (0 != lstat(temp_path, &node_stat)) {
			engine_remove_inode(temp_path1);
		}
	}
	closedir(dirp);
}

static void engine_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		engine_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}

static void engine_copy_file(char *src_file, char *dst_file, size_t size)
{
	int fd;
	char *pbuff;

	pbuff = (char*)malloc(size);
	if (NULL == pbuff) {
		return;
	}
	fd = open(src_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	if (size != read(fd, pbuff, size)) {
		free(pbuff);
		close(fd);
		return;
	}
	close(fd);
	fd = open(dst_file, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		free(pbuff);
		return;
	}
	write(fd, pbuff, size);
	free(pbuff);
	close(fd);
}

void engine_init(const char *list_path, int log_days,
	int valid_days, const char *default_domain,
	const char *admin_mailbox, const char *db_name,
	const char *backup_path, BOOL parellel_scanning,
	BOOL freetime_scanning)
{
	g_log_days = log_days;
	g_valid_days = valid_days;
	strcpy(g_list_path, list_path);
	strcpy(g_default_domain, default_domain);
	strcpy(g_admin_mailbox, admin_mailbox);
	strcpy(g_db_name, db_name);
	strcpy(g_backup_path, backup_path);
	double_list_init(&g_partition_list);
	g_created = FALSE;
	g_parellel_scanning = parellel_scanning;
	g_freetime_scanning = freetime_scanning;
}

void engine_free()
{
	g_list_path[0] = '\0';
	double_list_free(&g_partition_list);
}

int engine_run()
{
	int i, item_num;
	AREA_ITEM *pitem;
	LIST_FILE *pfile;
	char *pdb_storage;
	PARTITION_ITEM *ppartition;
	
	pfile = list_file_init(g_list_path, "%s:12%s:256%s:256%d%d");

	if (NULL == pfile) {
		printf("[engine]: fail to init list file %s\n", g_list_path);
		return -1;
	}
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	item_num = list_file_get_item_num(pfile);
	
	for (i=0; i<item_num; i++) {
		ppartition = (PARTITION_ITEM*)malloc(sizeof(PARTITION_ITEM));
		if (NULL == ppartition) {
			continue;
		}
		if (0 == strcmp(pitem[i].type, "USER")) {
			ppartition->type = TYPE_USER_AREA;
		} else if (0 == strcmp(pitem[i].type, "DOMAIN")) {
			ppartition->type = TYPE_DOMAIN_AREA;
		} else if (0 == strcmp(pitem[i].type, "MEDIA")) {
			ppartition->type = TYPE_MEDIA_AREA;
		} else {
			free(ppartition);
			continue;
		}
		pdb_storage = strchr(pitem[i].master, ':');
		if (NULL != pdb_storage) {
			*pdb_storage = '\0';
			pdb_storage ++;
		}
		strcpy(ppartition->master, pitem[i].master);
		strcpy(ppartition->slave, pitem[i].slave);
		ppartition->node.pdata = ppartition;
		if (TRUE == g_parellel_scanning) {
			if (0 != pthread_create(&ppartition->thr_id,
				NULL, scan_work_func, ppartition)) {
				free(ppartition);
			} else {
				double_list_append_as_tail(&g_partition_list, &ppartition->node);
			}
		} else {
			double_list_append_as_tail(&g_partition_list, &ppartition->node);
		}
	}
	list_file_free(pfile);
	
	if (0 != pthread_create(&g_backup_id, NULL, backup_work_func, NULL)) {
		printf("[engine]: fail to create mysql backup thread\n");
		return -2;
	}
	g_created = TRUE;
	return 0;

}

int engine_stop()
{
	DOUBLE_LIST_NODE *pnode;
	PARTITION_ITEM *ppartition;

	if (TRUE == g_created) {
		pthread_cancel(g_backup_id);
		g_created = FALSE;
	}
	while (pnode=double_list_get_from_head(&g_partition_list)) {
		ppartition = (PARTITION_ITEM*)pnode->pdata;
		if (TRUE == g_parellel_scanning) {
			pthread_cancel(ppartition->thr_id);
		}
		free(ppartition);
	}
	return 0;
}

static int engine_compare_file(const char *file1, char *file2, size_t size)
{
	char *ptr;
	int fd1, fd2;

	ptr = (char*)malloc(2*size);
	if (NULL == ptr) {
		return -1;
	}
	fd1 = open(file1, O_RDONLY);
	if (-1 == fd1) {
		free(ptr);
		return -1;
	}
	fd2 = open(file2, O_RDONLY);
	if (-1 == fd2) {
		free(ptr);
		close(fd1);
		return -1;
	}
	if (size != read(fd1, ptr, size) || size != read(fd2, ptr + size, size)) {
		free(ptr);
		close(fd1);
		close(fd2);
		return -1;
	}
	close(fd1);
	close(fd2);
	if (0 == memcmp(ptr, ptr + size, size)) {
		free(ptr);
		return 0;
	} else {
		free(ptr);
		return -1;
	}
}

static BOOL engine_check_format(const char *filename)
{
	int i;
	char *pdot;
	const char *ptr;

	pdot = strchr(filename, '.');
	if (pdot - filename > 10 || pdot - filename < 1) {
		return FALSE;
	}
	for (ptr=filename; ptr<pdot; ptr++) {
		if (0 == isdigit(*ptr)) {
			return FALSE;
		}
	}
	ptr = pdot + 1;
	pdot = strchr(ptr, '.');
	if (pdot - ptr > 10 || pdot - ptr < 1) {
		return FALSE;
	}
	for (; ptr<pdot; ptr++) {
		if (0 == isdigit(*ptr)) {
			return FALSE;
		}
	}
	return TRUE;
}

static void engine_check_working_time()
{
	time_t cur_time;
	struct tm temp_tm;
	
	if (TRUE == g_freetime_scanning) {
		time(&cur_time);
		localtime_r(&cur_time, &temp_tm);
		if (temp_tm.tm_hour >= 7 && temp_tm.tm_hour < 19) {
			sleep((18 - temp_tm.tm_hour) * 3600 + (59 -
				temp_tm.tm_min)*60 + 60 - temp_tm.tm_sec);
		}
	}
}

static void *engine_scan_partition(PARTITION_ITEM *ppartition)
{
	DIR *dirp;
	LOCKD lockd;
	char *pdomain;
	uint64_t bytes;
	int i, fd, len;
	int total_files;
	time_t cur_time;
	char time_str[32];
	char temp_path[256];
	uint64_t total_bytes;
	char temp_path1[256];
	char sender_buff[256];
	struct stat node_stat;
	struct dirent *direntp;
	int megas, files, homes;
	char temp_buff[MESSAGE_BUFF_SIZE];
	
	total_bytes = 0;
	total_files = 0;

	for (i=1; i<=VDIR_PER_PARTITION; i++) {
		snprintf(temp_path, 255, "%s/v%d", ppartition->master, i);
		dirp = opendir(temp_path);
		if (NULL == dirp) {
			continue;
		}
		while ((direntp = readdir(dirp)) != NULL) {
			if (0 == strcmp(direntp->d_name, ".") ||
				0 == strcmp(direntp->d_name, "..") ||
				0 == strcmp(direntp->d_name, "vinfo")) {
				continue;
			}
			engine_check_working_time();
			snprintf(temp_path, 255, "%s/v%d/%s",
				ppartition->master, i, direntp->d_name);
			if (0 != lstat(temp_path, &node_stat)) {
				continue;
			}
			snprintf(temp_path1, 255, "%s/v%d/%s",
				ppartition->slave, i, direntp->d_name);
			if (TYPE_USER_AREA == ppartition->type) {
				if (FALSE == engine_clean_and_calculate_maildir(
					temp_path, temp_path1, &bytes, &files)) {
					continue;
				}
			} else if (TYPE_DOMAIN_AREA == ppartition->type) {
				if (FALSE == engine_clean_and_calculate_homedir(
					temp_path, temp_path1, &bytes, &files)) {
					continue;
				}
			} else {
				engine_get_dirsize(temp_path, &bytes, &files);
			}

			if (0 == S_ISLNK(node_stat.st_mode)) {
				total_bytes += bytes;
				total_files += files;
			}
		}
		closedir(dirp);
	
		snprintf(temp_path, 255, "%s/v%d", ppartition->master, i);
		snprintf(temp_path1, 255, "%s/v%d", ppartition->slave, i);
		if (0 != stat(temp_path1, &node_stat) ||
			0 == S_ISDIR(node_stat.st_mode)) {
			engine_remove_inode(temp_path1);
			mkdir(temp_path1, 0777);
		}
		engine_backup_dir(temp_path, temp_path1);
	}

	if (TYPE_USER_AREA == ppartition->type) {
		lockd = locker_client_lock("USER-AREA");	
	} else if (TYPE_DOMAIN_AREA == ppartition->type) {
		lockd = locker_client_lock("DOMAIN-AREA");
	} else {
		lockd = locker_client_lock("MEDIA-AREA");
	}
	time(&cur_time);
	snprintf(temp_path, 255, "%s/pinfo", ppartition->master);
	snprintf(temp_path1, 255, "%s/pinfo.%d", ppartition->master, cur_time);
	fd = open(temp_path, O_RDONLY);
	if (-1 != fd) {
		len = read(fd, temp_buff, 1024);
		close(fd);
		if (len < 0) {
			len = 0;
		}
		temp_buff[len] = '\0';
		engine_read_partition_info(temp_buff, &megas, &files, &homes);
		if (homes >= 0) {
			fd = open(temp_path1, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1 != fd) {
				len = sprintf(temp_buff, "%dM,%dC,%dH",
						(int)(total_bytes/(1024*1024)), total_files, homes);
				write(fd, temp_buff, len);
				close(fd);
				rename(temp_path1, temp_path);
				snprintf(temp_path1, 255, "%s/pinfo", ppartition->slave);
				engine_copy_file(temp_path, temp_path1, len);
			}
		}
	}
	locker_client_unlock(lockd);
	
	snprintf(temp_path, 255, "%s/test.tmp", ppartition->master);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd || 8 != write(fd, "testing\n", 8)) {
		message_alarm_message(temp_buff,
			ppartition->master, g_admin_mailbox);
		pdomain = strchr(g_admin_mailbox, '@');
		if (NULL != pdomain) {
			pdomain ++;
			if (0 == strcasecmp(pdomain, g_default_domain)) {
				smtp_send_message("supervise-alarm@system.mail",
					g_admin_mailbox, temp_buff);
			} else {
				sprintf(sender_buff, "supervise-alarm@%s",
					g_default_domain);
				smtp_send_message(sender_buff,
					g_admin_mailbox, temp_buff);
			}
		}
	}

	if (-1 != fd) {
		close(fd);
		remove(temp_path);
	}
	
	snprintf(temp_path, 255, "%s/test.tmp", ppartition->slave);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd || 8 != write(fd, "testing\n", 8)) {
		message_alarm_message(temp_buff,
			ppartition->slave, g_admin_mailbox);
		pdomain = strchr(g_admin_mailbox, '@');
		if (NULL != pdomain) {
			pdomain ++;
			if (0 == strcasecmp(pdomain, g_default_domain)) {
				smtp_send_message("supervise-alarm@system.mail",
					g_admin_mailbox, temp_buff);
			} else {
				sprintf(sender_buff, "supervise-alarm@%s",
					g_default_domain);
				smtp_send_message(sender_buff,
					g_admin_mailbox, temp_buff);
			}
		}
	}
	if (-1 != fd) {
		close(fd);
		remove(temp_path);
	}
}

static void *scan_work_func(void *param)
{
	time_t end_time;
	time_t begin_time;
	
	while (TRUE) {
		time(&begin_time);
		engine_scan_partition(param);
		time(&end_time);
		sleep(24*60*60 - (end_time - begin_time) % (24*60*60));
	}
}

static void *backup_work_func(void *param)
{
	void *pmysql;
	time_t end_time;
	time_t begin_time;
	char temp_path[256];
	char temp_path1[256];
	DOUBLE_LIST_NODE *pnode;
	
	while (TRUE) {
		time(&begin_time);
		if (TRUE == data_source_get_datadir(temp_path)) {
			strcat(temp_path, "/");
			strcat(temp_path, g_db_name);
			pmysql = data_source_lock_flush();
			if (NULL != pmysql) {
				snprintf(temp_path1, 255, "%s/%s.bak.tgz",
					g_backup_path, g_db_name);
				engine_compress(temp_path, temp_path1);
				snprintf(temp_path, 255, "%s/%s.tgz",
					g_backup_path, g_db_name);
				rename(temp_path1, temp_path);
				data_source_unlock(pmysql);
				pmysql = NULL;
			}
		}
		if (FALSE == g_parellel_scanning) {
			for (pnode=double_list_get_head(&g_partition_list); NULL!=pnode;
				pnode=double_list_get_after(&g_partition_list, pnode)) {
				engine_scan_partition(pnode->pdata);
			}
		}
		time(&end_time);
		sleep(24*60*60 - (end_time - begin_time) % (24*60*60));
	}
}

static void engine_read_partition_info(char *s,
	int *pmegas, int *pfiles, int *phomes)
{
	char *plast;
	char *ptoken;
	
	plast = s;
	ptoken = strchr(plast, 'M');
	if (NULL == ptoken) {
		*pmegas = -1;
	} else {
		*ptoken = '\0';
		*pmegas = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'C');
	if (NULL == ptoken) {
		*pfiles = -1;
	} else {
		*ptoken = '\0';
		*pfiles = atoi(plast);
		if (',' == *(ptoken + 1)) {
			ptoken ++;
		}
		plast = ptoken + 1;
	}
	ptoken = strchr(plast, 'H');
	if (NULL == ptoken) {
		*phomes = -1;
	} else {
		*ptoken = '\0';
		*phomes = atoi(plast);
	}
}

static void engine_homedirlog_cleaning(const char *path)
{
	DIR *dirp;
	time_t cur_time;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	time(&cur_time);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..") ||
			0 == strcmp(direntp->d_name, "statistic.txt")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		if (0 == stat(temp_path, &node_stat) && cur_time
			- node_stat.st_mtime > g_log_days*24*60*60) {
			remove(temp_path);
		}
	}
	closedir(dirp);
}

static void engine_compress(const char *src_path, const char *dst_file)
{
	pid_t pid;
	int status;
	char *args[] = {"tar", "czf", NULL, "-C", NULL, ".", NULL};

	pid = fork();
	if (0 == pid) {
		args[2] = (char*)dst_file;
		args[4] = (char*)src_path;
		execvp("tar", args);
	} else if (pid > 0) {
		waitpid(pid, &status, 0);
	}
}

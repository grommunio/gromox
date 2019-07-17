#include "midb_tool.h"
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>


#define CONFIG_ID_USERNAME				1

static char g_data_path[256];

void midb_tool_init(const char *data_path)
{
	strcpy(g_data_path, data_path);
}

int midb_tool_run()
{
	return 0;
}

int midb_tool_stop()
{
	return 0;
}

void midb_tool_free()
{
	/* do nothing */
}

BOOL midb_tool_create(const char *dir, const char *username)
{
	int fd;
	int str_size;
	char *err_msg;
	char *sql_string;
	sqlite3 *psqlite;
	char temp_path[256];
	sqlite3_stmt* pstmt;
	struct stat node_stat;
	
	sprintf(temp_path, "%s/sqlite3_midb.txt", g_data_path);
	if (0 != stat(temp_path, &node_stat)) {
		return FALSE;
	}
	if (0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	str_size = node_stat.st_size;
	
	sql_string = malloc(str_size + 1);
	if (NULL == sql_string) {
		return FALSE;
	}
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(sql_string);
		return FALSE;
	}
	if (str_size != read(fd, sql_string, str_size)) {
		close(fd);
		free(sql_string);
		return FALSE;
	}
	close(fd);
	sql_string[str_size] = '\0';
	if (SQLITE_OK != sqlite3_initialize()) {
		free(sql_string);
		return FALSE;
	}
	snprintf(temp_path, 256, "%s/exmdb/midb.sqlite3", dir);
	if (SQLITE_OK != sqlite3_open_v2(temp_path, &psqlite,
		SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
		free(sql_string);
		sqlite3_shutdown();
		return FALSE;
	}
	chmod(temp_path, 0666);
	/* begin the transaction */
	sqlite3_exec(psqlite, "BEGIN TRANSACTION", NULL, NULL, NULL);
	
	if (SQLITE_OK != sqlite3_exec(psqlite,
		sql_string, NULL, NULL, &err_msg)) {
		free(sql_string);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	free(sql_string);
	
	sql_string = "INSERT INTO configurations VALUES (?, ?)";
	if (SQLITE_OK != sqlite3_prepare_v2(psqlite,
		sql_string, strlen(sql_string), &pstmt, NULL)) {
		printf("fail to prepare sql statement\n");
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	
	sqlite3_bind_int64(pstmt, 1, CONFIG_ID_USERNAME);
	sqlite3_bind_text(pstmt, 2, username, -1, SQLITE_STATIC);
	if (sqlite3_step(pstmt) != SQLITE_DONE) {
		printf("fail to step sql inserting\n");
		sqlite3_finalize(pstmt);
		sqlite3_close(psqlite);
		sqlite3_shutdown();
		return FALSE;
	}
	sqlite3_finalize(pstmt);
	
	/* commit the transaction */
	sqlite3_exec(psqlite, "COMMIT TRANSACTION", NULL, NULL, NULL);
	sqlite3_close(psqlite);
	sqlite3_shutdown();
	return TRUE;
}

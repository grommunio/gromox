#pragma once
#include "double_list.h"
#include <mysql/mysql.h>


enum {
	MYSQL_POOL_ALIVE_CONNECTION,
	MYSQL_POOL_DEAD_CONNECTION
};

typedef struct _MYSQL_CONNECTION {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	MYSQL *pmysql;
} MYSQL_CONNECTION;


void mysql_pool_init(int conn_num, int scan_interval, const char *host,
	int port, const char *user, const char *password, const char *db_name,
	int timeout);
extern int mysql_pool_run(void);
extern int mysql_pool_stop(void);
extern void mysql_pool_free(void);
extern MYSQL_CONNECTION *mysql_pool_get_connection(void);
void mysql_pool_put_connection(MYSQL_CONNECTION *pconnection, BOOL b_alive);

int mysql_pool_get_param(int param);

void mysql_pool_encode_squote(const char *in, char *out);

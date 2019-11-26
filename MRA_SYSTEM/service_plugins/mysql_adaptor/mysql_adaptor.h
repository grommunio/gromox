#ifndef _H_MYSQL_ADAPTOR_
#define _H_MYSQL_ADAPTOR_
#include "mem_file.h"

enum {
	MYSQL_ADAPTOR_SCAN_INTERVAL,
	MYSQL_ADAPTOR_CONNECTION_NUMBER,
	MYSQL_ADAPTOR_ALIVECONN_NUMBER
};

void mysql_adaptor_init(int conn_num, int scan_interval, const char *host,
	int port, const char *user, const char *password, const char *db_name,
	int timeout);
extern int mysql_adaptor_run(void);
extern int mysql_adaptor_stop(void);
extern void mysql_adaptor_free(void);
BOOL mysql_adaptor_login(const char *username, const char *password,
	char *maildir, char *lang, char *reason, int length);

int mysql_adaptor_get_param(int param);

void mysql_adaptor_set_param(int param, int value);


#endif

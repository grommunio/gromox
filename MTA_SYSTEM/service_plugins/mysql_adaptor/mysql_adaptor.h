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

int mysql_adaptor_run();

int mysql_adaptor_stop();

void mysql_adaptor_free();

BOOL mysql_adaptor_login(const char *username,
	const char *password, char *reason, int length);

BOOL mysql_adaptor_check_user(const char *username, char *path);

void mysql_adaptor_disable_smtp(const char *username);

BOOL mysql_adaptor_get_user_info(const char *username,
	char *maildir, char *lang, char *timezone);

BOOL mysql_adaptor_get_user_ids(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type);

BOOL mysql_adaptor_get_username(int user_id, char *username);

BOOL mysql_adaptor_get_lang(const char *username, char *lang);

BOOL mysql_adaptor_get_timezone(const char *username, char *timezone);

BOOL mysql_adaptor_get_homedir(const char *domainname, char *homedir);

BOOL mysql_adaptor_check_same_org2(
	const char *domainname1, const char *domainname2);

BOOL mysql_adaptor_get_forward(const char *username, int *ptype,
	char *destination);

BOOL mysql_adaptor_get_groupname(const char *username, char *groupname);

BOOL mysql_adaptor_get_mlist(const char *username,
	const char *from, int *presult, MEM_FILE *pfile);

BOOL mysql_adaptor_check_virtual(const char *username, const char *from,
	BOOL *pb_expanded, MEM_FILE *pfile);

int mysql_adaptor_get_param(int param);

void mysql_adaptor_set_param(int param, int value);


#endif

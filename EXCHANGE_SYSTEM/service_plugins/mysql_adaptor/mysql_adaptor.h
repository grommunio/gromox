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

BOOL mysql_adaptor_login(const char *username, const char *password,
	char *maildir, char *lang, char *reason, int length);
	
BOOL mysql_adaptor_setpasswd(const char *username,
	const char *password, const char *new_password);

BOOL mysql_adaptor_get_username_from_id(int user_id, char *username);

BOOL mysql_adaptor_get_id_from_username(const char *username, int *puser_id);

BOOL mysql_adaptor_get_id_from_maildir(const char *maildir, int *puser_id);

BOOL mysql_adaptor_get_user_displayname(
	const char *username, char *pdisplayname);

BOOL mysql_adaptor_get_user_privilege_bits(
	const char *username, uint32_t *pprivilege_bits);

BOOL mysql_adaptor_get_user_lang(const char *username, char *lang);

BOOL mysql_adaptor_set_user_lang(const char *username, const char *lang);
	
BOOL mysql_adaptor_get_timezone(const char *username, char *timezone);

BOOL mysql_adaptor_set_timezone(const char *username, const char *timezone);

BOOL mysql_adaptor_get_maildir(const char *username, char *maildir);

BOOL mysql_adaptor_get_domainname_from_id(int domain_id, char *domainname);

BOOL mysql_adaptor_get_homedir(const char *domainname, char *homedir);

BOOL mysql_adaptor_get_homedir_by_id(int domain_id, char *homedir);

BOOL mysql_adaptor_get_id_from_homedir(const char *homedir, int *pdomain_id);

BOOL mysql_adaptor_get_user_ids(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type);

BOOL mysql_adaptor_get_domain_ids(const char *domainname,
	int *pdomain_id, int *porg_id);
	
BOOL mysql_adaptor_get_mlist_ids(int user_id,
	int *pgroup_id, int *pdomain_id);

BOOL mysql_adaptor_get_org_domains(int org_id, MEM_FILE *pfile);

BOOL mysql_adaptor_get_domain_info(int domain_id,
	char *name, char *title, char *address);

BOOL mysql_adaptor_check_same_org(int domain_id1, int domain_id2);

BOOL mysql_adaptor_get_domain_groups(int domain_id, MEM_FILE *pfile);

BOOL mysql_adaptor_get_group_classes(int group_id, MEM_FILE *pfile);

BOOL mysql_adaptor_get_sub_classes(int class_id, MEM_FILE *pfile);

int mysql_adaptor_get_class_users(int class_id, MEM_FILE *pfile);

int mysql_adaptor_get_group_users(int group_id, MEM_FILE *pfile);

int mysql_adaptor_get_domain_users(int domain_id, MEM_FILE *pfile);

BOOL mysql_adaptor_check_mlist_include(
	const char *mlist_name, const char *account);

int mysql_adaptor_get_param(int param);

void mysql_adaptor_set_param(int param, int value);


#endif

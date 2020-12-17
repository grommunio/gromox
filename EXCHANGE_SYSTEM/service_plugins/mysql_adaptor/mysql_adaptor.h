#pragma once
#include <string>
#include <vector>
#include "mem_file.h"

enum {
	MYSQL_ADAPTOR_SCAN_INTERVAL,
	MYSQL_ADAPTOR_CONNECTION_NUMBER,
	MYSQL_ADAPTOR_ALIVECONN_NUMBER
};

enum {
	USER_PRIVILEGE_POP3_IMAP = 1 << 0,
	USER_PRIVILEGE_SMTP = 1 << 1,
	USER_PRIVILEGE_CHGPASSWD = 1 << 2,
	USER_PRIVILEGE_PUBADDR = 1 << 3,
};

enum sql_schema_upgrade {
	S_ABORT, S_SKIP, S_AUTOUP,
};

struct mysql_adaptor_init_param {
	const char *host, *user, *pass, *dbname;
	int port, conn_num, scan_interval, timeout;
	enum sql_schema_upgrade schema_upgrade;
};

#ifdef __cplusplus
extern void mysql_adaptor_init(const struct mysql_adaptor_init_param &);
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int mysql_adaptor_run(void);
extern int mysql_adaptor_stop(void);
extern void mysql_adaptor_free(void);
extern BOOL mysql_adaptor_meta(const char *username, const char *password, char *maildir, char *lang, char *reason, int length, unsigned int mode, char *encrypted_passwd, size_t enc_size);
extern BOOL mysql_adaptor_login2(const char *username, const char *password, char *encrypt_passwd, size_t enc_size, char *reason, int length, unsigned int mode);
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
extern BOOL mysql_adaptor_get_homedir(const char *domainname, char *homedir);
extern BOOL mysql_adaptor_get_domain_homedir(const char *domainname, char *homedir);
BOOL mysql_adaptor_get_homedir_by_id(int domain_id, char *homedir);

BOOL mysql_adaptor_get_id_from_homedir(const char *homedir, int *pdomain_id);

BOOL mysql_adaptor_get_user_ids(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type);

BOOL mysql_adaptor_get_domain_ids(const char *domainname,
	int *pdomain_id, int *porg_id);
	
BOOL mysql_adaptor_get_mlist_ids(int user_id,
	int *pgroup_id, int *pdomain_id);
extern BOOL mysql_adaptor_get_org_domains(int org_id, std::vector<int> &);
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
extern BOOL mysql_adaptor_check_same_org2(const char *domainname1, const char *domainname2);
extern BOOL mysql_adaptor_check_user(const char *username, char *path);
extern BOOL mysql_adaptor_get_forward(const char *username, int *ptype, char *destination);
extern BOOL mysql_adaptor_get_groupname(const char *username, char *groupname);
extern BOOL mysql_adaptor_get_mlist(const char *username, const char *from, int *presult, std::vector<std::string> &);
extern BOOL mysql_adaptor_get_user_info(const char *username, char *maildir, char *lang, char *timezone);
extern BOOL mysql_adaptor_get_username(int user_id, char *username);
extern void mysql_adaptor_disable_smtp(const char *username);

#ifdef __cplusplus
} /* extern "C" */
#endif

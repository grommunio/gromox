#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <gromox/authmgr.hpp>
#include <gromox/common_types.hpp>
#include <gromox/mapidefs.h>

enum {
	/* Reason codes (users.address_status) for forbidden login */
	AF_USER_NORMAL      = 0x00,
	AF_USER_SUSPENDED   = 0x01,
	AF_USER_OUTOFDATE   = 0x02,
	AF_USER_DELETED     = 0x03,
	AF_USER_SHAREDMBOX  = 0x04,
	AF_USER_CONTACT     = 0x05,
	AF_USER__MASK       = 0x0F,

	// historically: groups with AF_GROUP__MASK = 0xC0, with statuses NORMAL..DELETED
	AF_DOMAIN_NORMAL    = 0x00,
	AF_DOMAIN_SUSPENDED = 0x10,
	AF_DOMAIN_OUTOFDATE = 0x20,
	AF_DOMAIN_DELETED   = 0x30,
	AF_DOMAIN__MASK     = 0x30,

	/* note: users.address_status is a tinyint(4), so only 7 "usable" bits */
};

enum class mlist_type {
	normal = 0, group, domain, dyngroup /* class */,
};

enum sql_schema_upgrade : uint8_t {
	SSU_NOT_ENABLED, SSU_NOT_ME, SSU_AUTOUPGRADE,
};

struct mysql_adaptor_init_param {
	std::string host, user, pass, dbname;
	int port = 0, conn_num = 0, timeout = 0;
	enum sql_schema_upgrade schema_upgrade = SSU_NOT_ENABLED;
	bool enable_firsttimepw = false;
};

struct sql_domain {
	std::string name, title, address;
};

/**
 * %AB_HIDE_FROM_GAL:	hide from Global Address List (container 0)
 * %AB_HIDE_FROM_AL:	hide from Address Lists, EXC style (container != 0)
 * %AB_HIDE_DELEGATE:	hide from Delegate List
 * %AB_HIDE_RESOLVE:	hide from name resolution ("Check Names" in g-web)
 * %AB_HIDE_MINID:	disable resolution via MINID (experimental)
 *
 * %AB_HIDE__DEFAULT:	default action if AB encounters PR_ATTR_HIDDEN
 */
enum { /* for PR_ATTR_HIDDEN_*GROMOX* */
	AB_HIDE_FROM_GAL   = 0x01U,
	AB_HIDE_FROM_AL    = 0x02U,
	AB_HIDE_DELEGATE   = 0x04U,
	AB_HIDE_RESOLVE    = 0x08U,

	AB_HIDE__DEFAULT   = 0x03U,
};

/**
 * @dtex:	%DT_* type as specified for PR_DISPLAY_TYPE_EX.
 * @hidden:	hide bits for the address book
 * @list_type:	mlist_type value; only interpret field when
 * 		addr_type==ADDRESS_TYPE_MLIST.
 */
struct sql_user {
	enum display_type dtypx = DT_MAILUSER;
	unsigned int id = 0;
	enum mlist_type list_type = mlist_type::normal;
	uint32_t hidden = 0;
	unsigned int list_priv = 0;
	std::string username, maildir;
	std::vector<std::string> aliases; /* email addresses */
	std::map<unsigned int, std::string> propvals;
};

struct sql_group {
	unsigned int id;
	std::string name, title;
};

struct sql_class {
	unsigned int child_id;
	std::string name;
};

extern void mysql_adaptor_init(mysql_adaptor_init_param &&);
extern int mysql_adaptor_run();
extern void mysql_adaptor_stop();
extern gromox::errno_t mysql_adaptor_meta(const char *username, unsigned int wantpriv, sql_meta_result &out);
extern BOOL mysql_adaptor_login2(const char *username, const char *password, std::string &enc_passwd, std::string &errstr);
BOOL mysql_adaptor_setpasswd(const char *username,
	const char *password, const char *new_password);
extern BOOL mysql_adaptor_get_username_from_id(unsigned int user_id, char *username, size_t);
extern BOOL mysql_adaptor_get_id_from_username(const char *username, unsigned int *user_id);
extern BOOL mysql_adaptor_get_id_from_maildir(const char *maildir, unsigned int *user_id);
extern bool mysql_adaptor_get_user_displayname(const char *username, char *dispname, size_t);
BOOL mysql_adaptor_get_user_privilege_bits(
	const char *username, uint32_t *pprivilege_bits);
extern bool mysql_adaptor_get_user_lang(const char *username, char *lang, size_t);
BOOL mysql_adaptor_set_user_lang(const char *username, const char *lang);
extern bool mysql_adaptor_get_timezone(const char *username, char *timezone, size_t);
BOOL mysql_adaptor_set_timezone(const char *username, const char *timezone);
extern bool mysql_adaptor_get_maildir(const char *username, char *maildir, size_t);
extern bool mysql_adaptor_get_homedir(const char *domainname, char *homedir, size_t);
extern bool mysql_adaptor_get_homedir_by_id(unsigned int domain_id, char *homedir, size_t);
extern BOOL mysql_adaptor_get_id_from_homedir(const char *homedir, unsigned int *domain_id);
extern BOOL mysql_adaptor_get_user_ids(const char *username, unsigned int *user_id, unsigned int *domain_id, enum display_type *);
extern BOOL mysql_adaptor_get_domain_ids(const char *domainname, unsigned int *domain_id, unsigned int *org_id);
extern BOOL mysql_adaptor_get_mlist_ids(unsigned int user_id, unsigned int *group_id, unsigned int *domain_id);
extern BOOL mysql_adaptor_get_org_domains(unsigned int org_id, std::vector<unsigned int> &);
extern BOOL mysql_adaptor_get_domain_info(unsigned int domain_id, sql_domain &);
extern BOOL mysql_adaptor_check_same_org(unsigned int domain_id1, unsigned int domain_id2);
extern BOOL mysql_adaptor_get_domain_groups(unsigned int domain_id, std::vector<sql_group> &);
extern int mysql_adaptor_get_group_users(unsigned int group_id, std::vector<sql_user> &);
extern int mysql_adaptor_get_domain_users(unsigned int domain_id, std::vector<sql_user> &);
BOOL mysql_adaptor_check_mlist_include(
	const char *mlist_name, const char *account);
extern BOOL mysql_adaptor_check_same_org2(const char *domainname1, const char *domainname2);
extern bool mysql_adaptor_check_user(const char *username, char *path, size_t);
extern BOOL mysql_adaptor_get_mlist_memb(const char *username, const char *from, int *presult, std::vector<std::string> &);
extern bool mysql_adaptor_get_user_info(const char *username, char *maildir, size_t msize, char *lang, size_t lsize, char *timezone, size_t tsize);
extern void mysql_adaptor_encode_squote(const char *in, char *out);
extern gromox::errno_t mysql_adaptor_get_homeserver(const char *ent, bool is_pvt, std::pair<std::string, std::string> &);

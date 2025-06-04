#pragma once
#include <cstring>
#include <mysql.h>
#include <string>
#include <vector>
#include <gromox/database_mysql.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/resource_pool.hpp>

enum {
	/* For ADDRESS_TYPE_NORMAL */
	SUB_TYPE_USER = 0,
	SUB_TYPE_ROOM,
	SUB_TYPE_EQUIPMENT,
};

class config_file;

namespace gromox {

class sqlconn final {
	public:
	sqlconn() = default;
	sqlconn(MYSQL *m) : m_conn(m) {}
	sqlconn(sqlconn &&o) noexcept : m_conn(o.m_conn) { o.m_conn = nullptr; }
	~sqlconn() { mysql_close(m_conn); }
	sqlconn &operator=(sqlconn &&o) noexcept;
	operator bool() const { return m_conn; }
	bool operator==(std::nullptr_t) const { return m_conn == nullptr; }
	bool operator!=(std::nullptr_t) const { return m_conn != nullptr; }
	MYSQL *get() const { return m_conn; }
	std::string quote(std::string_view);
	bool query(std::string_view);
	gromox::DB_RESULT store_result() { return mysql_store_result(m_conn); }

	protected:
	MYSQL *m_conn = nullptr;
};

struct sqlconnpool final : public gromox::resource_pool<sqlconn> {
	template<typename... T> void get(T &&...) = delete;
	resource_pool::token get_wait();
};

struct mysql_plugin final {
	public:
	void init(mysql_adaptor_init_param &&);
	int run();
	bool reload_config(std::shared_ptr<config_file> &&);
	bool db_upgrade_check_2(MYSQL *);
	bool db_upgrade_check();
	MYSQL *sql_make_conn();

	gromox::errno_t meta(const char *username, unsigned int wantpriv, sql_meta_result &out);
	bool login2(const char *username, const char *password, const std::string &enc_passwd, std::string &errstr);
	bool setpasswd(const char *username, const char *password, const char *new_password);
	ec_error_t userid_to_name(unsigned int user_id, std::string &username);
	bool get_id_from_maildir(const char *maildir, unsigned int *user_id);
	bool get_user_displayname(const char *username, std::string &);
	bool get_user_aliases(const char *username, std::vector<std::string>&);
	bool get_user_props(const char *username, TPROPVAL_ARRAY&);
	bool get_user_privbits(const char *username, uint32_t *pprivilege_bits);
	bool set_user_lang(const char *username, const char *lang);
	bool set_timezone(const char *username, const char *timezone);
	bool get_homedir(const char *domainname, char *homedir, size_t);
	bool get_homedir_by_id(unsigned int domain_id, char *homedir, size_t);
	bool get_id_from_homedir(const char *homedir, unsigned int *domain_id);
	bool get_user_ids(const char *username, unsigned int *user_id, unsigned int *domain_id, enum display_type *);
	bool get_domain_ids(const char *domainname, unsigned int *domain_id, unsigned int *org_id);
	bool get_org_domains(unsigned int org_id, std::vector<unsigned int> &);
	bool get_domain_info(unsigned int domain_id, sql_domain &);
	bool check_same_org(unsigned int domain_id1, unsigned int domain_id2);
	bool get_domain_groups(unsigned int domain_id, std::vector<sql_group> &);
	int get_domain_users(unsigned int domain_id, std::vector<sql_user> &);
	bool check_mlist_include(const char *mlist_name, const char *account, unsigned int max_depth = 16);
	bool check_same_org2(const char *domainname1, const char *domainname2);
	bool get_mlist_memb(const char *username, const char *from, int *presult, std::vector<std::string> &);
	gromox::errno_t get_homeserver(const char *ent, bool is_pvt, std::pair<std::string, std::string> &);
	gromox::errno_t scndstore_hints(unsigned int pri, std::vector<sql_user> &hints);
	int domain_list_query(const char *dom);
	int mbop_userlist(std::vector<sql_user> &);
	gromox::errno_t mda_alias_list(gromox::sql_alias_map &, size_t &);
	gromox::errno_t mda_domain_list(gromox::sql_domain_set &);

	protected:
	bool mlist_domain_contains(sqlconn *, const char *mlist, const char *account);

	mysql_adaptor_init_param g_parm;
	sqlconnpool g_sqlconn_pool;
};

}

extern std::string sql_crypt_newhash(const char *);
extern bool sql_crypt_verify(const char *, const char *);

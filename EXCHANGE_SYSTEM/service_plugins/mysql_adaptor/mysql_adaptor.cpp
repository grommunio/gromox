#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <libHX/string.h>
#include <gromox/database.h>
#include <gromox/dbop.h>
#include <gromox/defs.h>
#include <gromox/resource_pool.hpp>
#include "mysql_adaptor.h"
#include "mem_file.h"
#include "util.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <mysql/mysql.h>

#define ADDRESS_TYPE_NORMAL				0
#define ADDRESS_TYPE_ALIAS 1 /* historic; no longer used in db schema */
#define ADDRESS_TYPE_MLIST				2
#define ADDRESS_TYPE_VIRTUAL			3
/* composed value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM				4
/* composed value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT			5

#define SUB_TYPE_USER					0
#define SUB_TYPE_ROOM					1
#define SUB_TYPE_EQUIPMENT				2

#define MLIST_TYPE_NORMAL				0
#define MLIST_TYPE_GROUP				1
#define MLIST_TYPE_DOMAIN				2
#define MLIST_TYPE_CLASS				3

#define MLIST_PRIVILEGE_ALL				0
#define MLIST_PRIVILEGE_INTERNAL		1
#define MLIST_PRIVILEGE_DOMAIN			2
#define MLIST_PRIVILEGE_SPECIFIED		3
#define MLIST_PRIVILEGE_OUTGOING		4

#define MLIST_RESULT_OK					0
#define MLIST_RESULT_NONE				1
#define MLIST_RESULT_PRIVIL_DOMAIN		2
#define MLIST_RESULT_PRIVIL_INTERNAL	3
#define MLIST_RESULT_PRIVIL_SPECIFIED	4

using namespace gromox;

struct icasecmp {
	bool operator()(const std::string &a, const std::string &b) const {
		return strcasecmp(a.c_str(), b.c_str()) == 0;
	}
};

struct sqlfree {
	void operator()(MYSQL *m) { mysql_close(m); }
};

using sqlconn_ptr = std::unique_ptr<MYSQL, sqlfree>;

static struct sqlconnpool final : public resource_pool<sqlconn_ptr> {
	resource_pool::token get_wait();
} g_sqlconn_pool;

static int g_conn_num;
static int g_port;
static int g_timeout;
static char g_host[256];
static char g_user[256];
static char *g_password;
static char g_password_buff[256];
static char g_db_name[256];
static pthread_mutex_t g_crypt_lock;
static enum sql_schema_upgrade g_schema_upgrade;

static void mysql_adaptor_encode_squote(const char *in, char *out);

static inline size_t z_strlen(const char *s)
{
	return s != nullptr ? strlen(s) : 0;
}

static inline const char *z_null(const char *s)
{
	return s != nullptr ? s : "";
}

void mysql_adaptor_init(const struct mysql_adaptor_init_param &parm)
{
	g_conn_num = parm.conn_num;
	HX_strlcpy(g_host, parm.host, sizeof(g_host));
	g_port = parm.port;
	g_timeout = parm.timeout;
	HX_strlcpy(g_user, parm.user, sizeof(g_user));
	if (parm.pass == nullptr || *parm.pass == '\0') {
		g_password = NULL;
	} else {
		HX_strlcpy(g_password_buff, parm.pass, sizeof(g_password_buff));
		g_password = g_password_buff;
	}
	HX_strlcpy(g_db_name, parm.dbname, sizeof(g_db_name));
	g_schema_upgrade = parm.schema_upgrade;
	pthread_mutex_init(&g_crypt_lock, NULL);
}

static bool db_upgrade_check_2(MYSQL *conn)
{
	auto recent = dbop_mysql_recentversion();
	auto current = dbop_mysql_schemaversion(conn);
	if (current >= recent)
		return true;
	printf("[mysql_adaptor]: Current schema n%d. Update available: n%d. Configured action: ",
	       current, recent);
	if (g_schema_upgrade == S_SKIP) {
		printf("skip\n");
		return true;
	} else if (g_schema_upgrade != S_AUTOUP) {
		printf("abort\n");
		return false;
	}
	printf("autoupgrade\n");
	return dbop_mysql_upgrade(conn) == EXIT_SUCCESS;
}

static bool db_upgrade_check()
{
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	return db_upgrade_check_2(conn.res.get());
}

static sqlconn_ptr sql_make_conn()
{
	sqlconn_ptr conn(mysql_init(nullptr));
	if (conn == nullptr)
		return conn;
	if (g_timeout > 0) {
		mysql_options(conn.get(), MYSQL_OPT_READ_TIMEOUT,
			&g_timeout);
		mysql_options(conn.get(), MYSQL_OPT_WRITE_TIMEOUT,
			&g_timeout);
	}
	mysql_options(conn.get(), MYSQL_SET_CHARSET_NAME, "utf8mb4");
	if (mysql_real_connect(conn.get(), g_host, g_user, g_password,
	    g_db_name, g_port, nullptr, 0) != nullptr)
		return conn;
	printf("[mysql_adaptor]: Failed to connect to mysql server: %s\n",
	       mysql_error(conn.get()));
	return nullptr;
}

resource_pool<sqlconn_ptr>::token sqlconnpool::get_wait()
{
	auto c = resource_pool::get_wait();
	if (c.res == nullptr)
		c.res = sql_make_conn();
	return c;
}

int mysql_adaptor_run()
{
	for (int i = 0; i < g_conn_num; ++i) {
		auto conn = sql_make_conn();
		if (conn == nullptr)
			break;
		g_sqlconn_pool.put(std::move(conn));
	}

	if (!db_upgrade_check())
		return -1;
	g_sqlconn_pool.resize(g_conn_num);
	return 0;

}

int mysql_adaptor_stop()
{
	g_sqlconn_pool.clear();
	return 0;
}

void mysql_adaptor_free()
{
	pthread_mutex_destroy(&g_crypt_lock);
}

BOOL mysql_adaptor_meta(const char *username, const char *password,
    char *maildir, char *lang, char *reason, int length, unsigned int mode,
    char *encrypt_passwd, size_t encrypt_size)
{
	int temp_type;
	int temp_status;
	char temp_name[512];
	char sql_string[1024];

	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT password, address_type, address_status, "
		"privilege_bits, maildir, lang FROM users WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr)
			return false;
		if (mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1) {
		snprintf(reason, length, "user \"%s\" does not exist; check if "
			"it is properly composed", username);
		return FALSE;
	}
	
	auto myrow = pmyres.fetch_row();
	temp_type = atoi(myrow[1]);
	if (temp_type != ADDRESS_TYPE_NORMAL) {
		snprintf(reason, length, "\"%s\" is not a real user; "
			"correct the account name and retry.", username);
		return FALSE;
	}
	temp_status = atoi(myrow[2]);
	if (0 != temp_status) {
		if (0 != (temp_status&0x30)) {
			snprintf(reason, length, "domain of user \"%s\" is disabled!",
				username);
		} else if (0 != (temp_status&0xC)) {
			snprintf(reason, length, "group of user \"%s\" is disabled!",
				username);
		} else {
			snprintf(reason, length, "user \"%s\" is disabled!", username);
		}
		return FALSE;
	}

	if (mode == USER_PRIVILEGE_POP3_IMAP && !(strtoul(myrow[3], nullptr, 0) & USER_PRIVILEGE_POP3_IMAP)) {
		strncpy(reason, "you are not authorized to download email through the POP3 or IMAP server", length);
		return false;
	}
	if (mode == USER_PRIVILEGE_SMTP && !(strtoul(myrow[3], nullptr, 0) & USER_PRIVILEGE_SMTP)) {
		strncpy(reason, "you are not authorized to download email through the SMTP server", length);
		return false;
	}

	strncpy(encrypt_passwd, myrow[0], encrypt_size);
	strcpy(maildir, myrow[4]);
	if (NULL != lang) {
		strcpy(lang, myrow[5]);
	}
	encrypt_passwd[encrypt_size-1] = '\0';
	return TRUE;
}

static BOOL firsttime_password(const char *username, const char *password,
    char *encrypt_passwd, char *reason, int length, unsigned int mode)
{
	const char *pdomain;
	pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		strncpy(reason, "domain name should be included!", length);
		return FALSE;
	}
	pdomain++;

	pthread_mutex_lock(&g_crypt_lock);
	strcpy(encrypt_passwd, md5_crypt_wrapper(password));
	pthread_mutex_unlock(&g_crypt_lock);

	char sql_string[1024], temp_name[512];
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
	         "username='%s'", encrypt_passwd, temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr)
			return false;
		if (mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
	         "mainname='%s'", temp_name);
	if (mysql_query(conn.res.get(), sql_string) != 0)
		return false;
	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;

	mysql_adaptor_encode_squote(pdomain, temp_name);
	snprintf(sql_string, 1024, "SELECT aliasname FROM aliases WHERE "
	         "mainname='%s'", temp_name);
	if (mysql_query(conn.res.get(), sql_string) != 0)
		return false;
	DB_RESULT pmyres1 = mysql_store_result(conn.res.get());
	if (pmyres1 == nullptr)
		return false;

	size_t k, rows = pmyres.num_rows(), rows1 = pmyres1.num_rows();
	for (k = 0; k < rows1; k++) {
		char virtual_address[256];
		char *pat;

		auto myrow1 = pmyres1.fetch_row();
		strcpy(virtual_address, username);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow1[0]);
		mysql_adaptor_encode_squote(virtual_address, temp_name);
		snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
		         "username='%s'", encrypt_passwd, temp_name);
		mysql_query(conn.res.get(), sql_string);
	}

	size_t j;
	for (j = 0; j < rows; j++) {
		auto myrow = pmyres.fetch_row();
		mysql_adaptor_encode_squote(myrow[0], temp_name);
		snprintf(sql_string, 1024, "UPDATE users SET password='%s' WHERE "
		         "username='%s'", encrypt_passwd, temp_name);
		mysql_query(conn.res.get(), sql_string);
		mysql_data_seek(pmyres1.get(), 0);
		size_t k;
		for (k = 0; k < rows1; k++) {
			char virtual_address[256], *pat;

			auto myrow1 = pmyres1.fetch_row();
			strcpy(virtual_address, myrow[0]);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow1[0]);
			mysql_adaptor_encode_squote(virtual_address, temp_name);
			snprintf(sql_string, 1024, "UPDATE users SET password='%s' "
				"WHERE username='%s'", encrypt_passwd, temp_name);
			mysql_query(conn.res.get(), sql_string);
		}
	}
	return TRUE;
}

static BOOL verify_password(const char *username, const char *password,
    const char *encrypt_passwd, char *reason, int length, unsigned int mode)
{
		pthread_mutex_lock(&g_crypt_lock);
		if (0 == strcmp(crypt(password, encrypt_passwd), encrypt_passwd)) {
			pthread_mutex_unlock(&g_crypt_lock);
			return TRUE;
		} else {
			pthread_mutex_unlock(&g_crypt_lock);
			snprintf(reason, length, "password error, please check it "
				"and retry");
			return FALSE;
		}
		return FALSE;
}

BOOL mysql_adaptor_login2(const char *username, const char *password,
    char *encrypt_passwd, size_t encrypt_size, char *reason,
    int length, unsigned int mode)
{
	BOOL ret;
	if (*encrypt_passwd == '\0')
		ret = firsttime_password(username, password, encrypt_passwd,
		      reason, length, mode);
	else
		ret = verify_password(username, password, encrypt_passwd, reason,
		      length, mode);
	return ret;
}

BOOL mysql_adaptor_setpasswd(const char *username,
	const char *password, const char *new_password)
{
	int j, k;
	int temp_type;
	int temp_status;
	const char *pdomain;
	char *pat;
	char temp_name[512];
	char sql_string[1024];
	char encrypt_passwd[40];
	char virtual_address[256];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT password, address_type,"
			" address_status, privilege_bits FROM users WHERE "
			"username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	temp_type = atoi(myrow[1]);
	if (temp_type != ADDRESS_TYPE_NORMAL) {
		return FALSE;
	}
	temp_status = atoi(myrow[2]);
	if (0 != temp_status) {
		return FALSE;
	}
	
	if (0 == (atoi(myrow[3])&USER_PRIVILEGE_CHGPASSWD)) {
		return FALSE;
	}

	strncpy(encrypt_passwd, myrow[0], sizeof(encrypt_passwd));
	encrypt_passwd[sizeof(encrypt_passwd) - 1] = '\0';
	
	pthread_mutex_lock(&g_crypt_lock);
	if ('\0' != encrypt_passwd[0] && 0 != strcmp(crypt(
		password, encrypt_passwd), encrypt_passwd)) {
		pthread_mutex_unlock(&g_crypt_lock);
		return FALSE;
	}
	pthread_mutex_unlock(&g_crypt_lock);
	
	pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	pdomain ++;
	
	pthread_mutex_lock(&g_crypt_lock);
	strcpy(encrypt_passwd, md5_crypt_wrapper(new_password));
	pthread_mutex_unlock(&g_crypt_lock);

	snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
			" WHERE username='%s'", encrypt_passwd, temp_name);
	if (conn.res == nullptr ||
	    mysql_query(conn.res.get(), sql_string) != 0)
		return false;

	snprintf(sql_string, 1024, "SELECT aliasname FROM"
			" aliases WHERE mainname='%s'", temp_name);
	if (conn.res == nullptr ||
	    mysql_query(conn.res.get(), sql_string) != 0)
		return false;
	pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;

	mysql_adaptor_encode_squote(pdomain, temp_name);
	snprintf(sql_string, 1024, "SELECT aliasname FROM"
			" aliases WHERE mainname='%s'", temp_name);
	if (conn.res == nullptr ||
	    mysql_query(conn.res.get(), sql_string) != 0)
		return false;

	DB_RESULT pmyres1 = mysql_store_result(conn.res.get());
	if (pmyres1 == nullptr)
		return false;
	size_t rows = pmyres.num_rows(), rows1 = pmyres1.num_rows();
	for (k=0; k<rows1; k++) {
		auto myrow1 = pmyres1.fetch_row();
		strcpy(virtual_address, username);
		pat = strchr(virtual_address, '@') + 1;
		strcpy(pat, myrow1[0]);
		mysql_adaptor_encode_squote(virtual_address, temp_name);
		snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
				" WHERE username='%s'", encrypt_passwd, temp_name);
		mysql_query(conn.res.get(), sql_string);
	}

	for (j=0; j<rows; j++) {
		auto myrow = pmyres.fetch_row();
		mysql_adaptor_encode_squote(myrow[0], temp_name);
		snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
				" WHERE username='%s'", encrypt_passwd, temp_name);
		mysql_query(conn.res.get(), sql_string);
		mysql_data_seek(pmyres1.get(), 0);
		for (k=0; k<rows1; k++) {
			auto myrow1 = pmyres1.fetch_row();
			strcpy(virtual_address, myrow[0]);
			pat = strchr(virtual_address, '@') + 1;
			strcpy(pat, myrow1[0]);
			mysql_adaptor_encode_squote(virtual_address, temp_name);
			snprintf(sql_string, 1024, "UPDATE users SET password='%s'"
					" WHERE username='%s'", encrypt_passwd, temp_name);
			mysql_query(conn.res.get(), sql_string);
		}
	}
	return TRUE;
}

BOOL mysql_adaptor_get_username_from_id(int user_id, char *username)
{
	char sql_string[1024];
	
	snprintf(sql_string, 1024, "SELECT username FROM users "
		"WHERE id=%d", user_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(username, myrow[0], 256);
	return TRUE;
}

BOOL mysql_adaptor_get_id_from_username(const char *username, int *puser_id)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT id FROM users "
		"WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr)
			return false;
		if (mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*puser_id = atoi(myrow[0]);
	return TRUE;
}

BOOL mysql_adaptor_get_id_from_maildir(const char *maildir, int *puser_id)
{
	char temp_dir[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(maildir, temp_dir);
	snprintf(sql_string, 1024, "SELECT id FROM users "
		"WHERE maildir='%s' AND address_type=0", temp_dir);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*puser_id = atoi(myrow[0]);
	return TRUE;
}

BOOL mysql_adaptor_get_user_displayname(
	const char *username, char *pdisplayname)
{
	int address_type;
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, sizeof(sql_string),
	         "SELECT u2.propval_str AS real_name, "
	         "u3.propval_str AS nickname, u.address_type FROM users AS u "
	         "LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 "
	         "LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=978255903 "
	         "WHERE u.username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr)
			return false;
		if (mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	address_type = atoi(myrow[2]);
	strcpy(pdisplayname,
	       address_type == ADDRESS_TYPE_MLIST ? username :
	       myrow[0] != nullptr && *myrow[0] != '\0' ? myrow[0] :
	       myrow[1] != nullptr && *myrow[1] != '\0' ? myrow[1] :
	       username);
	return TRUE;
}

BOOL mysql_adaptor_get_user_privilege_bits(
	const char *username, uint32_t *pprivilege_bits)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT privilege_bits"
		" FROM users WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*pprivilege_bits = atoi(myrow[0]);
	return TRUE;
}

BOOL mysql_adaptor_get_user_lang(const char *username, char *lang)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT lang FROM users "
		"WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1) {
		lang[0] = '\0';	
	} else {
		auto myrow = pmyres.fetch_row();
		strcpy(lang, myrow[0]);
	}
	return TRUE;
}

BOOL mysql_adaptor_set_user_lang(const char *username, const char *lang)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "UPDATE users set "
		"lang='%s' WHERE username='%s'", lang, temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}
	return TRUE;
}

static BOOL mysql_adaptor_expand_hierarchy(MYSQL *pmysql,
    std::vector<int> &seen, int class_id)
{
	int child_id;
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT child_id FROM"
		" hierarchy WHERE class_id=%d", class_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();

	size_t i, rows = pmyres.num_rows();
	for (i = 0; i < rows; i++) {
		auto myrow = pmyres.fetch_row();
		child_id = atoi(myrow[0]);
		if (std::find(seen.cbegin(), seen.cend(), child_id) != seen.cend())
			continue;
		seen.push_back(child_id);
		if (!mysql_adaptor_expand_hierarchy(pmysql, seen, child_id))
			return FALSE;
	}
	return TRUE;
}

BOOL mysql_adaptor_get_timezone(const char *username, char *timezone)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT timezone FROM users "
		"WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1) {
		timezone[0] = '\0';	
	} else {
		auto myrow = pmyres.fetch_row();
		strcpy(timezone, myrow[0]);
	}
	return TRUE;
}

BOOL mysql_adaptor_set_timezone(const char *username, const char *timezone)
{
	char temp_name[512];
	char temp_zone[128];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	mysql_adaptor_encode_squote(timezone, temp_zone);
	snprintf(sql_string, 1024, "UPDATE users set timezone='%s'"
				" WHERE username='%s'", temp_zone, temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}
	return TRUE;
}

BOOL mysql_adaptor_get_maildir(const char *username, char *maildir)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT maildir FROM users "
		"WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(maildir, myrow[0], 256);
	return TRUE;
}

BOOL mysql_adaptor_get_domainname_from_id(int domain_id, char *domainname)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT domainname FROM domains "
		"WHERE id=%d", domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(domainname, myrow[0], 256);
	return TRUE;
}

BOOL mysql_adaptor_get_homedir(const char *domainname, char *homedir)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(domainname, temp_name);
	snprintf(sql_string, 1024, "SELECT homedir, domain_status FROM domains "
		"WHERE domainname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(homedir, myrow[0], 256);
	return TRUE;
}

BOOL mysql_adaptor_get_homedir_by_id(int domain_id, char *homedir)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT homedir FROM domains "
		"WHERE id=%d", domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(homedir, myrow[0], 256);
	return TRUE;
}

BOOL mysql_adaptor_get_id_from_homedir(const char *homedir, int *pdomain_id)
{
	char temp_dir[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(homedir, temp_dir);
	snprintf(sql_string, 1024, "SELECT id FROM domains "
		"WHERE homedir='%s'", temp_dir);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*pdomain_id = atoi(myrow[0]);
	return TRUE;
}

BOOL mysql_adaptor_get_user_ids(const char *username,
	int *puser_id, int *pdomain_id, int *paddress_type)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT id, domain_id, address_type,"
			" sub_type FROM users WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;	
	auto myrow = pmyres.fetch_row();
	*puser_id = atoi(myrow[0]);
	*pdomain_id = atoi(myrow[1]);
	*paddress_type = atoi(myrow[2]);
	if (ADDRESS_TYPE_NORMAL == *paddress_type) {
		switch (atoi(myrow[3])) {
		case SUB_TYPE_ROOM:
			*paddress_type = ADDRESS_TYPE_ROOM;
			break;
		case SUB_TYPE_EQUIPMENT:
			*paddress_type = ADDRESS_TYPE_EQUIPMENT;
			break;
		}
	}
	return TRUE;
}

BOOL mysql_adaptor_get_domain_ids(const char *domainname,
	int *pdomain_id, int *porg_id)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(domainname, temp_name);
	snprintf(sql_string, 1024, "SELECT id, org_id FROM domains "
		"WHERE domainname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*pdomain_id = atoi(myrow[0]);
	*porg_id = atoi(myrow[1]);
	return TRUE;
}

BOOL mysql_adaptor_get_mlist_ids(int user_id,
	int *pgroup_id, int *pdomain_id)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT address_type, domain_id, "
		"group_id FROM users WHERE id='%d'", user_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	if (myrow == nullptr || strtol(myrow[0], nullptr, 0) != ADDRESS_TYPE_MLIST) {
		return FALSE;
	}
	
	*pdomain_id = atoi(myrow[1]);
	*pgroup_id = atoi(myrow[2]);
	return TRUE;
}

BOOL mysql_adaptor_get_org_domains(int org_id, std::vector<int> &pfile)
{
	char sql_string[1024];

	snprintf(sql_string, 1024,
		"SELECT id FROM domains WHERE org_id=%d", org_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	pfile = std::vector<int>(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		pfile[i] = strtoul(myrow[0], nullptr, 0);
	}
	return TRUE;
}

BOOL mysql_adaptor_get_domain_info(int domain_id,
	char *name, char *title, char *address)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT domainname, title, address, homedir "
		"FROM domains WHERE id=%d", domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(name, myrow[0], 256);
	strncpy(title, myrow[1], 1024);
	strncpy(address, myrow[2], 1024);
	return TRUE;
}

BOOL mysql_adaptor_check_same_org(int domain_id1, int domain_id2)
{
	int org_id1;
	int org_id2;
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT org_id FROM domains "
		"WHERE id=%d OR id=%d", domain_id1, domain_id2);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 2)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	org_id1 = atoi(myrow[0]);
	myrow = pmyres.fetch_row();
	org_id2 = atoi(myrow[0]);
	if (0 == org_id1 || 0 == org_id2 || org_id1 != org_id2) {
		return FALSE;
	}
	return TRUE;
}

BOOL mysql_adaptor_get_domain_groups(int domain_id, std::vector<sql_group> &pfile)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT id, groupname, title "
		"FROM groups WHERE domain_id=%d", domain_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	std::vector<sql_group> gv(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		gv[i].id = strtoul(myrow[0], nullptr, 0);
		gv[i].name = myrow[1];
		gv[i].title = myrow[2];
	}
	pfile = std::move(gv);
	return TRUE;
}

BOOL mysql_adaptor_get_group_classes(int group_id, std::vector<sql_class> &pfile)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT child_id, classname FROM "
			"hierarchy INNER JOIN classes ON class_id=0 AND "
			"hierarchy.group_id=%d AND child_id=classes.id", group_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	std::vector<sql_class> cv(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		cv[i].child_id = strtoul(myrow[0], nullptr, 0);
		cv[i].name = myrow[1];
	}
	pfile = std::move(cv);
	return TRUE;
}

BOOL mysql_adaptor_get_sub_classes(int class_id, std::vector<sql_class> &pfile)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT child_id, classname FROM "
		"hierarchy INNER JOIN classes ON class_id=%d AND "
		"child_id=classes.id", class_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	size_t i, rows = pmyres.num_rows();
	std::vector<sql_class> cv(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		cv[i].child_id = strtoul(myrow[0], nullptr, 0);
		cv[i].name = myrow[1];
	}
	pfile = std::move(cv);
	return TRUE;
}

static BOOL mysql_adaptor_get_group_title(const char *groupname, char *title)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(groupname, temp_name);
	snprintf(sql_string, 1024, "SELECT title FROM"
		" groups WHERE groupname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(title, myrow[0], 1024);
	return TRUE;
}

static BOOL mysql_adaptor_get_class_title(
	const char *listname, char *classname)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(listname, temp_name);
	snprintf(sql_string, 1024, "SELECT classname FROM"
			" classes WHERE listname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(classname, myrow[0], 1024);
	return TRUE;
}

static BOOL mysql_adaptor_get_mlist_info(const char *listname,
	int *plist_type, int *plist_privilege, char *title)
{
	char temp_name[512];
	char sql_string[1024];
	
	mysql_adaptor_encode_squote(listname, temp_name);
	snprintf(sql_string, 1024, "SELECT list_type, list_privilege"
					" FROM mlists WHERE listname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	*plist_type = atoi(myrow[0]);
	*plist_privilege = atoi(myrow[1]);
	if (MLIST_TYPE_GROUP == *plist_type) {
		return mysql_adaptor_get_group_title(listname, title);
	} else if (MLIST_TYPE_CLASS == *plist_type) {
		return mysql_adaptor_get_class_title(listname, title);
	}
	return TRUE;
}

int mysql_adaptor_get_class_users(int class_id, std::vector<sql_user> &pfile)
{
	int temp_len;
	char *ptoken;
	char title[1024];
	int address_type;
	char sql_string[1600];

	snprintf(sql_string, sizeof(sql_string),
	         "SELECT u.id, u.privilege_bits, u.username, "
	         "u2.propval_str AS real_name, u3.propval_str AS title, "
	         "u4.propval_str AS memo, u5.propval_str AS cell, "
	         "u6.propval_str AS tel, u7.propval_str AS nickname, "
	         "u8.propval_str AS homeaddress, u.address_type, 0 AS create_day, "
	         "u.sub_type, u.maildir FROM users AS u "
	         "INNER JOIN members ON members.class_id=%d AND members.username=u.username "
	         "LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 "
	         "LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=974585887 "
	         "LEFT JOIN user_properties AS u4 ON u.id=u4.user_id AND u4.proptag=805568543 "
	         "LEFT JOIN user_properties AS u5 ON u.id=u5.user_id AND u5.proptag=974913567 "
	         "LEFT JOIN user_properties AS u6 ON u.id=u6.user_id AND u6.proptag=974782495 "
	         "LEFT JOIN user_properties AS u7 ON u.id=u7.user_id AND u7.proptag=978255903 "
	         "LEFT JOIN user_properties AS u8 ON u.id=u8.user_id AND u8.proptag=979173407",
	         class_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	
	size_t i, rows = pmyres.num_rows();
	pfile.clear();
	pfile.reserve(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		address_type = atoi(myrow[10]);
		if (ADDRESS_TYPE_NORMAL == address_type) {
			switch (atoi(myrow[12])) {
			case SUB_TYPE_ROOM:
				address_type = ADDRESS_TYPE_ROOM;
				break;
			case SUB_TYPE_EQUIPMENT:
				address_type = ADDRESS_TYPE_EQUIPMENT;
				break;
			}
		}
		sql_user u;
		switch (address_type) {
		case ADDRESS_TYPE_NORMAL:
		case ADDRESS_TYPE_ROOM:
		case ADDRESS_TYPE_EQUIPMENT:
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			temp_len = z_strlen(myrow[3]);
			if (0 == temp_len) {
				ptoken = strchr(myrow[2], '@');
				temp_len = ptoken - myrow[2];
				u.realname = std::string(myrow[2], temp_len);
			} else {
				u.realname = z_null(myrow[3]);
			}
			u.title = z_null(myrow[4]);
			u.memo = z_null(myrow[5]);
			u.cell = z_null(myrow[6]);
			u.tel = z_null(myrow[7]);
			u.nickname = z_null(myrow[8]);
			u.homeaddr = z_null(myrow[9]);
			u.maildir = myrow[13];
			pfile.push_back(std::move(u));
			break;
		case ADDRESS_TYPE_MLIST:
			if (!mysql_adaptor_get_mlist_info(myrow[2],
			    &u.list_type, &u.list_priv, title))
				return -1;
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			if (u.list_type == MLIST_TYPE_GROUP ||
			    u.list_type == MLIST_TYPE_CLASS)
				u.title = z_null(myrow[4]);
			pfile.push_back(std::move(u));
			break;
		}
	}
	return pfile.size();
}

int mysql_adaptor_get_group_users(int group_id, std::vector<sql_user> &pfile)
{
	int temp_len;
	char *ptoken;
	int address_type;
	char title[1024];
	char sql_string[1024];

	snprintf(sql_string, sizeof(sql_string),
	         "SELECT u.id, u.privilege_bits, u.username, "
	         "u2.propval_str AS real_name, u3.propval_str AS title, "
	         "u4.propval_str AS memo, u5.propval_str AS cell, "
	         "u6.propval_str AS tel, u7.propval_str AS nickname, "
	         "u8.propval_str AS homeaddress, u.address_type, 0 AS create_day, "
	         "u.sub_type, u.maildir FROM users AS u "
	         "LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 "
	         "LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=974585887 "
	         "LEFT JOIN user_properties AS u4 ON u.id=u4.user_id AND u4.proptag=805568543 "
	         "LEFT JOIN user_properties AS u5 ON u.id=u5.user_id AND u5.proptag=974913567 "
	         "LEFT JOIN user_properties AS u6 ON u.id=u6.user_id AND u6.proptag=974782495 "
	         "LEFT JOIN user_properties AS u7 ON u.id=u7.user_id AND u7.proptag=978255903 "
	         "LEFT JOIN user_properties AS u8 ON u.id=u8.user_id AND u8.proptag=979173407 "
	         "WHERE u.group_id=%d AND (SELECT COUNT(*) AS num FROM members WHERE u.username=members.username)=0",
	         group_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	
	size_t i, rows = pmyres.num_rows();
	pfile.clear();
	pfile.reserve(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		address_type = atoi(myrow[10]);
		if (ADDRESS_TYPE_NORMAL == address_type) {
			switch (atoi(myrow[12])) {
			case SUB_TYPE_ROOM:
				address_type = ADDRESS_TYPE_ROOM;
				break;
			case SUB_TYPE_EQUIPMENT:
				address_type = ADDRESS_TYPE_EQUIPMENT;
				break;
			}
		}
		sql_user u;
		switch (address_type) {
		case ADDRESS_TYPE_NORMAL:
		case ADDRESS_TYPE_ROOM:
		case ADDRESS_TYPE_EQUIPMENT:
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			temp_len = z_strlen(myrow[3]);
			if (0 == temp_len) {
				ptoken = strchr(myrow[2], '@');
				temp_len = ptoken - myrow[2];
				u.realname = std::string(myrow[2], temp_len);
			} else {
				u.realname = z_null(myrow[3]);
			}
			u.title = z_null(myrow[4]);
			u.memo = z_null(myrow[5]);
			u.cell = z_null(myrow[6]);
			u.tel = z_null(myrow[7]);
			u.nickname = z_null(myrow[8]);
			u.homeaddr = z_null(myrow[9]);
			u.maildir = myrow[13];
			pfile.push_back(std::move(u));
			break;
		case ADDRESS_TYPE_MLIST:
			if (!mysql_adaptor_get_mlist_info(myrow[2],
			    &u.list_type, &u.list_priv, title))
				return -1;
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			if (u.list_type == MLIST_TYPE_GROUP ||
			    u.list_type == MLIST_TYPE_CLASS)
				u.title = z_null(myrow[4]);
			pfile.push_back(std::move(u));
			break;
		}
	}
	return pfile.size();
}

static bool get_domain_aliases(sqlconn_ptr &conn, int domain_id,
    sql_user::alias_map_type &out)
{
	char query[160];
	snprintf(query, sizeof(query),
		"SELECT u.username, a.aliasname FROM users AS u "
		"INNER JOIN aliases AS a ON u.username=a.mainname "
		"WHERE u.domain_id=%d", domain_id);
	if (mysql_query(conn.get(), query) != 0) {
		conn = sql_make_conn();
		if (conn == nullptr ||
		    mysql_query(conn.get(), query) != 0)
			return false;
	}
	DB_RESULT res(mysql_store_result(conn.get()));
	if (res == nullptr)
		return false;
	out.clear();
	DB_ROW row;
	while ((row = res.fetch_row()) != nullptr)
		out.emplace(row[0], row[1]);
	return true;
}

int mysql_adaptor_get_domain_users(int domain_id, std::vector<sql_user> &pfile)
{
	int temp_len;
	char *ptoken;
	int address_type;
	char title[1024];
	char sql_string[1024];
	sql_user::alias_map_type dom_alias;

	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	get_domain_aliases(conn.res, domain_id, dom_alias);
	snprintf(sql_string, sizeof(sql_string),
	         "SELECT u.id, u.privilege_bits, u.username, "
	         "u2.propval_str AS real_name, u3.propval_str AS title, "
	         "u4.propval_str AS memo, u5.propval_str AS cell, "
	         "u6.propval_str AS tel, u7.propval_str AS nickname, "
	         "u8.propval_str AS homeaddress, u.address_type, 0 AS create_day, "
	         "u.sub_type, u.maildir FROM users AS u "
	         "LEFT JOIN user_properties AS u2 ON u.id=u2.user_id AND u2.proptag=805371935 "
	         "LEFT JOIN user_properties AS u3 ON u.id=u3.user_id AND u3.proptag=974585887 "
	         "LEFT JOIN user_properties AS u4 ON u.id=u4.user_id AND u4.proptag=805568543 "
	         "LEFT JOIN user_properties AS u5 ON u.id=u5.user_id AND u5.proptag=974913567 "
	         "LEFT JOIN user_properties AS u6 ON u.id=u6.user_id AND u6.proptag=974782495 "
	         "LEFT JOIN user_properties AS u7 ON u.id=u7.user_id AND u7.proptag=978255903 "
	         "LEFT JOIN user_properties AS u8 ON u.id=u8.user_id AND u8.proptag=979173407 "
	         "WHERE u.domain_id=%d AND u.group_id=0", domain_id);
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();

	size_t i, rows = pmyres.num_rows();
	pfile.clear();
	pfile.reserve(rows);
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		address_type = atoi(myrow[10]);
		if (ADDRESS_TYPE_NORMAL == address_type) {
			switch (atoi(myrow[12])) {
			case SUB_TYPE_ROOM:
				address_type = ADDRESS_TYPE_ROOM;
				break;
			case SUB_TYPE_EQUIPMENT:
				address_type = ADDRESS_TYPE_EQUIPMENT;
				break;
			}
		}
		sql_user u;
		switch (address_type) {
		case ADDRESS_TYPE_NORMAL:
		case ADDRESS_TYPE_ROOM:
		case ADDRESS_TYPE_EQUIPMENT:
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			temp_len = z_strlen(myrow[3]);
			if (0 == temp_len) {
				ptoken = strchr(myrow[2], '@');
				temp_len = ptoken - myrow[2];
				u.realname = std::string(myrow[2], temp_len);
			} else {
				u.realname = z_null(myrow[3]);
			}
			u.title = z_null(myrow[4]);
			u.memo = z_null(myrow[5]);
			u.cell = z_null(myrow[6]);
			u.tel = z_null(myrow[7]);
			u.nickname = z_null(myrow[8]);
			u.homeaddr = z_null(myrow[9]);
			u.maildir = myrow[13];
			u.aliases = std::move(dom_alias);
			pfile.push_back(std::move(u));
			break;
		case ADDRESS_TYPE_MLIST:
			if (!mysql_adaptor_get_mlist_info(myrow[2],
			    &u.list_type, &u.list_priv, title))
				return -1;
			u.addr_type = address_type;
			u.id = strtoul(myrow[0], nullptr, 0);
			u.username = myrow[2];
			if (u.list_type == MLIST_TYPE_GROUP ||
			    u.list_type == MLIST_TYPE_CLASS)
				u.title = z_null(myrow[4]);
			u.aliases = std::move(dom_alias);
			pfile.push_back(std::move(u));
			break;
		}
	}
	return pfile.size();
}

static BOOL mysql_adaptor_hierarchy_include(
	MYSQL *pmysql, const char *account, int class_id)
{
	int child_id;
	char sql_string[512];
	
	snprintf(sql_string, sizeof(sql_string), "SELECT username FROM members WHERE"
		" class_id=%d AND username='%s'", class_id, account);
	if (mysql_query(pmysql, sql_string) != 0)
		return false;
	DB_RESULT pmyres = mysql_store_result(pmysql);
	if (pmyres == nullptr)
		return FALSE;
	if (pmyres.num_rows() > 0)
		return TRUE;

	snprintf(sql_string, sizeof(sql_string), "SELECT child_id FROM"
			" hierarchy WHERE class_id=%d", class_id);
	if (mysql_query(pmysql, sql_string) != 0)
		return false;
	pmyres = mysql_store_result(pmysql);
	if (pmyres == nullptr)
		return FALSE;
	size_t i, rows = pmyres.num_rows();
	for (i=0; i<rows; i++) {
		auto myrow = pmyres.fetch_row();
		child_id = atoi(myrow[0]);
		if (TRUE == mysql_adaptor_hierarchy_include(
			pmysql, account, child_id)) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL mysql_adaptor_check_mlist_include(
	const char *mlist_name, const char *account)
{
	int group_id;
	int class_id;
	int domain_id;
	BOOL b_result;
	int id, type;
	char temp_name[512];
	char *pencode_domain;
	char temp_account[512];
	char sql_string[1024];
	
	if (NULL == strchr(mlist_name, '@')) {
		return FALSE;
	}
	
	mysql_adaptor_encode_squote(mlist_name, temp_name);
	pencode_domain = strchr(temp_name, '@') + 1;
	mysql_adaptor_encode_squote(account, temp_account);
	snprintf(sql_string, 1024, "SELECT id, list_type "
		"FROM mlists WHERE listname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	
	id = atoi(myrow[0]);
	type = atoi(myrow[1]);
	
	b_result = FALSE;
	switch (type) {
	case MLIST_TYPE_NORMAL:
		snprintf(sql_string, 1024, "SELECT username FROM associations"
			" WHERE list_id=%d AND username='%s'", id, temp_account);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = TRUE;
		return b_result;
	case MLIST_TYPE_GROUP:
		snprintf(sql_string, 1024, "SELECT id FROM "
			"groups WHERE groupname='%s'", temp_name);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1)
			return FALSE;
		myrow = pmyres.fetch_row();
		group_id = atoi(myrow[0]);
		
		snprintf(sql_string, 1024, "SELECT username FROM users WHERE"
			" group_id=%d AND username='%s'", group_id, temp_account);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = TRUE;
		return b_result;
	case MLIST_TYPE_DOMAIN:
		snprintf(sql_string, 1024, "SELECT id FROM domains"
				" WHERE domainname='%s'", pencode_domain);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1)
			return FALSE;
		myrow = pmyres.fetch_row();
		domain_id = atoi(myrow[0]);
		
		snprintf(sql_string, 1024, "SELECT username FROM users WHERE"
			" domain_id=%d AND username='%s'", domain_id, temp_account);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() > 0)
			b_result = TRUE;
		return b_result;
	case MLIST_TYPE_CLASS:
		snprintf(sql_string, 1024, "SELECT id FROM "
			"classes WHERE listname='%s'", temp_name);
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1)
			return FALSE;		
		myrow = pmyres.fetch_row();
		class_id = atoi(myrow[0]);
		b_result = mysql_adaptor_hierarchy_include(conn.res.get(), temp_account, class_id);
		return b_result;
	default:
		return FALSE;
	}
}

static void mysql_adaptor_encode_squote(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if ('\'' == in[i] || '\\' == in[i]) {
			out[j] = '\\';
			j ++;
	}
		out[j] = in[i];
	}
	out[j] = '\0';
}

BOOL mysql_adaptor_check_same_org2(
	const char *domainname1, const char *domainname2)
{
	int org_id1;
	int org_id2;
	char temp_name1[512];
	char temp_name2[512];
	char sql_string[1024];

	mysql_adaptor_encode_squote(domainname1, temp_name1);
	mysql_adaptor_encode_squote(domainname2, temp_name2);
	snprintf(sql_string, 1024, "SELECT org_id FROM domains "
		"WHERE domainname='%s' OR domainname='%s'",
		temp_name1, temp_name2);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 2)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	org_id1 = atoi(myrow[0]);
	myrow = pmyres.fetch_row();
	org_id2 = atoi(myrow[0]);
	if (0 == org_id1 || 0 == org_id2 || org_id1 != org_id2) {
		return FALSE;
	}
	return TRUE;
}

BOOL mysql_adaptor_check_user(const char *username, char *path)
{
	char temp_name[512];
	char sql_string[1024];

	if (path != nullptr)
		*path = '\0';
	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT address_status, maildir FROM users "
		"WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1) {
		return FALSE;
	} else {
		auto myrow = pmyres.fetch_row();
		if (0 != atoi(myrow[0])) {
			if (NULL != path) {
				strcpy(path, myrow[1]);
			}
			return FALSE;
		} else {
			if (NULL != path) {
				strcpy(path, myrow[1]);
			}
			return TRUE;
		}
	}
}

BOOL mysql_adaptor_get_forward(const char *username, int *ptype,
    char *destination)
{
	char temp_name[512];
	char sql_string[1024];

	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT destination, forward_type FROM "
		"forwards WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(),	sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1) {
		destination[0] = '\0';
	} else {
		auto myrow = pmyres.fetch_row();
		strcpy(destination, myrow[0]);
		*ptype = atoi(myrow[1]);
	}
	return TRUE;
}

BOOL mysql_adaptor_get_mlist(const char *username,  const char *from,
    int *presult, std::vector<std::string> &pfile)
{
	int i, id, rows;
	int type, privilege;
	int group_id;
	int domain_id;
	int class_id;
	BOOL b_chkintl;
	char *pencode_domain;
	char temp_name[512];
	char sql_string[1024];

	*presult = MLIST_RESULT_NONE;
	const char *pdomain = strchr(username, '@');
	if (NULL == pdomain) {
		return TRUE;
	}

	pdomain++;
	const char *pfrom_domain = strchr(from, '@');
	if (NULL == pfrom_domain) {
		return TRUE;
	}

	pfrom_domain++;
	mysql_adaptor_encode_squote(username, temp_name);
	pencode_domain = strchr(temp_name, '@') + 1;

	snprintf(sql_string, 1024, "SELECT id, list_type, list_privilege"
		" FROM mlists WHERE listname='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	if (pmyres.num_rows() != 1) {
		*presult = MLIST_RESULT_NONE;
		return TRUE;
	}
	auto myrow = pmyres.fetch_row();
	id = atoi(myrow[0]);
	type = atoi(myrow[1]);
	privilege = atoi(myrow[2]);
	b_chkintl = FALSE;

	switch (type) {
	case MLIST_TYPE_NORMAL:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (mysql_query(conn.res.get(), sql_string) != 0) {
				conn.res = sql_make_conn();
				if (conn.res == nullptr ||
				    mysql_query(conn.res.get(), sql_string) != 0)
					return false;
			}

			pmyres = mysql_store_result(conn.res.get());
			if (pmyres == nullptr)
				return false;
			rows = pmyres.num_rows();
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			if (i == rows) {
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		default:
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}
		snprintf(sql_string, 1024, "SELECT username "
			"FROM associations WHERE list_id=%d", id);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (TRUE == b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			pfile.push_back(myrow[0]);
		}
		*presult = MLIST_RESULT_OK;
		return TRUE;

	case MLIST_TYPE_GROUP:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (mysql_query(conn.res.get(), sql_string) != 0) {
				conn.res = sql_make_conn();
				if (conn.res == nullptr ||
				    mysql_query(conn.res.get(), sql_string) != 0)
					return false;
			}

			pmyres = mysql_store_result(conn.res.get());
			if (pmyres == nullptr)
				return false;
			rows = pmyres.num_rows();
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			if (i == rows) {
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		default:
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}
		snprintf(sql_string, 1024, "SELECT id FROM "
			"groups WHERE groupname='%s'", temp_name);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1) {
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}
		myrow = pmyres.fetch_row();
		group_id = atoi(myrow[0]);
		snprintf(sql_string, 1024, "SELECT username, address_type,"
				" sub_type FROM users WHERE group_id=%d", group_id);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (TRUE == b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
					&& SUB_TYPE_USER == atoi(myrow[2]) &&
					0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
				&& SUB_TYPE_USER == atoi(myrow[2])) {
				pfile.push_back(myrow[0]);
			}
		}
		*presult = MLIST_RESULT_OK;
		return TRUE;

	case MLIST_TYPE_DOMAIN:
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (mysql_query(conn.res.get(), sql_string) != 0) {
				conn.res = sql_make_conn();
				if (conn.res == nullptr ||
				    mysql_query(conn.res.get(), sql_string) != 0)
					return false;
			}

			pmyres = mysql_store_result(conn.res.get());
			if (pmyres == nullptr)
				return false;
			rows = pmyres.num_rows();
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			if (i == rows) {
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		default:
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}
		snprintf(sql_string, 1024, "SELECT id FROM domains"
				" WHERE domainname='%s'", pencode_domain);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1) {
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}
		myrow = pmyres.fetch_row();
		domain_id = atoi(myrow[0]);
		snprintf(sql_string, 1024, "SELECT username, address_type,"
			" sub_type FROM users WHERE domain_id=%d", domain_id);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		rows = pmyres.num_rows();
		if (TRUE == b_chkintl) {
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
					&& SUB_TYPE_USER == atoi(myrow[2]) &&
					0 == strcasecmp(myrow[0], from)) {
					b_chkintl = FALSE;
					break;
				}
			}
		}

		if (TRUE == b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		mysql_data_seek(pmyres.get(), 0);
		for (i = 0; i < rows; i++) {
			myrow = pmyres.fetch_row();
			if (ADDRESS_TYPE_NORMAL == atoi(myrow[1])
				&& SUB_TYPE_USER == atoi(myrow[2])) {
				pfile.push_back(myrow[0]);
			}
		}
		*presult = MLIST_RESULT_OK;
		return TRUE;

	case MLIST_TYPE_CLASS: {
		switch (privilege) {
		case MLIST_PRIVILEGE_ALL:
		case MLIST_PRIVILEGE_OUTGOING:
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_INTERNAL:
			b_chkintl = TRUE;
			break;
		case MLIST_PRIVILEGE_DOMAIN:
			if (0 != strcasecmp(pdomain, pfrom_domain)) {
				*presult = MLIST_RESULT_PRIVIL_DOMAIN;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		case MLIST_PRIVILEGE_SPECIFIED:
			snprintf(sql_string, 1024, "SELECT username"
				" FROM specifieds WHERE list_id=%d", id);
			if (mysql_query(conn.res.get(), sql_string) != 0) {
				conn.res = sql_make_conn();
				if (conn.res == nullptr ||
				    mysql_query(conn.res.get(), sql_string) != 0)
					return false;
			}

			pmyres = mysql_store_result(conn.res.get());
			if (pmyres == nullptr)
				return false;
			rows = pmyres.num_rows();
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				if (0 == strcasecmp(myrow[0], from) ||
					0 == strcasecmp(myrow[0], pfrom_domain)) {
					break;
				}
			}
			if (i == rows) {
				*presult = MLIST_RESULT_PRIVIL_SPECIFIED;
				return TRUE;
			}
			b_chkintl = FALSE;
			break;
		default:
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}

		snprintf(sql_string, 1024, "SELECT id FROM "
			"classes WHERE listname='%s'", temp_name);
		if (mysql_query(conn.res.get(), sql_string) != 0) {
			conn.res = sql_make_conn();
			if (conn.res == nullptr ||
			    mysql_query(conn.res.get(), sql_string) != 0)
				return false;
		}

		pmyres = mysql_store_result(conn.res.get());
		if (pmyres == nullptr)
			return false;
		if (pmyres.num_rows() != 1) {
			*presult = MLIST_RESULT_NONE;
			return TRUE;
		}

		myrow = pmyres.fetch_row();
		class_id = atoi(myrow[0]);
		std::vector<int> file_temp{class_id};
		if (!mysql_adaptor_expand_hierarchy(conn.res.get(),
		    file_temp, class_id)) {
			*presult = MLIST_RESULT_NONE;
			return FALSE;
		}

		std::set<std::string, icasecmp> file_temp1;
		for (auto class_id : file_temp) {
			snprintf(sql_string, 1024, "SELECT username "
				"FROM members WHERE class_id=%d", class_id);
			if (mysql_query(conn.res.get(), sql_string) != 0) {
				conn.res = sql_make_conn();
				if (conn.res == nullptr ||
				    mysql_query(conn.res.get(), sql_string) != 0)
					return false;
			}

			pmyres = mysql_store_result(conn.res.get());
			if (pmyres == nullptr)
				return false;
			rows = pmyres.num_rows();
			for (i = 0; i < rows; i++) {
				myrow = pmyres.fetch_row();
				file_temp1.emplace(myrow[0]);
			}
		}

		if (TRUE == b_chkintl)
			b_chkintl = file_temp1.find(from) == file_temp1.cend();
		if (TRUE == b_chkintl) {
			*presult = MLIST_RESULT_PRIVIL_INTERNAL;
			return TRUE;
		}
		for (auto &&temp_name : file_temp1)
			pfile.push_back(std::move(temp_name));
		*presult = MLIST_RESULT_OK;
		return TRUE;
	}
	default:
		*presult = MLIST_RESULT_NONE;
		return TRUE;
	}
}

BOOL mysql_adaptor_get_user_info(const char *username,
    char *maildir, char *lang, char *timezone)
{
	char temp_name[512];
	char sql_string[1024];

	mysql_adaptor_encode_squote(username, temp_name);
	snprintf(sql_string, 1024, "SELECT maildir, address_status, "
		"lang, timezone FROM users WHERE username='%s'", temp_name);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();

	if (pmyres.num_rows() != 1) {
		maildir[0] = '\0';
	} else {
		auto myrow = pmyres.fetch_row();
		if (0 == atoi(myrow[1])) {
			strcpy(maildir, myrow[0]);
			strcpy(lang, myrow[2]);
			strcpy(timezone, myrow[3]);
		} else {
			maildir[0] = '\0';
		}
	}
	return TRUE;
}

BOOL mysql_adaptor_get_username(int user_id, char *username)
{
	char sql_string[1024];

	snprintf(sql_string, 1024, "SELECT username FROM users "
		"WHERE id=%d", user_id);
	auto conn = g_sqlconn_pool.get_wait();
	if (conn.res == nullptr)
		return false;
	if (mysql_query(conn.res.get(), sql_string) != 0) {
		conn.res = sql_make_conn();
		if (conn.res == nullptr ||
		    mysql_query(conn.res.get(), sql_string) != 0)
			return false;
	}

	DB_RESULT pmyres = mysql_store_result(conn.res.get());
	if (pmyres == nullptr)
		return false;
	conn.finish();
	if (pmyres.num_rows() != 1)
		return FALSE;
	auto myrow = pmyres.fetch_row();
	strncpy(username, myrow[0], 256);
	return TRUE;
}

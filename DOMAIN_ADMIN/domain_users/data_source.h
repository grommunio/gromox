#ifndef _H_DATA_SOURCE_
#define _H_DATA_SOURCE_
#include "common_types.h"
#include "double_list.h"
#include <time.h>

enum {
	ADD_RESULT_OK = 0,
	ADD_RESULT_NODOMAIN,
	ADD_RESULT_DOMAINNOTMAIN,
	ADD_RESULT_SIZEFULL,
	ADD_RESULT_USERFULL,
	ADD_RESULT_NOGROUP,
	ADD_RESULT_GROUPERR,
	ADD_RESULT_MLIST,
	ADD_RESULT_EXIST
};

enum {
	EDIT_RESULT_OK = 0,
	EDIT_RESULT_NODOMAIN,
	EDIT_RESULT_DOMAINNOTMAIN,
	EDIT_RESULT_NOGROUP,
	EDIT_RESULT_GROUPERR,
	EDIT_RESULT_NOEXIST,
	EDIT_RESULT_SIZEFULL,
	EDIT_RESULT_NOTMAIN
};

enum {
	ALIAS_RESULT_OK = 0,
	ALIAS_RESULT_NODOMAIN,
	ALIAS_RESULT_DOMAINNOTMAIN,
	ALIAS_RESULT_FULL,
	ALIAS_RESULT_MLIST,
	ALIAS_RESULT_EXIST,
	ALIAS_RESULT_NOEXIST,
	ALIAS_RESULT_NOTMAIN
};

#define RECORD_STATUS_NORMAL				0

#define RECORD_STATUS_SUSPEND				1

#define RECORD_STATUS_OUTOFDATE				2

#define RECORD_STATUS_DELETED				3

#define DOMAIN_TYPE_NORMAL					0

#define DOMAIN_TYPE_ALIAS					1

#define ADDRESS_TYPE_NORMAL					0

#define ADDRESS_TYPE_ALIAS					1

#define ADDRESS_TYPE_MLIST					2

#define ADDRESS_TYPE_VIRTUAL				3
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM					4
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT				5

#define SUB_TYPE_USER						0

#define SUB_TYPE_ROOM						1

#define SUB_TYPE_EQUIPMENT					2

#define DOMAIN_PRIVILEGE_NETDISK			0x10

#define DOMAIN_PRIVILEGE_EXTPASSWD			0x20

#define USER_PRIVILEGE_POP3_IMAP            0x1

#define USER_PRIVILEGE_SMTP                 0x2

#define USER_PRIVILEGE_CHGPASSWD            0x4

#define USER_PRIVILEGE_PUBADDR              0x8

#define USER_PRIVILEGE_NETDISK              0x10



typedef struct _USER_ITEM {
	char username[128];
	char title[128];
	char real_name[128];
	char nickname[128];
	char tel[64];
	char cell[64];
	char homeaddress[128];
	char memo[128];
	int group_id;
	char group_title[128];
	char maildir[128];
	int max_size;
	time_t create_day;
	int privilege_bits;
	int address_status;
	int address_type;
	int sub_type;
} USER_ITEM;

typedef struct _DATA_COLLECT {
	DOUBLE_LIST list;
	DOUBLE_LIST_NODE *pnode;
} DATA_COLLECT;

typedef struct _DATA_NODE {
	DOUBLE_LIST_NODE node;
	USER_ITEM item;
} DATA_NODE;

DATA_COLLECT* data_source_collect_init();

void data_source_collect_free(DATA_COLLECT *pcollect);

int data_source_collect_total(DATA_COLLECT *pcollect);

void data_source_collect_begin(DATA_COLLECT *pcollect);

int data_source_collect_done(DATA_COLLECT *pcollect);

USER_ITEM* data_source_collect_get_value(DATA_COLLECT *pcollect);

int data_source_collect_forward(DATA_COLLECT *pcollect);


void data_source_init(const char *host, int port, const char *user,
	const char *password, const char *db_name);

int data_source_run();

int data_source_stop();

void data_source_free();

BOOL data_source_query(const char *domainname, const char *username,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int group_id, int size_min, int size_max,
	time_t create_min, time_t create_max, int address_status,
	int address_type, DATA_COLLECT *pcollect);

BOOL data_source_add_user(const char *username, const char *password,
	const char *lang, const char *title, const char *real_name,
	const char *nickname, const char *tel, const char *cell,
	const char *homeaddress, const char *memo, int group_id,
	const char *maildir, int max_size, int max_file,
	int privilege_bits, int address_status, int sub_type,
	int *presult, int *puser_id);

BOOL data_source_add_alias(const char *username, const char *alias,
	int *presult);

BOOL data_source_edit_user(const char *username, const char *password,
	const char *title, const char *real_name, const char *nickname,
	const char *tel, const char *cell, const char *homeaddress,
	const char *memo, int group_id, int max_size, int privilege_bits,
	int address_status, int *presult);

BOOL data_source_get_username_by_alias(const char *username, char *user_buff);

BOOL data_source_remove_user(const char *username, BOOL *pb_alias,
	DATA_COLLECT *pcollect);

BOOL data_source_get_aliases(const char *username, DATA_COLLECT *pcollect);

BOOL data_source_num_user(const char *domainname, int *pnum);

BOOL data_source_get_domain_homedir(const char *domainname, char *path_buff);

BOOL data_source_get_user_maildir(const char *username, char *path_buff);

BOOL data_source_get_groups(const char *domainname, DATA_COLLECT *pcollect);

BOOL data_source_get_grouptitle(int group_id, char *title_buff);

BOOL data_source_get_domain_privilege(const char *domainname, int *pprivilege);

BOOL data_source_check_domain_migration(const char *domainname,
	BOOL *pb_migrating, char *media_area);

#endif

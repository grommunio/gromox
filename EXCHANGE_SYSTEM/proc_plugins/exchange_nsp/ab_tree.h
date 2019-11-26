#ifndef _H_AB_TREE_
#define _H_AB_TREE_

#ifdef __cplusplus
#	include <cstdint>
#	include <ctime>
#else
#	include <stdint.h>
#	include <time.h>
#endif
#include "proc_common.h"
#include "simple_tree.h"
#include "single_list.h"
#include "int_hash.h"
#include "mem_file.h"

#define NODE_TYPE_DOMAIN					0x81
#define NODE_TYPE_GROUP						0x82
#define NODE_TYPE_CLASS						0x83
#define NODE_TYPE_REMOTE					0x0
#define NODE_TYPE_PERSOPN					0x1
#define NODE_TYPE_MLIST						0x2
#define NODE_TYPE_ROOM						0x3
#define NODE_TYPE_EQUIPMENT					0x4
#define NODE_TYPE_FOLDER					0x5

#define USER_MAIL_ADDRESS					0
#define USER_REAL_NAME						1
#define USER_JOB_TITLE						2
#define USER_COMMENT						3
#define USER_MOBILE_TEL						4
#define USER_BUSINESS_TEL					5
#define USER_NICK_NAME						6
#define USER_HOME_ADDRESS					7
#define USER_CREATE_DAY						8
#define USER_STORE_PATH						9

typedef struct _DOMAIN_NODE {
	SINGLE_LIST_NODE node;
	int domain_id;
	SIMPLE_TREE tree;
} DOMAIN_NODE;

typedef struct _AB_BASE {
	GUID guid;
	volatile int status;
	volatile int reference;
	time_t load_time;
	int base_id;
	SINGLE_LIST list;
	SINGLE_LIST gal_list;
	SINGLE_LIST remote_list;
	INT_HASH_TABLE *phash;
} AB_BASE;


void ab_tree_init(const char *org_name, int base_size,
	int cache_interval, int file_blocks);
extern int ab_tree_run(void);
extern int ab_tree_stop(void);
extern void ab_tree_free(void);
AB_BASE* ab_tree_get_base(int base_id);

void ab_tree_put_base(AB_BASE *pbase);

uint32_t ab_tree_get_leaves_num(SIMPLE_TREE_NODE *pnode);

void ab_tree_node_to_guid(SIMPLE_TREE_NODE *pnode, GUID *pguid);

BOOL ab_tree_node_to_dn(SIMPLE_TREE_NODE *pnode, char *pbuff, int length);

SIMPLE_TREE_NODE* ab_tree_dn_to_node(AB_BASE *pbase, const char *pdn);

SIMPLE_TREE_NODE* ab_tree_uid_to_node(AB_BASE *pbase, int user_id);

SIMPLE_TREE_NODE* ab_tree_minid_to_node(AB_BASE *pbase, uint32_t minid);

uint32_t ab_tree_get_node_minid(SIMPLE_TREE_NODE *pnode);

uint8_t ab_tree_get_node_type(SIMPLE_TREE_NODE *pnode);

void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, char *str_dname);
	
void ab_tree_get_user_info(SIMPLE_TREE_NODE *pnode, int type, char *value);
	
void ab_tree_get_mlist_info(SIMPLE_TREE_NODE *pnode,
	char *mail_address, char *create_day, int *plist_privilege);

void ab_tree_get_mlist_title(uint32_t codepage, char *str_title);

void ab_tree_get_company_info(SIMPLE_TREE_NODE *pnode,
	char *str_name, char *str_address);

void ab_tree_get_department_name(SIMPLE_TREE_NODE *pnode,
	char *str_name);

void ab_tree_get_server_dn(SIMPLE_TREE_NODE *pnode, char *dn, int length);

int ab_tree_get_guid_base_id(GUID guid);

#endif /* _H_AB_TREE_ */

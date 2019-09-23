#include "util.h"
#include "guid.h"
#include "ab_tree.h"
#include "ext_buffer.h"
#include "common_util.h"
#include "zarafa_server.h"
#include "system_services.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/md5.h>

#define EPOCH_DIFF 							11644473600LL

#define DTE_FLAG_ACL_CAPABLE				0x40000000

#define ADDRESS_TYPE_NORMAL					0
#define ADDRESS_TYPE_ALIAS					1
#define ADDRESS_TYPE_MLIST					2
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_ROOM */
#define ADDRESS_TYPE_ROOM					4
/* composd value, not in database, means ADDRESS_TYPE_NORMAL and SUB_TYPE_EQUIPMENT */
#define ADDRESS_TYPE_EQUIPMENT				5

#define BASE_STATUS_CONSTRUCTING			0
#define BASE_STATUS_LIVING					1
#define BASE_STATUS_DESTRUCTING				2

#define MLIST_TYPE_NORMAL 					0
#define MLIST_TYPE_GROUP					1
#define MLIST_TYPE_DOMAIN					2
#define MLIST_TYPE_CLASS					3

/* 0x00 ~ 0x10 minid reserved by nspi */
#define MINID_TYPE_RESERVED					7

#define HGROWING_SIZE						100

/* 
	PERSON: username, real_name, title, memo, cell, tel,
			nickname, homeaddress, create_day, maildir
	ROOM: title
	EQUIPMENT: title
	MLIST: listname, list_type(int), list_privilege(int)
	DOMAIN: domainname, title, address
	GROUP: groupname, title
	CLASS: classname
*/

typedef struct _AB_NODE {
	SIMPLE_TREE_NODE node;
	uint8_t node_type;
	uint32_t minid;
	MEM_FILE f_info;
	int id;
} AB_NODE;

typedef struct _GUID_ENUM {
	int item_id;
	int node_type;
	uint64_t dgt;
	AB_NODE *pabnode;
} GUID_ENUM;

typedef struct _SORT_ITEM {
	SIMPLE_TREE_NODE *pnode;
	char *string;
} SORT_ITEM;

static int g_base_size;
static int g_file_blocks;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static int g_cache_interval;
static char g_org_name[256];
static SINGLE_LIST g_snode_list;
static SINGLE_LIST g_abnode_list;
static INT_HASH_TABLE *g_base_hash;
static pthread_mutex_t g_base_lock;
static pthread_mutex_t g_list_lock;
static LIB_BUFFER *g_file_allocator;
static const uint8_t g_guid_nspi[] = {0xDC, 0xA7, 0x40, 0xC8,
									   0xC0, 0x42, 0x10, 0x1A,
									   0xB4, 0xB9, 0x08, 0x00,
									   0x2B, 0x2F, 0xE1, 0x82};

static void* scan_work_func(void *param);

static void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, char *str_dname);

static void ab_tree_get_user_info(
	SIMPLE_TREE_NODE *pnode, int type, char *value);

uint32_t ab_tree_make_minid(uint8_t type, int value)
{
	uint32_t minid;
	
	if (MINID_TYPE_ADDRESS == type && value <= 0x10) {
		type = MINID_TYPE_RESERVED;
	}
	minid = type;
	minid <<= 29;
	minid |= value;
	return minid;
}

uint8_t ab_tree_get_minid_type(uint32_t minid)
{
	uint8_t type;
	
	if (0 == (minid & 0x80000000)) {
		return MINID_TYPE_ADDRESS;
	}
	type = minid >> 29;
	if (MINID_TYPE_RESERVED == type) {
		return MINID_TYPE_ADDRESS;
	}
	return type;
}

int ab_tree_get_minid_value(uint32_t minid)
{
	if (0 == (minid & 0x80000000)) {
		return minid;
	}
	return minid & 0x1FFFFFFF;
}

uint32_t ab_tree_get_leaves_num(SIMPLE_TREE_NODE *pnode)
{
	uint32_t count;
	
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return 0;
	}
	count = 0;
	do {
		if (ab_tree_get_node_type(pnode) < 0x80) {
			count ++;
		}
	} while (pnode=simple_tree_node_get_slibling(pnode));
	return count;
}

static SINGLE_LIST_NODE* ab_tree_get_snode()
{
	SINGLE_LIST_NODE *psnode;
	
	pthread_mutex_lock(&g_list_lock);
	psnode = single_list_get_from_head(&g_snode_list);
	pthread_mutex_unlock(&g_list_lock);
	if (NULL == psnode) {
		psnode = malloc(sizeof(SINGLE_LIST_NODE));
	}
	return psnode;
}

static void ab_tree_put_snode(SINGLE_LIST_NODE *psnode)
{
	pthread_mutex_lock(&g_list_lock);
	single_list_append_as_tail(&g_snode_list, psnode);
	pthread_mutex_unlock(&g_list_lock);
}

static AB_NODE* ab_tree_get_abnode()
{
	AB_NODE *pabnode;
	
	pthread_mutex_lock(&g_list_lock);
	pabnode = (AB_NODE*)single_list_get_from_head(&g_abnode_list);
	pthread_mutex_unlock(&g_list_lock);
	if (NULL == pabnode) {
		pabnode = malloc(sizeof(AB_NODE));
	}
	if (NULL != pabnode) {
		mem_file_init(&pabnode->f_info, g_file_allocator);
		pabnode->minid = 0;
	}
	return pabnode;
}

static void ab_tree_put_abnode(AB_NODE *pabnode)
{
	mem_file_free(&pabnode->f_info);
	pthread_mutex_lock(&g_list_lock);
	single_list_append_as_tail(&g_abnode_list,
				(SINGLE_LIST_NODE*)pabnode);
	pthread_mutex_unlock(&g_list_lock);
}

SIMPLE_TREE_NODE* ab_tree_minid_to_node(AB_BASE *pbase, uint32_t minid)
{
	SINGLE_LIST_NODE *psnode;
	SIMPLE_TREE_NODE **ppnode;
	
	ppnode = int_hash_query(pbase->phash, minid);
	if (NULL != ppnode) {
		return *ppnode;
	}
	return NULL;
}

void ab_tree_init(const char *org_name, int base_size,
	int cache_interval, int file_blocks)
{
	strcpy(g_org_name, org_name);
	g_base_size = base_size;
	g_cache_interval = cache_interval;
	g_file_blocks = file_blocks;
	single_list_init(&g_snode_list);
	single_list_init(&g_abnode_list);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_base_lock, NULL);
	g_notify_stop = TRUE;
}

int ab_tree_run()
{
	int i;
	AB_NODE *pabnode;
	SINGLE_LIST_NODE *psnode;
	
	g_base_hash = int_hash_init(g_base_size, sizeof(AB_BASE*), NULL);
	if (NULL == g_base_hash) {
		printf("[exchange_nsp]: fail to init base hash table\n");
		return -1;
	}
	g_file_allocator = lib_buffer_init(
		FILE_ALLOC_SIZE, g_file_blocks, TRUE);
	if (NULL == g_file_allocator) {
		printf("[exchange_nsp]: fail to allocate file blocks\n");
		return -2;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		printf("[exchange_nsp]: fail to create scanning thread\n");
		g_notify_stop = TRUE;
		return -3;
	}
	for (i=0; i<2*g_file_blocks; i++) {
		psnode = ab_tree_get_snode();
		if (NULL != psnode) {
			ab_tree_put_snode(psnode);
		}
	}
	for (i=0; i<g_file_blocks; i++) {
		pabnode = ab_tree_get_abnode();
		if (NULL != pabnode) {
			ab_tree_put_abnode(pabnode);
		}
	}
	return 0;
}

static void ab_tree_destruct_tree(SIMPLE_TREE *ptree)
{
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(ptree);
	if (NULL != proot) {
		simple_tree_destroy_node(ptree, proot,
			(SIMPLE_TREE_DELETE)ab_tree_put_abnode);
	}
	simple_tree_free(ptree);
}

static void ab_tree_unload_base(AB_BASE *pbase)
{
	SINGLE_LIST_NODE *pnode;
	
	while (pnode = single_list_get_from_head(&pbase->list)) {
		ab_tree_destruct_tree(&((DOMAIN_NODE*)pnode->pdata)->tree);
		free(pnode->pdata);
	}
	single_list_free(&pbase->list);
	while (pnode = single_list_get_from_head(&pbase->gal_list)) {
		ab_tree_put_snode(pnode);
	}
	single_list_free(&pbase->gal_list);
	if (NULL != pbase->phash) {
		int_hash_free(pbase->phash);
		pbase->phash = NULL;
	}
}

int ab_tree_stop()
{
	AB_BASE **ppbase;
	INT_HASH_ITER *iter;
	SINGLE_LIST_NODE *pnode;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}
	if (NULL != g_base_hash) {
		iter = int_hash_iter_init(g_base_hash);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ppbase = int_hash_iter_get_value(iter, NULL);
			ab_tree_unload_base(*ppbase);
			free(*ppbase);
		}
		int_hash_iter_free(iter);
		int_hash_free(g_base_hash);
		g_base_hash = NULL;
	}
	while (pnode=single_list_get_from_head(&g_snode_list)) {
		free(pnode);
	}
	while (pnode=single_list_get_from_head(&g_abnode_list)) {
		free(pnode);
	}
	if (NULL != g_file_allocator) {
		lib_buffer_free(g_file_allocator);
		g_file_allocator = NULL;
	}
	return 0;
}

void ab_tree_free()
{
	pthread_mutex_destroy(&g_base_lock);
	pthread_mutex_destroy(&g_list_lock);
	single_list_free(&g_abnode_list);
	single_list_free(&g_snode_list);
}

static BOOL ab_tree_cache_node(AB_BASE *pbase, AB_NODE *pabnode)
{
	int tmp_id;
	void *ptmp_value;
	INT_HASH_ITER *iter;
	INT_HASH_TABLE *phash;
	
	if (NULL == pbase->phash) {
		pbase->phash = int_hash_init(
			HGROWING_SIZE, sizeof(AB_NODE*), NULL);
		if (NULL == pbase->phash) {
			return FALSE;
		}
	}
	if (1 != int_hash_add(pbase->phash, pabnode->minid, &pabnode)) {
		phash = int_hash_init(pbase->phash->capacity
			+ HGROWING_SIZE, sizeof(AB_NODE*), NULL);
		if (NULL == phash) {
			return FALSE;
		}
		iter = int_hash_iter_init(pbase->phash);
		for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ptmp_value = int_hash_iter_get_value(iter, &tmp_id);
			int_hash_add(phash, tmp_id, ptmp_value);
		}
		int_hash_iter_free(iter);
		int_hash_free(pbase->phash);
		pbase->phash = phash;
		int_hash_add(pbase->phash, pabnode->minid, &pabnode);
	}
	return TRUE;
}

static BOOL ab_tree_load_user(AB_NODE *pabnode,
	int address_type, MEM_FILE *pfile_user, AB_BASE *pbase)
{
	int i;
	int user_id;
	int temp_len;
	char temp_buff[1024];
	
	switch (address_type) {
	case ADDRESS_TYPE_ROOM:
		pabnode->node_type = NODE_TYPE_ROOM;
		break;
	case ADDRESS_TYPE_EQUIPMENT:
		pabnode->node_type = NODE_TYPE_EQUIPMENT;
		break;
	default:
		pabnode->node_type = NODE_TYPE_PERSOPN;
		break;
	}
	mem_file_read(pfile_user, &user_id, sizeof(int));
	pabnode->id = user_id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, user_id);
	((SIMPLE_TREE_NODE*)pabnode)->pdata = int_hash_query(
							pbase->phash, pabnode->minid);
	if (NULL == ((SIMPLE_TREE_NODE*)pabnode)->pdata) {
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
	}
	for (i=0; i<10; i++) {
		/* username,  real_name, title, memo, cell, tell,
			nickname, homeaddress, create_day, maildir */
		mem_file_read(pfile_user, &temp_len, sizeof(int));
		mem_file_read(pfile_user, temp_buff, temp_len);
		temp_buff[temp_len] = '\0';
		if (FALSE == utf8_check(temp_buff)) {
			utf8_filter(temp_buff);
			temp_len = strlen(temp_buff);
		}
		mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_write(&pabnode->f_info, temp_buff, temp_len);
	}
	return TRUE;
}

static BOOL ab_tree_load_mlist(AB_NODE *pabnode,
	MEM_FILE *pfile_user, AB_BASE *pbase)
{
	int user_id;
	int temp_len;
	int list_type;
	int list_privilege;
	char temp_buff[1024];
	
	pabnode->node_type = NODE_TYPE_MLIST;
	mem_file_read(pfile_user, &user_id, sizeof(int));
	pabnode->id = user_id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_ADDRESS, user_id);
	((SIMPLE_TREE_NODE*)pabnode)->pdata = int_hash_query(
							pbase->phash, pabnode->minid);
	if (NULL == ((SIMPLE_TREE_NODE*)pabnode)->pdata) {
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
	}
	/* listname */
	mem_file_read(pfile_user, &temp_len, sizeof(int));
	mem_file_read(pfile_user, temp_buff, temp_len);
	temp_buff[temp_len] = '\0';
	if (FALSE == utf8_check(temp_buff)) {
		utf8_filter(temp_buff);
		temp_len = strlen(temp_buff);
	}
	mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
	mem_file_write(&pabnode->f_info, temp_buff, temp_len);
	/* create_day */
	mem_file_read(pfile_user, &temp_len, sizeof(int));
	mem_file_read(pfile_user, temp_buff, temp_len);
	mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
	mem_file_write(&pabnode->f_info, temp_buff, temp_len);
	/* list_type */
	mem_file_read(pfile_user, &list_type, sizeof(int));
	mem_file_write(&pabnode->f_info, &list_type, sizeof(int));
	/* list_privilege */
	mem_file_read(pfile_user, &list_privilege, sizeof(int));
	mem_file_write(&pabnode->f_info, &list_privilege, sizeof(int));
	if (MLIST_TYPE_GROUP == list_type || MLIST_TYPE_CLASS == list_type) {
		/* title */
		mem_file_read(pfile_user, &temp_len, sizeof(int));
		mem_file_read(pfile_user, temp_buff, temp_len);
		mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_write(&pabnode->f_info, temp_buff, temp_len);
	}
	return TRUE;
}

static int ab_tree_cmpstring(const void *p1, const void *p2)
{
	return strcasecmp(((SORT_ITEM*)p1)->string, ((SORT_ITEM*)p2)->string);
}

static BOOL ab_tree_load_class(
	int class_id, SIMPLE_TREE *ptree,
	SIMPLE_TREE_NODE *pnode, AB_BASE *pbase)
{
	int i;
	int rows;
	int child_id;
	int temp_len;
	int user_type;
	AB_NODE *pabnode;
	SORT_ITEM *parray;
	MEM_FILE file_user;
	char temp_buff[1024];
	MEM_FILE file_subclass;
	SIMPLE_TREE_NODE *pclass;
	
	mem_file_init(&file_subclass, g_file_allocator);
	if (FALSE == system_services_get_sub_classes(class_id, &file_subclass)) {
		mem_file_free(&file_subclass);
		return FALSE;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&file_subclass, &child_id, sizeof(int))) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			mem_file_free(&file_subclass);
			return FALSE;
		}
		pabnode->node_type = NODE_TYPE_CLASS;
		pabnode->id = child_id;
		pabnode->minid = ab_tree_make_minid(MINID_TYPE_CLASS, child_id);
		if (NULL == int_hash_query(pbase->phash, pabnode->minid)) {
			if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
				mem_file_free(&file_subclass);
				return FALSE;
			}
		}
		/* classname */
		mem_file_read(&file_subclass, &temp_len, sizeof(int));
		mem_file_read(&file_subclass, temp_buff, temp_len);
		temp_buff[temp_len] = '\0';
		if (FALSE == utf8_check(temp_buff)) {
			utf8_filter(temp_buff);
			temp_len = strlen(temp_buff);
		}
		mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_write(&pabnode->f_info, temp_buff, temp_len);
		pclass = (SIMPLE_TREE_NODE*)pabnode;
		simple_tree_add_child(ptree, pnode,
			pclass, SIMPLE_TREE_ADD_LAST);
		if (FALSE == ab_tree_load_class(
			child_id, ptree, pclass, pbase)) {
			mem_file_free(&file_subclass);
			return FALSE;
		}
	}
	mem_file_free(&file_subclass);
	mem_file_init(&file_user, g_file_allocator);
	rows = system_services_get_class_users(class_id, &file_user);
	if (-1 == rows) {
		mem_file_free(&file_user);
		return FALSE;
	} else if (0 == rows) {
		mem_file_free(&file_user);
		return TRUE;
	}
	parray = malloc(sizeof(SORT_ITEM)*rows);
	if (NULL == parray) {
		mem_file_free(&file_user);
		return FALSE;
	}
	i = 0;
	while (MEM_END_OF_FILE != mem_file_read(
		&file_user, &user_type, sizeof(int))) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			goto LOAD_FAIL;
		}
		if (ADDRESS_TYPE_MLIST == user_type) {
			if (FALSE == ab_tree_load_mlist(
				pabnode, &file_user, pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		} else {
			if (FALSE == ab_tree_load_user(pabnode,
				user_type, &file_user, pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		}
		parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
		ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			ab_tree_put_abnode(pabnode);
			goto LOAD_FAIL;
		}
		i ++;
	}
	mem_file_free(&file_user);
	qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
	for (i=0; i<rows; i++) {
		simple_tree_add_child(ptree, pnode,
			parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		free(parray[i].string);
	}
	free(parray);
	return TRUE;
LOAD_FAIL:
	for (i-=1; i>=0; i--) {
		free(parray[i].string);
		ab_tree_put_abnode((AB_NODE*)parray[i].pnode);
	}
	free(parray);
	mem_file_free(&file_user);
	return FALSE;
}

static BOOL ab_tree_load_tree(int domain_id,
	SIMPLE_TREE *ptree, AB_BASE *pbase)
{
	int i;
	int rows;
	int temp_len;
	int group_id;
	int class_id;
	int user_type;
	AB_NODE *pabnode;
	SORT_ITEM *parray;
	char address[1024];
	MEM_FILE file_user;
	MEM_FILE file_group;
	MEM_FILE file_class;
	char temp_buff[1024];
	char group_name[256];
	char domain_name[256];
	SIMPLE_TREE_NODE *pgroup;
	SIMPLE_TREE_NODE *pclass;
	SIMPLE_TREE_NODE *pdomain;
	
	
	if (FALSE == system_services_get_domain_info(domain_id,
		domain_name, temp_buff, address)) {
		return FALSE;
	}
	pabnode = ab_tree_get_abnode();
	if (NULL == pabnode) {
		return FALSE;
	}
	pabnode->node_type = NODE_TYPE_DOMAIN;
	pabnode->id = domain_id;
	pabnode->minid = ab_tree_make_minid(MINID_TYPE_DOMAIN, domain_id);
	if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
		return FALSE;
	}
	/* domainname */
	if (FALSE == utf8_check(domain_name)) {
		utf8_filter(domain_name);
	}
	temp_len = strlen(domain_name);
	mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
	mem_file_write(&pabnode->f_info, domain_name, temp_len);
	/* domain title */
	if (FALSE == utf8_check(temp_buff)) {
		utf8_filter(temp_buff);
	}
	temp_len = strlen(temp_buff);
	mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
	mem_file_write(&pabnode->f_info, temp_buff, temp_len);
	/* address */
	if (FALSE == utf8_check(address)) {
		utf8_filter(address);
	}
	temp_len = strlen(address);
	mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
	mem_file_write(&pabnode->f_info, address, temp_len);
	pdomain = (SIMPLE_TREE_NODE*)pabnode;
	simple_tree_set_root(ptree, pdomain);
	mem_file_init(&file_group, g_file_allocator);
	if (FALSE == system_services_get_domain_groups(domain_id, &file_group)) {
		mem_file_free(&file_group);
		return FALSE;
	}
	while (MEM_END_OF_FILE != mem_file_read(
		&file_group, &group_id, sizeof(int))) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			mem_file_free(&file_group);
			return FALSE;
		}
		pabnode->node_type = NODE_TYPE_GROUP;
		pabnode->id = group_id;
		pabnode->minid = ab_tree_make_minid(MINID_TYPE_GROUP, group_id);
		if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
			return FALSE;
		}
		/* groupname */
		mem_file_read(&file_group, &temp_len, sizeof(int));	
		mem_file_read(&file_group, group_name, temp_len);
		group_name[temp_len] = '\0';
		if (FALSE == utf8_check(group_name)) {
			utf8_filter(group_name);
			temp_len = strlen(group_name);
		}
		mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_write(&pabnode->f_info, group_name, temp_len);
		/* group title */
		mem_file_read(&file_group, &temp_len, sizeof(int));
		mem_file_read(&file_group, temp_buff, temp_len);
		temp_buff[temp_len] = '\0';
		if (FALSE == utf8_check(temp_buff)) {
			utf8_filter(temp_buff);
			temp_len = strlen(temp_buff);
		}
		mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_write(&pabnode->f_info, temp_buff, temp_len);
		pgroup = (SIMPLE_TREE_NODE*)pabnode;
		simple_tree_add_child(ptree, pdomain, pgroup, SIMPLE_TREE_ADD_LAST);
		
		mem_file_init(&file_class, g_file_allocator);
		if (FALSE == system_services_get_group_classes(group_id, &file_class)) {
			mem_file_free(&file_class);
			mem_file_free(&file_group);
			return FALSE;
		}
		while (MEM_END_OF_FILE != mem_file_read(
			&file_class, &class_id, sizeof(int))) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				mem_file_free(&file_class);
				mem_file_free(&file_group);
				return FALSE;
			}
			pabnode->node_type = NODE_TYPE_CLASS;
			pabnode->id = class_id;
			pabnode->minid = ab_tree_make_minid(MINID_TYPE_CLASS, class_id);
			if (NULL == int_hash_query(pbase->phash, pabnode->minid)) {
				if (FALSE == ab_tree_cache_node(pbase, pabnode)) {
					ab_tree_put_abnode(pabnode);
					mem_file_free(&file_class);
					mem_file_free(&file_group);
					return FALSE;
				}
			}
			/* classname */
			mem_file_read(&file_class, &temp_len, sizeof(int));
			mem_file_read(&file_class, temp_buff, temp_len);
			temp_buff[temp_len] = '\0';
			if (FALSE == utf8_check(temp_buff)) {
				utf8_filter(temp_buff);
				temp_len = strlen(temp_buff);
			}
			mem_file_write(&pabnode->f_info, &temp_len, sizeof(int));
			mem_file_write(&pabnode->f_info, temp_buff, temp_len);
			pclass = (SIMPLE_TREE_NODE*)pabnode;
			simple_tree_add_child(ptree, pgroup,
				pclass, SIMPLE_TREE_ADD_LAST);
			if (FALSE == ab_tree_load_class(
				class_id, ptree, pclass, pbase)) {
				mem_file_free(&file_class);
				mem_file_free(&file_group);
				return FALSE;
			}
		}
		mem_file_free(&file_class);
		
		mem_file_init(&file_user, g_file_allocator);
		rows = system_services_get_group_users(group_id, &file_user);
		if (-1 == rows) {
			mem_file_free(&file_user);
			mem_file_free(&file_group);
			return FALSE;
		} else if (0 == rows) {
			mem_file_free(&file_user);
			continue;
		}
		parray = malloc(sizeof(SORT_ITEM)*rows);
		if (NULL == parray) {
			mem_file_free(&file_user);
			mem_file_free(&file_group);
			return FALSE;
		}
		i = 0;
		while (MEM_END_OF_FILE != mem_file_read(
			&file_user, &user_type, sizeof(int))) {
			pabnode = ab_tree_get_abnode();
			if (NULL == pabnode) {
				mem_file_free(&file_group);
				goto LOAD_FAIL;
			}
			if (ADDRESS_TYPE_MLIST == user_type) {
				if (FALSE == ab_tree_load_mlist(
					pabnode, &file_user, pbase)) {
					ab_tree_put_abnode(pabnode);
					mem_file_free(&file_group);
					goto LOAD_FAIL;
				}
			} else {
				if (FALSE == ab_tree_load_user(pabnode,
					user_type, &file_user, pbase)) {
					ab_tree_put_abnode(pabnode);
					mem_file_free(&file_group);
					goto LOAD_FAIL;
				}
			}
			parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
			ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
			parray[i].string = strdup(temp_buff);
			if (NULL == parray[i].string) {
				ab_tree_put_abnode(pabnode);
				mem_file_free(&file_group);
				goto LOAD_FAIL;
			}
			i ++;
		}
		mem_file_free(&file_user);
		
		qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
		for (i=0; i<rows; i++) {
			simple_tree_add_child(ptree, pgroup,
				parray[i].pnode, SIMPLE_TREE_ADD_LAST);
			free(parray[i].string);
		}
		free(parray);
	}
	mem_file_free(&file_group);
	
	mem_file_init(&file_user, g_file_allocator);
	rows = system_services_get_domain_users(domain_id, &file_user);
	if (-1 == rows) {
		mem_file_free(&file_user);
		return FALSE;
	} else if (0 == rows) {
		mem_file_free(&file_user);
		return TRUE;
	}
	parray = malloc(sizeof(SORT_ITEM)*rows);
	if (NULL == parray) {
		mem_file_free(&file_user);
		return FALSE;	
	}
	i = 0;
	while (MEM_END_OF_FILE != mem_file_read(
		&file_user, &user_type, sizeof(int))) {
		pabnode = ab_tree_get_abnode();
		if (NULL == pabnode) {
			goto LOAD_FAIL;
		}
		if (ADDRESS_TYPE_MLIST == user_type) {
			if (FALSE == ab_tree_load_mlist(
				pabnode, &file_user, pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		} else {
			if (FALSE == ab_tree_load_user(pabnode,
				user_type, &file_user, pbase)) {
				ab_tree_put_abnode(pabnode);
				goto LOAD_FAIL;
			}
		}
		parray[i].pnode = (SIMPLE_TREE_NODE*)pabnode;
		ab_tree_get_display_name(parray[i].pnode, 1252, temp_buff);
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			ab_tree_put_abnode(pabnode);
			goto LOAD_FAIL;
		}
		i ++;
	}
	mem_file_free(&file_user);
	
	qsort(parray, rows, sizeof(SORT_ITEM), ab_tree_cmpstring);
	for (i=0; i<rows; i++) {
		simple_tree_add_child(ptree, pdomain,
			parray[i].pnode, SIMPLE_TREE_ADD_LAST);
		free(parray[i].string);
	}
	free(parray);
	return TRUE;
LOAD_FAIL:
	for (i-=1; i>=0; i--) {
		free(parray[i].string);
		ab_tree_put_abnode((AB_NODE*)parray[i].pnode);
	}
	free(parray);
	mem_file_free(&file_user);
	return FALSE;
}

static void ab_tree_enum_nodes(SIMPLE_TREE_NODE *pnode, void *pparam)
{
	uint8_t node_type;
	SINGLE_LIST_NODE *psnode;
	
	node_type = ab_tree_get_node_type(pnode);
	if (node_type > 0x80) {
		return;
	}
	if (NULL != pnode->pdata) {
		return;	
	}
	psnode = ab_tree_get_snode();
	if (NULL == psnode) {
		return;
	}
	psnode->pdata = pnode;
	single_list_append_as_tail((SINGLE_LIST*)pparam, psnode);
}

static BOOL ab_tree_load_base(AB_BASE *pbase)
{
	int i, num;
	int domain_id;
	SORT_ITEM *parray;
	MEM_FILE temp_file;
	DOMAIN_NODE *pdomain;
	char temp_buff[1024];
	SIMPLE_TREE_NODE *proot;
	SINGLE_LIST_NODE *pnode;
	
	if (pbase->base_id > 0) {
		mem_file_init(&temp_file, g_file_allocator);
		if (FALSE == system_services_get_org_domains(pbase->base_id, &temp_file)) {
			mem_file_free(&temp_file);
			return FALSE;
		}
		while (MEM_END_OF_FILE != mem_file_read(
			&temp_file, &domain_id, sizeof(int))) {
			pdomain = (DOMAIN_NODE*)malloc(sizeof(DOMAIN_NODE));
			if (NULL == pdomain) {
				ab_tree_unload_base(pbase);
				mem_file_free(&temp_file);
				return FALSE;
			}
			pdomain->node.pdata = pdomain;
			pdomain->domain_id = domain_id;
			simple_tree_init(&pdomain->tree);
			if (FALSE == ab_tree_load_tree(
				domain_id, &pdomain->tree, pbase)) {
				ab_tree_destruct_tree(&pdomain->tree);
				free(pdomain);
				ab_tree_unload_base(pbase);
				mem_file_free(&temp_file);
				return FALSE;
			}
			single_list_append_as_tail(&pbase->list, &pdomain->node);
		}
		mem_file_free(&temp_file);
	} else {
		pdomain = (DOMAIN_NODE*)malloc(sizeof(DOMAIN_NODE));
		if (NULL == pdomain) {
			return FALSE;
		}
		pdomain->node.pdata = pdomain;
		domain_id = pbase->base_id * (-1);
		pdomain->domain_id = domain_id;
		simple_tree_init(&pdomain->tree);
		if (FALSE == ab_tree_load_tree(
			domain_id, &pdomain->tree, pbase)) {
			ab_tree_destruct_tree(&pdomain->tree);
			free(pdomain);
			ab_tree_unload_base(pbase);
			return FALSE;
		}
		single_list_append_as_tail(&pbase->list, &pdomain->node);
	}
	for (pnode=single_list_get_head(&pbase->list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->list, pnode)) {
		pdomain = (DOMAIN_NODE*)pnode->pdata;
		proot = simple_tree_get_root(&pdomain->tree);
		if (NULL == proot) {
			continue;
		}
		simple_tree_enum_from_node(proot,
			ab_tree_enum_nodes, &pbase->gal_list);
	}
	num = single_list_get_nodes_num(&pbase->gal_list);
	if (num <= 1) {
		return TRUE;
	}
	parray = malloc(sizeof(SORT_ITEM)*num);
	if (NULL == parray) {
		return TRUE;
	}
	i = 0;
	for (pnode=single_list_get_head(&pbase->gal_list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->gal_list, pnode)) {
		ab_tree_get_display_name(pnode->pdata, 1252, temp_buff);
		parray[i].pnode = pnode->pdata;
		parray[i].string = strdup(temp_buff);
		if (NULL == parray[i].string) {
			for (i-=1; i>=0; i--) {
				free(parray[i].string);
			}
			free(parray);
			return TRUE;
		}
		i ++;
	}
	qsort(parray, num, sizeof(SORT_ITEM), ab_tree_cmpstring);
	i = 0;
	for (pnode=single_list_get_head(&pbase->gal_list); NULL!=pnode;
		pnode=single_list_get_after(&pbase->gal_list, pnode)) {
		pnode->pdata = parray[i].pnode;
		free(parray[i].string);
		i ++;
	}
	free(parray);
	return TRUE;
}

AB_BASE* ab_tree_get_base(int base_id)
{
	int count;
	AB_BASE *pbase;
	AB_BASE **ppbase;
	SINGLE_LIST_NODE *pnode;
	
	count = 0;
RETRY_LOAD_BASE:
	pthread_mutex_lock(&g_base_lock);
	ppbase = int_hash_query(g_base_hash, base_id);
	if (NULL == ppbase) {
		pbase = (AB_BASE*)malloc(sizeof(AB_BASE));
		if (NULL == pbase) {
			pthread_mutex_unlock(&g_base_lock);
			return NULL;
		}
		if (1 != int_hash_add(g_base_hash, base_id, &pbase)) {
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
			return NULL;
		}
		pbase->base_id = base_id;
		pbase->load_time = 0;
		pbase->reference = 0;
		pbase->status = BASE_STATUS_CONSTRUCTING;
		single_list_init(&pbase->list);
		single_list_init(&pbase->gal_list);
		pbase->phash = NULL;
		pthread_mutex_unlock(&g_base_lock);
		if (FALSE == ab_tree_load_base(pbase)) {
			pthread_mutex_lock(&g_base_lock);
			int_hash_remove(g_base_hash, base_id);
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
			return NULL;
		}
		time(&pbase->load_time);
		pthread_mutex_lock(&g_base_lock);
		pbase->status = BASE_STATUS_LIVING;
	} else {
		if (BASE_STATUS_LIVING != (*ppbase)->status) {
			pthread_mutex_unlock(&g_base_lock);
			count ++;
			if (count > 60) {
				return NULL;
			}
			sleep(1);
			goto RETRY_LOAD_BASE;
		}
		pbase = *ppbase;
	}
	pbase->reference ++;
	pthread_mutex_unlock(&g_base_lock);
	return pbase;
}

void ab_tree_put_base(AB_BASE *pbase)
{
	pthread_mutex_lock(&g_base_lock);
	pbase->reference --;
	pthread_mutex_unlock(&g_base_lock);
}

static void *scan_work_func(void *param)
{
	AB_BASE *pbase;
	AB_BASE **ppbase;
	INT_HASH_ITER *iter;
	SINGLE_LIST_NODE *pnode;
	
	while (FALSE == g_notify_stop) {
		pbase = NULL;
		pthread_mutex_lock(&g_base_lock);
		iter = int_hash_iter_init(g_base_hash);
		for (int_hash_iter_begin(iter);
			FALSE == int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ppbase = int_hash_iter_get_value(iter, NULL);
			if (BASE_STATUS_LIVING != (*ppbase)->status ||
				0 != (*ppbase)->reference || time(NULL) -
				(*ppbase)->load_time < g_cache_interval) {
				continue;
			}
			pbase = *ppbase;
			pbase->status = BASE_STATUS_CONSTRUCTING;
			break;
		}
		int_hash_iter_free(iter);
		pthread_mutex_unlock(&g_base_lock);
		if (NULL == pbase) {
			sleep(1);
			continue;
		}
		while (pnode = single_list_get_from_head(&pbase->list)) {
			ab_tree_destruct_tree(&((DOMAIN_NODE*)pnode->pdata)->tree);
			free(pnode->pdata);
		}
		while (pnode = single_list_get_from_head(&pbase->gal_list)) {
			ab_tree_put_snode(pnode);
		}
		if (NULL != pbase->phash) {
			int_hash_free(pbase->phash);
			pbase->phash = NULL;
		}
		if (FALSE == ab_tree_load_base(pbase)) {
			pthread_mutex_lock(&g_base_lock);
			int_hash_remove(g_base_hash, pbase->base_id);
			pthread_mutex_unlock(&g_base_lock);
			free(pbase);
		} else {
			pthread_mutex_lock(&g_base_lock);
			time(&pbase->load_time);
			pbase->status = BASE_STATUS_LIVING;
			pthread_mutex_unlock(&g_base_lock);
		}
	}
}

static int ab_tree_node_to_rpath(SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	int len;
	AB_NODE *pabnode;
	char temp_buff[1024];
	
	pabnode = (AB_NODE*)pnode;
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
		len = sprintf(temp_buff, "d%d", pabnode->id);
		break;
	case NODE_TYPE_GROUP:
		len = sprintf(temp_buff, "g%d", pabnode->id);
		break;
	case NODE_TYPE_CLASS:
		len = sprintf(temp_buff, "c%d", pabnode->id);
		break;
	case NODE_TYPE_PERSOPN:
		len = sprintf(temp_buff, "p%d", pabnode->id);
		break;
	case NODE_TYPE_MLIST:
		len = sprintf(temp_buff, "l%d", pabnode->id);
		break;
	case NODE_TYPE_ROOM:
		len = sprintf(temp_buff, "r%d", pabnode->id);
		break;
	case NODE_TYPE_EQUIPMENT:
		len = sprintf(temp_buff, "e%d", pabnode->id);
		break;
	default:
		return 0;
	}
	if (len >= length) {
		return 0;
	}
	memcpy(pbuff, temp_buff, len + 1);
	return len;
}

static BOOL ab_tree_node_to_path(SIMPLE_TREE_NODE *pnode,
	char *pbuff, int length)
{
	int len;
	int offset;
	BOOL b_remote;
	AB_BASE *pbase;
	SIMPLE_TREE_NODE **ppnode;
	
	
	b_remote = FALSE;
	if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*((AB_NODE*)pnode)->id);
		if (NULL == pbase) {
			return FALSE;
		}
		ppnode = int_hash_query(pbase->phash, ((AB_NODE*)pnode)->minid);
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return FALSE;
		}
		pnode = *ppnode;
	}
	
	offset = 0;
	do {
		len = ab_tree_node_to_rpath(pnode,
			pbuff + offset, length - offset);
		if (0 == len) {
			return FALSE;
		}
		offset += len;
	} while (pnode = simple_tree_node_get_parent(pnode));
	
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
	return TRUE;
}


static void ab_tree_md5_path(const char *path, uint64_t *pdgt)
{
	int i;
	uint64_t b;
	MD5_CTX ctx;
	uint8_t dgt_buff[MD5_DIGEST_LENGTH];
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, path, strlen(path));
	MD5_Final(dgt_buff, &ctx);
	*pdgt = 0;
	for (i=0; i<16; i+=2) {
		b = dgt_buff[i];
		*pdgt |= (b << 4*i);
	}
}

static void ab_tree_enum_guid(SIMPLE_TREE_NODE *pnode, void *pparam)
{
	uint64_t dgt;
	AB_NODE *pabnode;
	GUID_ENUM *penum;
	char temp_path[512];
	
	pabnode = (AB_NODE*)pnode;
	penum = (GUID_ENUM*)pparam;
	if (NULL != penum->pabnode) {
		return;
	}
	if (pabnode->node_type != penum->node_type) {
		return;
	}
	if (pabnode->id != penum->item_id) {
		return;
	}
	ab_tree_node_to_path(pnode, temp_path, sizeof(temp_path));
	ab_tree_md5_path(temp_path, &dgt);
	if (dgt == penum->dgt) {
		penum->pabnode = pabnode;
	}
}

SIMPLE_TREE_NODE* ab_tree_guid_to_node(
	AB_BASE *pbase, GUID guid)
{
	int domain_id;
	int node_type;
	GUID_ENUM tmp_enum;
	DOMAIN_NODE *pdomain;
	SIMPLE_TREE_NODE *ptnode;
	SINGLE_LIST_NODE *psnode;
	
	domain_id = guid.time_low & 0xFFFFFF;
	for (psnode=single_list_get_head(&pbase->list); NULL!=psnode;
		psnode=single_list_get_after(&pbase->list, psnode)) {
		pdomain = (DOMAIN_NODE*)psnode->pdata;
		if (pdomain->domain_id == domain_id) {
			break;
		}
	}
	if (NULL == psnode) {
		return NULL;
	}
	tmp_enum.node_type = (guid.time_low & 0xFF000000) >> 24;
	tmp_enum.item_id = (((int)guid.time_hi_and_version) << 16)
											| guid.time_mid;
	tmp_enum.dgt = guid.node[0] |
		(((uint64_t)guid.node[1]) << 8) |
		(((uint64_t)guid.node[2]) << 16) |
		(((uint64_t)guid.node[3]) << 24) |
		(((uint64_t)guid.node[4]) << 32) |
		(((uint64_t)guid.node[5]) << 40) |
		(((uint64_t)guid.clock_seq[0]) << 48) |
		(((uint64_t)guid.clock_seq[1]) << 56);
	
	tmp_enum.pabnode = NULL;
	ptnode = simple_tree_get_root(&pdomain->tree);
	if (NULL == ptnode) {
		return NULL;
	}
	simple_tree_enum_from_node(ptnode, ab_tree_enum_guid, &tmp_enum);
	return (SIMPLE_TREE_NODE*)tmp_enum.pabnode;
}

static void ab_tree_node_to_guid(SIMPLE_TREE_NODE *pnode, GUID *pguid)
{
	uint64_t dgt;
	uint32_t tmp_id;
	AB_NODE *pabnode;
	char temp_path[512];
	SIMPLE_TREE_NODE *proot;
	SIMPLE_TREE_NODE *pnode1;
	
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type < 0x80 && NULL != pnode->pdata) {
		return ab_tree_node_to_guid(pnode->pdata, pguid);	
	}
	memset(pguid, 0, sizeof(GUID));
	pguid->time_low = pabnode->node_type << 24;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		pguid->time_low |= pabnode->id;
		tmp_id = ab_tree_get_minid_value(pabnode->minid);
		pguid->time_hi_and_version = (tmp_id & 0xFFFF0000) >> 16;
		pguid->time_mid = tmp_id & 0xFFFF;
	} else {
		proot = pnode;
		while (pnode1 = simple_tree_node_get_parent(proot)) {
			proot = pnode1;
		}
		pguid->time_low |= ((AB_NODE*)proot)->id;
		pguid->time_hi_and_version = (pabnode->id & 0xFFFF0000) >> 16;
		pguid->time_mid = pabnode->id & 0xFFFF;
	}
	memset(temp_path, 0, sizeof(temp_path));
	ab_tree_node_to_path((SIMPLE_TREE_NODE*)
		pabnode, temp_path, sizeof(temp_path));
	ab_tree_md5_path(temp_path, &dgt);
	pguid->node[0] = dgt & 0xFF;
	pguid->node[1] = (dgt & 0xFF00) >> 8;
	pguid->node[2] = (dgt & 0xFF0000) >> 16;
	pguid->node[3] = (dgt & 0xFF000000) >> 24;
	pguid->node[4] = (dgt & 0xFF00000000ULL) >> 32;
	pguid->node[5] = (dgt & 0xFF0000000000ULL) >> 40;
	pguid->clock_seq[0] = (dgt & 0xFF000000000000ULL) >> 48;
	pguid->clock_seq[1] = (dgt & 0xFF00000000000000ULL) >> 56;
}

BOOL ab_tree_node_to_dn(SIMPLE_TREE_NODE *pnode, char *pbuff, int length)
{
	int id;
	GUID guid;
	int temp_len;
	char *ptoken;
	int domain_id;
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	char username[256];
	char hex_string[32];
	char hex_string1[32];
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			return FALSE;
		}
		ppnode = int_hash_query(pbase->phash, pabnode->minid);
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return FALSE;
		}
		pabnode = (AB_NODE*)*ppnode;
		pnode = *ppnode;
	}
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
	case NODE_TYPE_GROUP:
	case NODE_TYPE_CLASS:
		ab_tree_node_to_guid(pnode, &guid);
		snprintf(pbuff, 128,
			"/guid=%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
			guid.time_low, guid.time_mid,
			guid.time_hi_and_version,
			guid.clock_seq[0],
			guid.clock_seq[1],
			guid.node[0], guid.node[1],
			guid.node[2], guid.node[3],
			guid.node[4], guid.node[5]);
		break;
	case NODE_TYPE_PERSOPN:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		id = pabnode->id;
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username);
		ptoken = strchr(username, '@');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		while (pnode=simple_tree_node_get_parent(pnode)) {
			pabnode = (AB_NODE*)pnode;
		}
		if (pabnode->node_type != NODE_TYPE_DOMAIN) {
			if (TRUE == b_remote) {
				ab_tree_put_base(pbase);
			}
			return FALSE;
		}
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
				g_org_name, hex_string1, hex_string, username);
		upper_string(pbuff);
		break;
	case NODE_TYPE_MLIST:
		id = pabnode->id;
		mem_file_seek(&pabnode->f_info,
			MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		mem_file_read(&pabnode->f_info, &temp_len, sizeof(int));
		mem_file_read(&pabnode->f_info, username, temp_len);
		username[temp_len] = '\0';
		ptoken = strchr(username, '@');
		if (NULL != ptoken) {
			*ptoken = '\0';
		}
		while (pnode=simple_tree_node_get_parent(pnode)) {
			pabnode = (AB_NODE*)pnode;
		}
		if (pabnode->node_type != NODE_TYPE_DOMAIN) {
			if (TRUE == b_remote) {
				ab_tree_put_base(pbase);
			}
			return FALSE;
		}
		domain_id = pabnode->id;
		encode_hex_int(id, hex_string);
		encode_hex_int(domain_id, hex_string1);
		sprintf(pbuff, "/o=%s/ou=Exchange Administrative Group"
				" (FYDIBOHF23SPDLT)/cn=Recipients/cn=%s%s-%s",
				g_org_name, hex_string1, hex_string, username);
		upper_string(pbuff);
		break;
	default:
		if (TRUE == b_remote) {
			ab_tree_put_base(pbase);
		}
		return FALSE;
	}
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
	return TRUE;	
}

uint32_t ab_tree_get_node_minid(SIMPLE_TREE_NODE *pnode)
{
	return ((AB_NODE*)pnode)->minid;
}

uint8_t ab_tree_get_node_type(SIMPLE_TREE_NODE *pnode)
{
	AB_BASE *pbase;
	AB_NODE *pabnode;
	uint8_t node_type;
	SIMPLE_TREE_NODE **ppnode;
	
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			return NODE_TYPE_REMOTE;
		}
		ppnode = int_hash_query(pbase->phash, pabnode->minid);
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			return NODE_TYPE_REMOTE;
		}
		node_type = ((AB_NODE*)*ppnode)->node_type;
		ab_tree_put_base(pbase);
		return node_type;
	}
	return pabnode->node_type;
}

static void ab_tree_get_display_name(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, char *str_dname)
{
	char *ptoken;
	int temp_len;
	int list_type;
	char title[1024];
	AB_NODE *pabnode;
	MEM_FILE fake_file;
	char lang_string[256];
	
	pabnode = (AB_NODE*)pnode;
	str_dname[0] = '\0';
	memcpy(&fake_file, &pabnode->f_info, sizeof(MEM_FILE));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	switch (pabnode->node_type) {
	case NODE_TYPE_DOMAIN:
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_read(&fake_file, str_dname, temp_len);
		str_dname[temp_len] = '\0';
		break;
	case NODE_TYPE_GROUP:
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_read(&fake_file, str_dname, temp_len);
		str_dname[temp_len] = '\0';
		break;
	case NODE_TYPE_CLASS:
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_read(&fake_file, str_dname, temp_len);
		str_dname[temp_len] = '\0';
		break;
	case NODE_TYPE_PERSOPN:
	case NODE_TYPE_ROOM:
	case NODE_TYPE_EQUIPMENT:
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_read(&fake_file, str_dname, temp_len);
		str_dname[temp_len] = '\0';
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		if (0 != temp_len) {
			mem_file_read(&fake_file, str_dname, temp_len);
			str_dname[temp_len] = '\0';
		} else {
			ptoken = strchr(str_dname, '@');
			if (NULL != ptoken) {
				*ptoken = '\0';
			}
		}
		break;
	case NODE_TYPE_MLIST:
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
		mem_file_read(&fake_file, &list_type, sizeof(int));
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			sizeof(int), MEM_FILE_SEEK_CUR);
		switch (list_type) {
		case MLIST_TYPE_NORMAL:
			if (FALSE == system_services_get_lang(codepage, "mlist0", str_dname, 256)) {
				strcpy(str_dname, "custom address list");
			}
			break;
		case MLIST_TYPE_GROUP:
			mem_file_read(&fake_file, &temp_len, sizeof(int));
			mem_file_read(&fake_file, title, temp_len);
			title[temp_len] = '\0';
			if (FALSE == system_services_get_lang(codepage, "mlist1", lang_string, 256)) {
				strcpy(lang_string, "all users in department of %s");
			}
			snprintf(str_dname, 256, lang_string, title);
			break;
		case MLIST_TYPE_DOMAIN:
			if (FALSE == system_services_get_lang(codepage, "mlist2", str_dname, 256)) {
				strcpy(str_dname, "all users in domain");
			}
			break;
		case MLIST_TYPE_CLASS:
			mem_file_read(&fake_file, &temp_len, sizeof(int));
			mem_file_read(&fake_file, title, temp_len);
			title[temp_len] = '\0';
			if (FALSE == system_services_get_lang(codepage, "mlist3", lang_string, 256)) {
				strcpy(lang_string, "all users in group of %s");
			}
			snprintf(str_dname, 256, lang_string, title);
			break;
		default:
			strcpy(str_dname, "unkown address list");
		}
		break;
	}
}

static void ab_tree_get_user_info(
	SIMPLE_TREE_NODE *pnode, int type, char *value)
{
	int i;
	int temp_len;
	AB_NODE *pabnode;
	MEM_FILE fake_file;
	
	value[0] = '\0';
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type != NODE_TYPE_PERSOPN &&
		pabnode->node_type != NODE_TYPE_ROOM &&
		pabnode->node_type != NODE_TYPE_EQUIPMENT &&
		pabnode->node_type != NODE_TYPE_REMOTE) {
		return;
	}
	memcpy(&fake_file, &pabnode->f_info, sizeof(MEM_FILE));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	for (i=0; i<10; i++) {
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		if (type == i) {
			mem_file_read(&fake_file, value, temp_len);
			value[temp_len] = '\0';
			return;
		}	
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
						temp_len, MEM_FILE_SEEK_CUR);
	}
}

static void ab_tree_get_mlist_info(SIMPLE_TREE_NODE *pnode,
	char *mail_address, char *create_day, int *plist_privilege)
{
	int temp_len;
	int list_type;
	AB_NODE *pabnode;
	MEM_FILE fake_file;
	
	pabnode = (AB_NODE*)pnode;
	if (pabnode->node_type != NODE_TYPE_MLIST &&
		pabnode->node_type != NODE_TYPE_REMOTE) {
		mail_address[0] = '\0';
		*plist_privilege = 0;
		return;
	}
	memcpy(&fake_file, &pabnode->f_info, sizeof(MEM_FILE));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	if (NULL == mail_address) {
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
	} else {
		mem_file_read(&fake_file, mail_address, temp_len);
		mail_address[temp_len] = '\0';
	}
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	if (NULL == create_day) {
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
			temp_len, MEM_FILE_SEEK_CUR);
	} else {
		mem_file_read(&fake_file, create_day, temp_len);
		create_day[temp_len] = '\0';
	}
	if (NULL != plist_privilege) {
		mem_file_read(&fake_file, &list_type, sizeof(int));
		mem_file_read(&fake_file, plist_privilege, sizeof(int));
	}	
}

static void ab_tree_get_mlist_title(uint32_t codepage, char *str_title)
{
	if (FALSE == system_services_get_lang(codepage, "mlist", str_title, 256)) {
		strcpy(str_title, "Address List");
	}
}

static void ab_tree_get_server_dn(
	SIMPLE_TREE_NODE *pnode, char *dn, int length)
{
	char *ptoken;
	char username[256];
	char hex_string[32];
	
	if (((AB_NODE*)pnode)->node_type < 0x80) {
		memset(username, 0, sizeof(username));
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, username);
		ptoken = strchr(username, '@');
		lower_string(username);
		if (NULL != ptoken) {
			ptoken ++;
		} else {
			ptoken = username;
		}
		if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
			encode_hex_int(ab_tree_get_minid_value(
				((AB_NODE*)pnode)->minid), hex_string);
		} else {
			encode_hex_int(((AB_NODE*)pnode)->id, hex_string);
		}
		snprintf(dn, length, "/o=%s/ou=Exchange Administrative "
			"Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers"
			"/cn=%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x"
			"-%02x%02x%s@%s", g_org_name, username[0], username[1],
			username[2], username[3], username[4], username[5],
			username[6], username[7], username[8], username[9],
			username[10], username[11], hex_string, ptoken);
		upper_string(dn);
	}
}

static void ab_tree_get_company_info(SIMPLE_TREE_NODE *pnode,
	char *str_name, char *str_address)
{
	int temp_len;
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	MEM_FILE fake_file;
	char temp_buff[1024];
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	pabnode = (AB_NODE*)pnode;
	if (NODE_TYPE_REMOTE == pabnode->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*pabnode->id);
		if (NULL == pbase) {
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		ppnode = int_hash_query(pbase->phash, pabnode->minid);
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			str_name[0] = '\0';
			str_address[0] = '\0';
			return;
		}
		pnode = *ppnode;
		pabnode = (AB_NODE*)*ppnode;
	}
	while (pnode=simple_tree_node_get_parent(pnode)) {
		pabnode = (AB_NODE*)pnode;
	}
	memcpy(&fake_file, &pabnode->f_info, sizeof(MEM_FILE));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
					temp_len, MEM_FILE_SEEK_CUR);
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	if (NULL == str_name) {
		mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
						temp_len, MEM_FILE_SEEK_CUR);
	} else {
		mem_file_read(&fake_file, str_name, temp_len);
		str_name[temp_len] = '\0';
	}
	if (NULL != str_address) {
		mem_file_read(&fake_file, &temp_len, sizeof(int));
		mem_file_read(&fake_file, str_address, temp_len);
		str_address[temp_len] = '\0';
	}
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
}

static void ab_tree_get_department_name(SIMPLE_TREE_NODE *pnode, char *str_name)
{
	int temp_len;
	BOOL b_remote;
	AB_BASE *pbase;
	AB_NODE *pabnode;
	MEM_FILE fake_file;
	char temp_buff[1024];
	SIMPLE_TREE_NODE **ppnode;
	
	b_remote = FALSE;
	if (NODE_TYPE_REMOTE == ((AB_NODE*)pnode)->node_type) {
		b_remote = TRUE;
		pbase = ab_tree_get_base((-1)*((AB_NODE*)pnode)->id);
		if (NULL == pbase) {
			str_name[0] = '\0';
			return;
		}
		ppnode = int_hash_query(pbase->phash, ((AB_NODE*)pnode)->minid);
		if (NULL == ppnode) {
			ab_tree_put_base(pbase);
			str_name[0] = '\0';
			return;
		}
		pnode = *ppnode;
	}
	do {
		pabnode = (AB_NODE*)pnode;
		if (NODE_TYPE_GROUP == pabnode->node_type) {
			break;
		}
	} while (pnode = simple_tree_node_get_parent(pnode));
	if (NULL == pnode) {
		str_name[0] = '\0';
		return;
	}
	memcpy(&fake_file, &pabnode->f_info, sizeof(MEM_FILE));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	mem_file_seek(&fake_file, MEM_FILE_READ_PTR,
				temp_len, MEM_FILE_SEEK_CUR);
	mem_file_read(&fake_file, &temp_len, sizeof(int));
	mem_file_read(&fake_file, str_name, temp_len);
	str_name[temp_len] = '\0';
	if (TRUE == b_remote) {
		ab_tree_put_base(pbase);
	}
}

BOOL ab_tree_has_child(SIMPLE_TREE_NODE *pnode)
{
	pnode = simple_tree_node_get_child(pnode);
	if (NULL == pnode) {
		return FALSE;
	}
	do {
		if (ab_tree_get_node_type(pnode) > 0x80) {
			return TRUE;
		}
	} while (pnode=simple_tree_node_get_slibling(pnode));
	return FALSE;
}

BOOL ab_tree_fetch_node_property(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, uint32_t proptag, void **ppvalue)
{
	int minid;
	void *pvalue;
	char dn[1280];
	GUID temp_guid;
	time_t tmp_time;
	struct tm tmp_tm;
	uint8_t node_type;
	EXT_PUSH ext_push;
	ADDRESSBOOK_ENTRYID ab_entryid;
	
	node_type = ab_tree_get_node_type(pnode);
	switch (proptag) {
	case PROP_TAG_ABPROVIDERID:
		*ppvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == *ppvalue) {
			return FALSE;
		}
		((BINARY*)*ppvalue)->cb = 16;
		((BINARY*)*ppvalue)->pb = common_util_get_muidecsab();
		return TRUE;
	case PROP_TAG_CONTAINERFLAGS:
		if (node_type < 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == ab_tree_has_child(pnode)) {
			*(uint32_t*)pvalue = AB_RECIPIENTS | AB_UNMODIFIABLE;
		} else {
			*(uint32_t*)pvalue = AB_RECIPIENTS |
				AB_SUBCONTAINERS | AB_UNMODIFIABLE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPTH:
		if (node_type < 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint32_t*)pvalue = simple_tree_node_get_depth(pnode) + 1;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKISMASTER:
		if (node_type < 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint8_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 0;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKHOMEMESSAGEDATABASE:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_server_dn(pnode, dn, sizeof(dn));
		strcat(dn, "/cn=Microsoft Private MDB");
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKOBJECTGUID:
		ab_tree_node_to_guid(pnode, &temp_guid);
		pvalue = common_util_guid_to_binary(temp_guid);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKCONTAINERID:
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type > 0x80) {
			*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
		} else {
			pnode = simple_tree_node_get_parent(pnode);
			if (NULL == pnode) {
				*(uint32_t*)pvalue = 0;
			} else {
				*(uint32_t*)pvalue = ab_tree_get_node_minid(pnode);
			}
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSTYPE:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = "EX";
		return TRUE;
	case PROP_TAG_EMAILADDRESS:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return FALSE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_OBJECTTYPE:
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type > 0x80) {
			*(uint32_t*)pvalue = OBJECT_ABCONTAINER;
		} else if (NODE_TYPE_MLIST == node_type) {
			*(uint32_t*)pvalue = OBJECT_DLIST;
		} else if (NODE_TYPE_FOLDER == node_type) {
			*(uint32_t*)pvalue = OBJECT_FOLDER;
		} else {
			*(uint32_t*)pvalue = OBJECT_USER;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DISPLAYTYPE:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (NODE_TYPE_MLIST == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_DISTLIST;
		} else {
			*(uint32_t*)pvalue = DISPLAY_TYPE_MAILUSER;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DISPLAYTYPEEX:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint32_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (NODE_TYPE_ROOM == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_ROOM;
		} else if (NODE_TYPE_EQUIPMENT == node_type) {
			*(uint32_t*)pvalue = DISPLAY_TYPE_EQUIPMENT;
		} else {
			*(uint32_t*)pvalue = DISPLAY_TYPE_MAILUSER
								| DTE_FLAG_ACL_CAPABLE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_MAPPINGSIGNATURE:
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = 16;
		((BINARY*)pvalue)->pb = (void*)g_guid_nspi;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_SENDRICHINFO:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(uint8_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		*(uint8_t*)pvalue = 1;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_PARENTENTRYID:
		pnode = simple_tree_node_get_parent(pnode);
		if (NULL == pnode) {
			*ppvalue = NULL;
			return TRUE;
		}
		return ab_tree_fetch_node_property(
			pnode, codepage, proptag, ppvalue);
	case PROP_TAG_ENTRYID:
	case PROP_TAG_RECORDKEY:
	case PROP_TAG_TEMPLATEID:
	case PROP_TAG_ORIGINALENTRYID:
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		ab_entryid.flags = 0;
		rop_util_get_provider_uid(PROVIDER_UID_ADDRESS_BOOK,
									ab_entryid.provider_uid);
		ab_entryid.version = 1;
		if (node_type > 0x80) {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_CONTAINER;
		} else if (NODE_TYPE_MLIST == node_type) {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_DLIST;
		} else {
			ab_entryid.type = ADDRESSBOOK_ENTRYID_TYPE_LOCAL_USER;
		}
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return FALSE;
		}
		ab_entryid.px500dn = dn;
		((BINARY*)pvalue)->pb = common_util_alloc(1280);
		if (NULL == ((BINARY*)pvalue)->pb) {
			return FALSE;
		}
		ext_buffer_push_init(&ext_push, ((BINARY*)pvalue)->pb, 1280, 0);
		if (EXT_ERR_SUCCESS != ext_buffer_push_addressbook_entryid(
			&ext_push, &ab_entryid)) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = ext_push.offset;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_SEARCHKEY:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (FALSE == ab_tree_node_to_dn(pnode, dn, 1024)) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = strlen(dn) + 4;
		((BINARY*)pvalue)->pb = common_util_alloc(((BINARY*)pvalue)->cb);
		if (NULL == ((BINARY*)pvalue)->pb) {
			return FALSE;
		}
		sprintf(((BINARY*)pvalue)->pb, "EX:%s", dn);
		upper_string(((BINARY*)pvalue)->pb);
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_INSTANCEKEY:
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		((BINARY*)pvalue)->cb = 4;
		((BINARY*)pvalue)->pb = common_util_alloc(4);
		if (NULL == ((BINARY*)pvalue)->pb) {
			return FALSE;
		}
		minid = ab_tree_get_node_minid(pnode);
		((BINARY*)pvalue)->pb[0] = minid & 0xFF;
		((BINARY*)pvalue)->pb[1] = (minid >> 8) & 0xFF;
		((BINARY*)pvalue)->pb[2] = (minid >> 16) & 0xFF;
		((BINARY*)pvalue)->pb[3] = (minid >> 24) & 0xFF;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_TRANSMITTABLEDISPLAYNAME:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
	case PROP_TAG_DISPLAYNAME:
	case PROP_TAG_ADDRESSBOOKDISPLAYNAMEPRINTABLE:
		ab_tree_get_display_name(pnode, codepage, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			return FALSE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_TITLE:
		if (NODE_TYPE_PERSOPN == node_type) {
			ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn);
			if ('\0' == dn[0]) {
				*ppvalue = NULL;
				return TRUE;
			}
			pvalue = common_util_dup(dn);
			if (NULL == pvalue) {
				return FALSE;
			}
		} else if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_title(codepage, dn);
			pvalue = common_util_dup(dn);
			if (NULL == pvalue) {
				return FALSE;
			}
		} else {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_NICKNAME:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_PRIMARYTELEPHONENUMBER:
	case PROP_TAG_BUSINESSTELEPHONENUMBER:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_MOBILETELEPHONENUMBER:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_HOMEADDRESSSTREET:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_COMMENT:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_COMPANYNAME:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_company_info(pnode, dn, NULL);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_DEPARTMENTNAME:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_department_name(pnode, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_OFFICELOCATION:
		if (node_type > 0x80) {
			*ppvalue = NULL;
			return TRUE;
		}
		ab_tree_get_company_info(pnode, NULL, dn);
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ACCOUNT:
	case PROP_TAG_SMTPADDRESS:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (NODE_TYPE_PERSOPN == node_type ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		} else {
			*ppvalue = NULL;
			return TRUE;
		}
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_dup(dn);
		if (NULL == pvalue) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_ADDRESSBOOKPROXYADDRESSES:
		if (NODE_TYPE_MLIST == node_type) {
			ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		} else if (NODE_TYPE_PERSOPN == node_type ||
			NODE_TYPE_EQUIPMENT == node_type ||
			NODE_TYPE_ROOM == node_type) {
			ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		} else {
			*ppvalue = NULL;
			return TRUE;
		}
		if ('\0' == dn[0]) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(STRING_ARRAY));
		if (NULL == pvalue) {
			return FALSE;
		}
		((STRING_ARRAY*)pvalue)->count = 1;
		((STRING_ARRAY*)pvalue)->ppstr =
			common_util_alloc(sizeof(char**));
		if (NULL == ((STRING_ARRAY*)pvalue)->ppstr) {
			return FALSE;
		}
		
		((STRING_ARRAY*)pvalue)->ppstr[0] =
			common_util_alloc(strlen(dn) + 6);
		if (NULL == ((STRING_ARRAY*)pvalue)->ppstr[0]) {
			return FALSE;
		}
		sprintf(((STRING_ARRAY*)pvalue)->ppstr[0], "SMTP:%s", dn);
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_CREATIONTIME:
		pvalue = common_util_alloc(sizeof(uint64_t));
		if (NULL == pvalue) {
			return FALSE;
		}
		if (node_type == NODE_TYPE_MLIST) {
			ab_tree_get_mlist_info(pnode, NULL, dn, NULL);
		} else if (node_type == NODE_TYPE_PERSOPN) {
			ab_tree_get_user_info(pnode, USER_CREATE_DAY, dn);
		} else {
			*ppvalue = NULL;
			return TRUE;
		}
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		strptime(dn, "%Y-%m-%d", &tmp_tm);
		tmp_time = mktime(&tmp_tm);
		*(uint64_t*)pvalue = ((uint64_t)tmp_time + EPOCH_DIFF)*10000000;
		*ppvalue = pvalue;
		return TRUE;
	case PROP_TAG_THUMBNAILPHOTO:
		if (node_type != NODE_TYPE_PERSOPN) {
			*ppvalue = NULL;
			return TRUE;
		}
		pvalue = common_util_alloc(sizeof(BINARY));
		if (NULL == pvalue) {
			return FALSE;
		}
		ab_tree_get_user_info(pnode, USER_STORE_PATH, dn);
		strcat(dn, "/config/portrait.jpg");
		if (FALSE == common_util_load_file(dn, pvalue)) {
			*ppvalue = NULL;
			return TRUE;
		}
		*ppvalue = pvalue;
		return TRUE;
	default:
		*ppvalue = NULL;
		return TRUE;
	}
}

BOOL ab_tree_fetch_node_properties(SIMPLE_TREE_NODE *pnode,
	const PROPTAG_ARRAY *pproptags, TPROPVAL_ARRAY *ppropvals)
{
	int i;
	void *pvalue;
	USER_INFO *pinfo;
	
	ppropvals->ppropval = common_util_alloc(
		sizeof(TAGGED_PROPVAL)*pproptags->count);
	if (NULL == ppropvals->ppropval) {
		return FALSE;
	}
	pinfo = zarafa_server_get_info();
	ppropvals->count = 0;
	for (i=0; i<pproptags->count; i++) {
		if (FALSE == ab_tree_fetch_node_property(pnode,
			pinfo->cpid, pproptags->pproptag[i], &pvalue)) {
			return FALSE;	
		}
		if (NULL == pvalue) {
			continue;
		}
		ppropvals->ppropval[ppropvals->count].proptag =
									pproptags->pproptag[i];
		ppropvals->ppropval[ppropvals->count].pvalue = pvalue;
		ppropvals->count ++;
	}
	return TRUE;
}

static BOOL ab_tree_resolve_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const char *pstr)
{
	char dn[1024];
	
	ab_tree_get_display_name(pnode, codepage, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	if (TRUE == ab_tree_node_to_dn(pnode, dn, sizeof(dn))
		&& 0 == strcasecmp(dn, pstr)) {
		return TRUE;
	}
	ab_tree_get_department_name(pnode, dn);
	if (NULL != strcasestr(dn, pstr)) {
		return TRUE;
	}
	switch(ab_tree_get_node_type(pnode)) {
	case NODE_TYPE_PERSOPN:
		ab_tree_get_user_info(pnode, USER_MAIL_ADDRESS, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_NICK_NAME, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_JOB_TITLE, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_COMMENT, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_MOBILE_TEL, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_BUSINESS_TEL, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		ab_tree_get_user_info(pnode, USER_HOME_ADDRESS, dn);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	case NODE_TYPE_MLIST:
		ab_tree_get_mlist_info(pnode, dn, NULL, NULL);
		if (NULL != strcasestr(dn, pstr)) {
			return TRUE;
		}
		break;
	}
	return FALSE;
}

BOOL ab_tree_resolvename(AB_BASE *pbase, uint32_t codepage,
	char *pstr, SINGLE_LIST *presult_list)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *prnode;
	SINGLE_LIST_NODE *psnode;
	SIMPLE_TREE_NODE *ptnode;
	
	ptnode = NULL;
	plist = &pbase->gal_list;
	single_list_init(presult_list);
	for (psnode=single_list_get_head(plist); NULL!=psnode;
		psnode=single_list_get_after(plist, psnode)) {
		if (FALSE == ab_tree_resolve_node(
			psnode->pdata, codepage, pstr)) {
			continue;
		}
		prnode = common_util_alloc(sizeof(SINGLE_LIST_NODE));
		if (NULL == prnode) {
			return FALSE;
		}
		prnode->pdata = psnode->pdata;
		single_list_append_as_tail(presult_list, prnode);
	}
	return TRUE;
}

static BOOL ab_tree_match_node(SIMPLE_TREE_NODE *pnode,
	uint32_t codepage, const RESTRICTION *pfilter)
{
	int i, len;
	char *ptoken;
	void *pvalue;
	uint8_t node_type;
	
	switch (pfilter->rt) {
	case RESTRICTION_TYPE_AND:
		for (i=0; i<((RESTRICTION_AND_OR*)pfilter->pres)->count; i++) {
			if (FALSE == ab_tree_match_node(pnode, codepage,
				&((RESTRICTION_AND_OR*)pfilter->pres)->pres[i])) {
				return FALSE;
			}
		}
		return TRUE;
	case RESTRICTION_TYPE_OR:
		for (i=0; i<((RESTRICTION_AND_OR*)pfilter->pres)->count; i++) {
			if (TRUE == ab_tree_match_node(pnode, codepage,
				&((RESTRICTION_AND_OR*)pfilter->pres)->pres[i])) {
				return TRUE;
			}
		}
		return FALSE;
	case RESTRICTION_TYPE_NOT:
		if (TRUE == ab_tree_match_node(pnode, codepage,
			&((RESTRICTION_NOT*)pfilter->pres)->res)) {
			return FALSE;
		}
		return TRUE;
	case RESTRICTION_TYPE_CONTENT:
		if (PROPVAL_TYPE_STRING != (((RESTRICTION_CONTENT*)
			pfilter->pres)->proptag & 0xFFFF) && PROPVAL_TYPE_WSTRING !=
			(((RESTRICTION_CONTENT*)pfilter->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if ((((RESTRICTION_CONTENT*)pfilter->pres)->proptag & 0xFFFF)
			!= (((RESTRICTION_CONTENT*)pfilter->pres)->propval.proptag
			& 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == ab_tree_fetch_node_property(
			pnode, codepage, ((RESTRICTION_CONTENT*)
			pfilter->pres)->proptag, &pvalue) ||
			NULL == pvalue) {
			return FALSE;	
		}
		switch (((RESTRICTION_CONTENT*)
			pfilter->pres)->fuzzy_level & 0xFFFF) {
		case FUZZY_LEVEL_FULLSTRING:
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (0 == strcasecmp(((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strcmp(((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, pvalue)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		case FUZZY_LEVEL_SUBSTRING:
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE|FUZZY_LEVEL_LOOSE)) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (NULL != strstr(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		case FUZZY_LEVEL_PREFIX:
			len = strlen(((RESTRICTION_CONTENT*)
				pfilter->pres)->propval.pvalue);
			if (((RESTRICTION_CONTENT*)pfilter->pres)->fuzzy_level &
				(FUZZY_LEVEL_IGNORECASE | FUZZY_LEVEL_LOOSE)) {
				if (0 == strncasecmp(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			} else {
				if (0 == strncmp(pvalue, ((RESTRICTION_CONTENT*)
					pfilter->pres)->propval.pvalue, len)) {
					return TRUE;
				}
				return FALSE;
			}
			return FALSE;
		}
		return FALSE;
	case RESTRICTION_TYPE_PROPERTY:
		if (PROP_TAG_ANR == ((RESTRICTION_PROPERTY*)pfilter->pres)->proptag) {
			if (TRUE == ab_tree_fetch_node_property(pnode,
				codepage, PROP_TAG_ACCOUNT, &pvalue) &&
				NULL != pvalue) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			/* =SMTP:user@company.com */
			ptoken = strchr(((RESTRICTION_PROPERTY*)
				pfilter->pres)->propval.pvalue, ':');
			if (NULL != ptoken) {
				if (NULL != strcasestr(pvalue, ptoken + 1)) {
					return TRUE;
				}
			}
			if (TRUE == ab_tree_fetch_node_property(pnode,
				codepage, PROP_TAG_DISPLAYNAME, &pvalue) &&
				NULL != pvalue) {
				if (NULL != strcasestr(pvalue, ((RESTRICTION_PROPERTY*)
					pfilter->pres)->propval.pvalue)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		if (FALSE == ab_tree_fetch_node_property(pnode, codepage,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag,
			&pvalue) || NULL == pvalue) {
			return FALSE;
		}
		return propval_compare_relop(
			((RESTRICTION_PROPERTY*)pfilter->pres)->relop,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag&0xFFFF,
			pvalue, ((RESTRICTION_PROPERTY*)pfilter->pres)->propval.pvalue);
	case RESTRICTION_TYPE_PROPCOMPARE:
		return FALSE;
	case RESTRICTION_TYPE_BITMASK:
		 if (PROPVAL_TYPE_LONG != (((RESTRICTION_BITMASK*)
			pfilter->pres)->proptag & 0xFFFF)) {
			return FALSE;
		}
		if (FALSE == ab_tree_fetch_node_property(pnode, codepage,
			((RESTRICTION_PROPERTY*)pfilter->pres)->proptag,
			&pvalue) || NULL == pvalue) {
			return FALSE;
		}
		switch (((RESTRICTION_BITMASK*)pfilter->pres)->bitmask_relop) {
		case BITMASK_RELOP_EQZ:
			if (0 == (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pfilter->pres)->mask)) {
				return TRUE;
			}
			break;
		case BITMASK_RELOP_NEZ:
			if (*(uint32_t*)pvalue &
				((RESTRICTION_BITMASK*)pfilter->pres)->mask) {
				return TRUE;
			}
			break;
		}
		return FALSE;
	case RESTRICTION_TYPE_SIZE:
		return FALSE;
	case RESTRICTION_TYPE_EXIST:
		node_type = ab_tree_get_node_type(pnode);
		if (node_type > 0x80) {
			return FALSE;
		}
		if (TRUE == ab_tree_fetch_node_property(pnode, codepage,
			((RESTRICTION_EXIST*)pfilter->pres)->proptag, &pvalue)
			&& NULL != pvalue) {
			return TRUE;	
		}
		return FALSE;
	case RESTRICTION_TYPE_SUBOBJ:
		return FALSE;
	}
}

BOOL ab_tree_match_minids(AB_BASE *pbase, uint32_t container_id,
	uint32_t codepage, const RESTRICTION *pfilter, LONG_ARRAY *pminids)
{
	int count;
	SINGLE_LIST temp_list;
	SINGLE_LIST *pgal_list;
	SIMPLE_TREE_NODE *pnode;
	SINGLE_LIST_NODE *psnode;
	SINGLE_LIST_NODE *psnode1;
	
	single_list_init(&temp_list);
	if (0xFFFFFFFF == container_id) {
		pgal_list = &pbase->gal_list;
		for (psnode=single_list_get_head(pgal_list); NULL!=psnode;
			psnode=single_list_get_after(pgal_list, psnode)) {
			if (TRUE == ab_tree_match_node(
				psnode->pdata, codepage, pfilter)) {
				psnode1 = common_util_alloc(sizeof(SINGLE_LIST_NODE));
				if (NULL == psnode1) {
					return FALSE;
				}
				psnode1->pdata = psnode->pdata;
				single_list_append_as_tail(&temp_list, psnode1);
			}
		}
	} else {
		pnode = ab_tree_minid_to_node(pbase, container_id);
		if (NULL == pnode || NULL == (pnode =
			simple_tree_node_get_child(pnode))) {
			pminids->count = 0;
			pminids->pl = NULL;
			return TRUE;
		}
		do {
			if (ab_tree_get_node_type(pnode) > 0x80) {
				continue;
			}
			if (TRUE == ab_tree_match_node(pnode, codepage, pfilter)) {
				psnode1 = common_util_alloc(sizeof(SINGLE_LIST_NODE));
				if (NULL == psnode1) {
					return FALSE;
				}
				psnode1->pdata = pnode;
				single_list_append_as_tail(&temp_list, psnode1);
			}
		} while (pnode=simple_tree_node_get_slibling(pnode));
	}
	pminids->count = single_list_get_nodes_num(&temp_list);
	if (0 == pminids->count) {
		pminids->pl = NULL;
	} else {
		pminids->pl = common_util_alloc(sizeof(uint32_t)*pminids->count);
		if (NULL == pminids->pl) {
			return FALSE;
		}
	}
	count = 0;
	for (psnode=single_list_get_head(&temp_list); NULL!=psnode;
		psnode=single_list_get_after(&temp_list, psnode),count++) {
		pminids->pl[count] = ab_tree_get_node_minid(psnode->pdata);
	}
	return TRUE;
}

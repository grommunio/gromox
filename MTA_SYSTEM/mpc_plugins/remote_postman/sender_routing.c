#include "sender_routing.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>


typedef struct _IP_NODE {
	SINGLE_LIST_NODE	node;
	char				ip[16];
} IP_NODE;

static char g_path[256];
static STR_HASH_TABLE *g_hash_table;
static pthread_mutex_t g_hash_lock;

static STR_HASH_TABLE* sender_routing_load_hash();

static void sender_routing_free_hash(STR_HASH_TABLE *phash);


void sender_routing_init(const char *path)
{
	strcpy(g_path, path);
	g_hash_table = NULL;
	pthread_mutex_init(&g_hash_lock, NULL);
}

void sender_routing_free()
{
	g_path[0] = '\0';
	pthread_mutex_destroy(&g_hash_lock);
}

int sender_routing_run()
{
	g_hash_table = sender_routing_load_hash();
	if (NULL == g_hash_table) {
		return -1;
	}
    return 0;
}

BOOL sender_routing_refresh()
{
	STR_HASH_TABLE *phash;
	STR_HASH_TABLE *ptemp_hash;

	phash = sender_routing_load_hash();
	if (NULL == phash) {
		return FALSE;
	}

	pthread_mutex_lock(&g_hash_lock);
	ptemp_hash = g_hash_table;
	g_hash_table = phash;
	pthread_mutex_unlock(&g_hash_lock);
	sender_routing_free_hash(ptemp_hash);
	return TRUE;

}

static void sender_routing_free_hash(STR_HASH_TABLE *phash)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *pnode;
	STR_HASH_ITER *iter;

	iter = str_hash_iter_init(phash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = (SINGLE_LIST*)str_hash_iter_get_value(iter, NULL);
		while (pnode = single_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		single_list_free(plist);
	}
	str_hash_iter_free(iter);

	str_hash_free(phash);
}

static STR_HASH_TABLE* sender_routing_load_hash()
{
	IP_NODE *p_ip;
	SINGLE_LIST temp_list;
	SINGLE_LIST_NODE *pnode;
	LIST_FILE *plist_file;
	STR_HASH_TABLE *phash;
	int i, list_num, ip_len;
	char tmp_ip[16], ip_buff[16];
	char *pitem, *pcomma, *pbegin;
	char *sender_name, *routing_ips;
	
	plist_file = list_file_init(g_path, "%s:256%s:1024");
	if (NULL == plist_file) {
		return NULL;
	}
	list_num = list_file_get_item_num(plist_file);
	phash = str_hash_init(list_num + 1, sizeof(SINGLE_LIST), NULL);
	if (NULL == phash) {
		list_file_free(plist_file);
		return NULL;
	}
	pitem = list_file_get_list(plist_file);
	for (i=0; i<list_num; i++) {
		sender_name = pitem + 1280*i;
		routing_ips = sender_name + 256;
		lower_string(sender_name);
		single_list_init(&temp_list);
		pbegin = routing_ips;
		while (NULL != (pcomma = strchr(pbegin, ':'))) {
			ip_len = pcomma - pbegin;
			if (ip_len > 15) {
				printf("[sender_routing]: ip format is illegal in item %d\n", i+1);
				pbegin = pcomma + 1;
				continue;
			}
			memcpy(tmp_ip, pbegin, ip_len);
			tmp_ip[ip_len] = '\0';
			if (NULL == extract_ip(pbegin, ip_buff) ||
				0 != strcmp(tmp_ip, ip_buff)) {
				printf("[sender_routing]: %s is illegal in item %d\n",tmp_ip, i+1);
				pbegin = pcomma + 1;
				continue;
			}
			p_ip = (IP_NODE*)malloc(sizeof(IP_NODE));
			if (NULL == p_ip) {
				while (pnode = single_list_get_from_head(&temp_list)) {
					free(pnode->pdata);
				}
				break;
			}
			p_ip->node.pdata = p_ip;
			strcpy(p_ip->ip, tmp_ip);
			single_list_append_as_tail(&temp_list, &p_ip->node);
			pbegin = pcomma + 1;
		}
		if (0 == single_list_get_nodes_num(&temp_list)) {
			single_list_free(&temp_list);
			continue;
		}
		if (1 != str_hash_add(phash, sender_name, &temp_list)) {
			while (pnode = single_list_get_from_head(&temp_list)) {
				free(pnode->pdata);
			}
			single_list_free(&temp_list);
			printf("[sender_routing]: fail to add item %d into hash table\n", i);
		}
	}
	list_file_free(plist_file);
	return phash;
}

int sender_routing_stop()
{
	if (NULL != g_hash_table) {
		sender_routing_free_hash(g_hash_table);
		g_hash_table = NULL;
	}
    return 0;
}

BOOL sender_routing_check(const char *sender, VSTACK *pstack)
{
	SINGLE_LIST *plist;
	char tmp_sender[256];
	SINGLE_LIST_NODE *pnode;
	
	strncpy(tmp_sender, sender, sizeof(tmp_sender));
	lower_string(tmp_sender);
	vstack_clear(pstack);
	pthread_mutex_lock(&g_hash_lock);
	plist = (SINGLE_LIST*)str_hash_query(g_hash_table, tmp_sender);
	if (NULL != plist) {
		for (pnode=single_list_get_head(plist); NULL!=pnode;
			pnode=single_list_get_after(plist, pnode)) {
			vstack_push(pstack, ((IP_NODE*)(pnode->pdata))->ip);
		}
		pthread_mutex_unlock(&g_hash_lock);
		return TRUE;
	}
	pthread_mutex_unlock(&g_hash_lock);
	return FALSE;
}

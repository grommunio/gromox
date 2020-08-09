#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/socket.h>
#include "address_list.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <pthread.h>


typedef struct _HOST_ITEM {
	char ip[16];
	uint16_t port;
} HOST_ITEM;

static char g_list_path[256];
static STR_HASH_TABLE *g_hash_table;
static pthread_rwlock_t g_table_lock;


int address_list_refresh()
{
	int i, item_num;
	HOST_ITEM temp_host;
	LIST_FILE *plist;
	STR_HASH_TABLE *phash, *phash_temp;
	struct ipitem { char a[256], ip_addr_and_port[32]; };

	plist = list_file_init3(g_list_path, "%s:256%s:32", false);
	if (NULL == plist) {
		printf("[domain_subsystem]: list_file_init %s: %s\n",
			g_list_path, strerror(errno));
		return REFRESH_FILE_ERROR;
	}
	item_num = list_file_get_item_num(plist);
	phash = str_hash_init(item_num + 1, sizeof(HOST_ITEM), NULL);
	if (NULL == phash) {
		printf("[domain_subsystem]: Failed to init hash table\n");
		list_file_free(plist);
		return REFRESH_HASH_FAIL;
	}
	struct ipitem *pitem = reinterpret_cast(struct ipitem *, list_file_get_list(plist));
	for (i=0; i<item_num; i++) {
		HX_strlower(pitem[i].a);
		temp_host.port = 25;
		int ret = gx_addrport_split(pitem[i].ip_addr_and_port, temp_host.ip,
		          GX_ARRAY_SIZE(temp_host.ip), &temp_host.port);
		if (ret < 0) {
			printf("[domain_subsystem]: error in line %d with host \"%s\": %s\n",
			       i, pitem[i].ip_addr_and_port, strerror(-ret));
			continue;
		}
		str_hash_add(phash, pitem[i].a, &temp_host);
	}
	list_file_free(plist);
	pthread_rwlock_wrlock(&g_table_lock);
	phash_temp = g_hash_table;
	g_hash_table = phash;
	pthread_rwlock_unlock(&g_table_lock);
	if (NULL != phash_temp) {
		str_hash_free(phash_temp);
	}
	return REFRESH_OK;
}

BOOL address_list_query(const char *domain, char *ip, int *port)
{
	HOST_ITEM *phost;
	char temp_domain[256];

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	pthread_rwlock_rdlock(&g_table_lock);
	phost = str_hash_query(g_hash_table, temp_domain);
	if (NULL == phost) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	} else {
		strcpy(ip, phost->ip);
		*port = phost->port;
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
}


void address_list_init(const char *list_path)
{
	strcpy(g_list_path, list_path);
	pthread_rwlock_init(&g_table_lock, NULL);
}


void address_list_free()
{
	pthread_rwlock_destroy(&g_table_lock);
}

int address_list_run()
{
	if (REFRESH_OK != address_list_refresh()) {
		return -1;
	}
	return 0;
}

int address_list_stop()
{
	if (NULL != g_hash_table) {
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	return 0;
}


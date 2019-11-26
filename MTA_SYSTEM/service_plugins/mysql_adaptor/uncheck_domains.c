#include <libHX/string.h>
#include "uncheck_domains.h"
#include "str_hash.h"
#include "util.h"
#include "list_file.h"
#include <pthread.h>
#include <stdio.h>

static STR_HASH_TABLE *g_domain_table;
static pthread_rwlock_t g_domain_lock;
static char g_list_path[256];

void uncheck_domains_init(const char *list_path)
{
	strcpy(g_list_path, list_path);
}

void uncheck_domains_free()
{
	g_list_path[0] = '\0';
}

int uncheck_domains_run()
{
    pthread_rwlock_init(&g_domain_lock, NULL);
    if (TABLE_REFRESH_OK != uncheck_domains_refresh()) {
        g_domain_table = NULL;
    }
    return 0;
}

int uncheck_domains_stop()
{
    if (NULL != g_domain_table) {
        str_hash_free(g_domain_table);
        g_domain_table = NULL;
    }
    pthread_rwlock_destroy(&g_domain_lock);
    return 0;
}

BOOL uncheck_domains_query(const char* domain)
{
	char temp_string[256];
	
	strncpy(temp_string, domain, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);
	pthread_rwlock_rdlock(&g_domain_lock);
    if (NULL != g_domain_table &&
		NULL != str_hash_query(g_domain_table, temp_string)) {
		pthread_rwlock_unlock(&g_domain_lock);
        return TRUE;
    }
	pthread_rwlock_unlock(&g_domain_lock);
    return FALSE;
}

int uncheck_domains_refresh()
{
    STR_HASH_TABLE *phash = NULL;
    int i, list_len;
	LIST_FILE *plist_file;
	char *pitem;
	
    /* initialize the list filter */
	plist_file = list_file_init(g_list_path, "%s:256");
	if (NULL == plist_file) {
		return TABLE_REFRESH_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	
    phash = str_hash_init(list_len + 1, sizeof(int), NULL);
	if (NULL == phash) {
		printf("[mysql_adaptor]: fail to allocate hash map for "
			"uncheck domains\n");
		list_file_free(plist_file);
		return TABLE_REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
		HX_strlower(pitem + 256 * i);
        str_hash_add(phash, pitem + 256*i, &i);   
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_domain_lock);
	if (NULL != g_domain_table) {
		str_hash_free(g_domain_table);
	}
    g_domain_table = phash;
    pthread_rwlock_unlock(&g_domain_lock);

    return TABLE_REFRESH_OK;
}


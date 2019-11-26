#include "site_protection.h"
#include "str_hash.h"
#include "double_list.h"
#include "list_file.h"
#include "util.h"
#include "mail_func.h"
#include <pthread.h>

enum {
	SPL_REFRESH_OK = 0,
	SPL_FILE_FAIL,
	SPL_HASH_FAIL
};

enum {
	PROTECTION_RETRY,
	PROTECTION_REJECT
};

typedef struct _PROTECTION_ITEM {
	DOUBLE_LIST list;
	int protection_type;
} PROTECTION_ITEM;

typedef struct _IP_SECT {
	DOUBLE_LIST_NODE node;
	char sect[8];
} IP_SECT;

static int site_protection_list_refresh();

static void site_protection_list_free(STR_HASH_TABLE *phash);

static char g_list_path[256];
static STR_HASH_TABLE *g_protection_hash;
static pthread_rwlock_t g_reload_lock;

/*
 *	site protection's construct function
 *	@param
 *		path [in]		indicate the path of list file
 */
void site_protection_init(const char *path)
{
	strcpy(g_list_path, path);
	g_protection_hash = NULL;
}

/*
 *	run the module of site protection
 *	@return
 *		0				OK
 *	  <>0				fail
 */
int site_protection_run()
{
	pthread_rwlock_init(&g_reload_lock, NULL);
	if (SPL_REFRESH_OK != site_protection_list_refresh()) {
		return -1;
	}
	return 0;
}

/*
 *	stop the module of site protection
 *	@return
 *		0				OK
 *	  <>0				fail
 */
int site_protection_stop()
{
	if (NULL != g_protection_hash) {
		site_protection_list_free(g_protection_hash);
		g_protection_hash = NULL;
	}
	pthread_rwlock_destroy(&g_reload_lock);
	return 0;
}

/*
 *	site protection's destruct function
 */
void site_protection_free()
{
	g_list_path[0] = '\0';
}

/*
 *  *  reload the list
 *  @return
 *		SPL_FILE_FAIL       fail to load list file
 *		SPL_HASH_FAIL       fail to creat hash table
 *		SPL_REFRESH_OK      OK to reload list
 */
static int site_protection_list_refresh()
{
	IP_SECT *psect;
	STR_HASH_TABLE *phash, *phash_temp;
	PROTECTION_ITEM *pprotection, temp_protection;
	char *pitem, *pbegin, *pcomma;
	int i, list_num, sect_len, type;
	LIST_FILE *plist_file;

	plist_file = list_file_init(g_list_path, "%s:16%s:256%s:1024");
	if (NULL == plist_file) {
		printf("[site_protection]: fail to load list file\n");
		return SPL_FILE_FAIL;
	}
	list_num = list_file_get_item_num(plist_file);
	pitem = (char*)list_file_get_list(plist_file);
	if (0 == list_num) {
		printf("[site_protection]: there's no item in list file\n");
		phash_temp = g_protection_hash;
		pthread_rwlock_wrlock(&g_reload_lock);
		g_protection_hash = NULL;
		pthread_rwlock_unlock(&g_reload_lock);
		list_file_free(plist_file);
		site_protection_list_free(phash_temp);
		return SPL_REFRESH_OK;
	}
	phash = str_hash_init(list_num, sizeof(PROTECTION_ITEM), NULL);
	if (NULL == phash) {
		printf("[site_protection]: fail to allocate hash map\n");
		list_file_free(plist_file);
		return SPL_HASH_FAIL;
	}
	for (i=0; i<list_num; i++) {
		pbegin = pitem + 1296*i;
		if (0 == strcasecmp(pbegin, "M_REJECT")) {
			type = PROTECTION_REJECT;
		} else if (0 == strcasecmp(pbegin, "M_RETRY")) {
			type = PROTECTION_RETRY;
		} else {
			continue;
		}
		pbegin += 16;
		lower_string(pbegin);
		str_hash_add(phash, pbegin, &temp_protection);
		pprotection = (PROTECTION_ITEM*)str_hash_query(phash, pbegin);
		if (NULL == pprotection) {
			printf("[site_protection]: error in str_hash!\n");
			continue;
		}
		pprotection->protection_type = type;
		double_list_init(&pprotection->list);
		pbegin += 256;
		while (NULL != (pcomma = strchr(pbegin, ':'))) {
			sect_len = pcomma - pbegin;
			if (sect_len >= 8 || sect_len < 3) {
				pbegin = pcomma + 1;
				continue;
			}
			psect = (IP_SECT*)malloc(sizeof(IP_SECT));
			if (NULL == psect) {
				site_protection_list_free(phash);
				list_file_free(plist_file);
				return SPL_HASH_FAIL;
			}
			psect->node.pdata = psect;
			memcpy(psect->sect, pbegin, pcomma - pbegin);
			psect->sect[sect_len] = '\0';
			double_list_append_as_tail(&pprotection->list, &psect->node);
			pbegin = pcomma + 1;
		}
	}
	list_file_free(plist_file);
	phash_temp = g_protection_hash;
	pthread_rwlock_wrlock(&g_reload_lock);
	g_protection_hash = phash;
	pthread_rwlock_unlock(&g_reload_lock);
	site_protection_list_free(phash_temp);
	return SPL_REFRESH_OK;
}


static void site_protection_list_free(STR_HASH_TABLE *phash)
{
	STR_HASH_ITER *iter;
	PROTECTION_ITEM *pprotection;
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL != phash) {
		iter = str_hash_iter_init(phash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pprotection = (PROTECTION_ITEM*)str_hash_iter_get_value(iter, NULL);
			while (NULL != (pnode = 
				double_list_get_from_head(&pprotection->list))) {
				free(pnode->pdata);
			}
			double_list_free(&pprotection->list);
		}
		str_hash_iter_free(iter);
		str_hash_free(phash);
	}
}

BOOL site_protection_verify(char *domain, char *ip)
{
	IP_SECT *psect;
	DOUBLE_LIST_NODE *pnode;
	PROTECTION_ITEM *pprotection;
	char temp_domain[256];
	
	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	pthread_rwlock_rdlock(&g_reload_lock);
	if (NULL != g_protection_hash) {
		pprotection = (PROTECTION_ITEM*)str_hash_query(
						g_protection_hash, temp_domain);
		if (NULL == pprotection) {
			pthread_rwlock_unlock(&g_reload_lock);
			return SITE_PROTECTION_NONE;
		}
		for (pnode=double_list_get_head(&pprotection->list); pnode!=NULL;
			pnode=double_list_get_after(&pprotection->list, pnode)) {
			psect = (IP_SECT*)(pnode->pdata);
			if (NULL != strstr(ip, psect->sect)) {
				pthread_rwlock_unlock(&g_reload_lock);
				return SITE_PROTECTION_OK;
			}
		}
		pthread_rwlock_unlock(&g_reload_lock);
		if (PROTECTION_RETRY == pprotection->protection_type) {
			return SITE_PROTECTION_RETRY;
		} else if (PROTECTION_REJECT == pprotection->protection_type) {
			return SITE_PROTECTION_REJECT;
		} else {
			printf("[site_protection]: error in protection_type!\n");
			return SITE_PROTECTION_NONE;
		}
	}
	pthread_rwlock_unlock(&g_reload_lock);
	return SITE_PROTECTION_NONE;
}

void site_protection_console_talk(int argc, char **argv, char *result,
	int length)
{
    char help_string[] = "250 site protection help information:\r\n"
                         "\t%s reload\r\n"
                         "\t    --reload the protection list from file";
    if (1 == argc) {
        strncpy(result, "550 too few arguments", length);
        return;
    }
    if (2 == argc && 0 == strcmp("--help", argv[1])) {
        snprintf(result, length, help_string, argv[0]);
        result[length - 1] ='\0';
        return;
    }
    if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		switch (site_protection_list_refresh()) {
		case SPL_REFRESH_OK:
			strncpy(result, "250 protection list reload OK", length);
			return;
		case SPL_FILE_FAIL:
			strncpy(result, "550 can not open protection list file", length);
			return;
		case SPL_HASH_FAIL:
			strncpy(result, "550 protection hash table fail", length);
			return;

		}
        return;
    }
	snprintf(result, length, "550 invalid argument %s", argv[1]);
    return;
}


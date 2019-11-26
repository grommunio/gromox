#include "domain_limit.h"
#include "str_hash.h"
#include "list_file.h"
#include "single_list.h"
#include "util.h"
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>

enum {
	DOMAIN_LIST_ADD_OK = 0,
	DOMAIN_LIST_FILE_FAIL,
	DOMAIN_LIST_HASH_FAIL
};

typedef struct _LIMIT_UNIT {
	SINGLE_LIST_NODE node;
	BOOL b_domain;
	char object[256];
} LIMIT_UNIT;

static int g_growing_num;
static int g_deny_cap;
static int g_allow_cap;
static char g_root_path[256];
static STR_HASH_TABLE *g_allow_hash;
static STR_HASH_TABLE *g_deny_hash;
static pthread_rwlock_t g_allow_lock;
static pthread_rwlock_t g_deny_lock;

static void domain_limit_remove_deny(const char *domain);

static void domain_limit_remove_allow(const char *domain);

static int domain_limit_add_deny(const char *domain);

static int domain_limit_add_allow(const char *domain);

void domain_limit_init(int growing_num, const char *root_path)
{
	g_growing_num = growing_num;
	strcpy(g_root_path, root_path);
	pthread_rwlock_init(&g_allow_lock, NULL);
	pthread_rwlock_init(&g_deny_lock, NULL);
}

int domain_limit_run()
{
	DIR *dirp;
	char *pitem;
	int temp_len;
	int domain_num;
	int i, item_num;
	SINGLE_LIST temp_list;
	LIST_FILE *plist;
	LIMIT_UNIT *punit;
	char temp_path[256];
	char temp_domain[256];
	struct dirent *direntp;

	sprintf(temp_path, "%s/deny", g_root_path);
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		printf("[domain_limit]: fail to open %s\n", temp_path);
		return -1;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		domain_num ++;
	}
	g_deny_cap = domain_num + g_growing_num;
	g_deny_hash = str_hash_init(g_deny_cap, sizeof(SINGLE_LIST), NULL);
	if (NULL == g_deny_hash) {
		closedir(dirp);
		printf("[domain_limit]: fail to init deny hash table\n");
		return -2;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		if (temp_len <= 4 && 0 != strcasecmp(temp_domain + temp_len - 4, ".txt")) {
			continue;
		}
		temp_domain[temp_len - 4] = '\0';
		for (i=0; i<temp_len-4; i++) {
			if (0 != isupper(temp_domain[i])) {
				break;
			}
		}
		if (i < temp_len - 4) {
			continue;
		}
		
		sprintf(temp_path, "%s/deny/%s", g_root_path, direntp->d_name);
		plist = list_file_init(temp_path, "%s:256");
		if (NULL == plist) {
			continue;
		}
		pitem = list_file_get_list(plist);
		item_num = list_file_get_item_num(plist);
		single_list_init(&temp_list);
		for (i=0; i<item_num; i++) {
			punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
			if (NULL != punit) {
				punit->node.pdata = punit;
				strcpy(punit->object, pitem + 256 * i);
				if (NULL == strchr(punit->object, '@')) {
					punit->b_domain = TRUE;
				} else {
					punit->b_domain = FALSE;
				}
				single_list_append_as_tail(&temp_list, &punit->node);
			}
		}
		str_hash_add(g_deny_hash, temp_domain, &temp_list);
		single_list_free(&temp_list);
		list_file_free(plist);
	}
	closedir(dirp);

	sprintf(temp_path, "%s/allow", g_root_path);
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		printf("[domain_limit]: fail to open %s\n", temp_path);
		return -3;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		domain_num ++;
	}
	g_allow_cap = domain_num + g_growing_num;
	g_allow_hash = str_hash_init(g_allow_cap, sizeof(SINGLE_LIST), NULL);
	if (NULL == g_allow_hash) {
		closedir(dirp);
		printf("[domain_limit]: fail to init allow hash table\n");
		return -4;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		if (temp_len <= 4 && 0 != strcasecmp(temp_domain + temp_len - 4, ".txt")) {
			continue;
		}
		temp_domain[temp_len - 4] = '\0';
		
		for (i=0; i<temp_len-4; i++) {
			if (0 != isupper(temp_domain[i])) {
				break;
			}
		}
		if (i < temp_len - 4) {
			continue;
		}
		
		sprintf(temp_path, "%s/allow/%s", g_root_path, direntp->d_name);
		plist = list_file_init(temp_path, "%s:256");
		if (NULL == plist) {
			continue;
		}
		pitem = list_file_get_list(plist);
		item_num = list_file_get_item_num(plist);
		single_list_init(&temp_list);
		punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
		if (NULL != punit) {
			punit->node.pdata = punit;
			strcpy(punit->object, temp_domain);
			punit->b_domain = TRUE;
			single_list_append_as_tail(&temp_list, &punit->node);
		}
		for (i=0; i<item_num; i++) {
			punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
			if (NULL != punit) {
				punit->node.pdata = punit;
				strcpy(punit->object, pitem + 256 * i);
				if (NULL == strchr(punit->object, '@')) {
					punit->b_domain = TRUE;
				} else {
					punit->b_domain = FALSE;
				}
				single_list_append_as_tail(&temp_list, &punit->node);
			}
		}
		str_hash_add(g_allow_hash, temp_domain, &temp_list);
		single_list_free(&temp_list);
		list_file_free(plist);
	}
	closedir(dirp);
	return 0;	
}

BOOL domain_limit_check(const char *from, MEM_FILE *pf_rcpt_to)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *pnode;
	LIMIT_UNIT *punit;
	char *rcpt_domain;
	char temp_rcpt[256];
	char from_domain[256];
	BOOL b_allowed;

	strcpy(from_domain, strchr(from, '@') + 1);
	lower_string(from_domain);

	/* query the deny table */
	pthread_rwlock_rdlock(&g_deny_lock);
	plist = str_hash_query(g_deny_hash, from_domain);
	if (NULL != plist) {
		for (pnode=single_list_get_head(plist); NULL!=pnode;
			pnode=single_list_get_after(plist, pnode)) {
			punit = (LIMIT_UNIT*)pnode->pdata;
			mem_file_seek(pf_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
			while (MEM_END_OF_FILE != mem_file_readline(pf_rcpt_to, temp_rcpt,
				256)) {
				if (TRUE == punit->b_domain) {
					rcpt_domain = strchr(temp_rcpt, '@') + 1;
					if (0 == strcasecmp(punit->object, rcpt_domain)) {
						pthread_rwlock_unlock(&g_deny_lock);
						return FALSE;
					}
				} else {
					if (0 == strcasecmp(punit->object, temp_rcpt)) {
						pthread_rwlock_unlock(&g_deny_lock);
						return FALSE;
					}
				}

			}
		}
	}
	mem_file_seek(pf_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(pf_rcpt_to, temp_rcpt, 256)) {
		lower_string(temp_rcpt);
		rcpt_domain = strchr(temp_rcpt, '@') + 1;
		plist = str_hash_query(g_deny_hash, rcpt_domain);
		if (NULL != plist) {
			for (pnode=single_list_get_head(plist); NULL!=pnode;
				pnode=single_list_get_after(plist, pnode)) {
				punit = (LIMIT_UNIT*)pnode->pdata;
				if (TRUE == punit->b_domain) {
					if (0 == strcasecmp(punit->object, from_domain)) {
						pthread_rwlock_unlock(&g_deny_lock);
						return FALSE;
					}
				} else {
					if (0 == strcasecmp(punit->object, from)) {
						pthread_rwlock_unlock(&g_deny_lock);
						return FALSE;
					}
				}
			}
		}
	}
	pthread_rwlock_unlock(&g_deny_lock);
	

	/* query the allow table */
	pthread_rwlock_rdlock(&g_allow_lock);
	plist = str_hash_query(g_allow_hash, from_domain);
	if (NULL != plist) {
		mem_file_seek(pf_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_readline(pf_rcpt_to, temp_rcpt, 256)) {
			rcpt_domain = strchr(temp_rcpt, '@') + 1;
			b_allowed = FALSE;
			for (pnode=single_list_get_head(plist); NULL!=pnode;
				pnode=single_list_get_after(plist, pnode)) {
				punit = (LIMIT_UNIT*)pnode->pdata;
				if (TRUE == punit->b_domain) {
					if (0 == strcasecmp(punit->object, rcpt_domain)) {
						b_allowed = TRUE;
						break;
					}
				} else {
					if (0 == strcasecmp(punit->object, temp_rcpt)) {
						b_allowed = TRUE;
						break;
					}
				}
			}
			if (FALSE == b_allowed) {
				pthread_rwlock_unlock(&g_allow_lock);
				return FALSE;
			}
		}
	}
	mem_file_seek(pf_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(pf_rcpt_to, temp_rcpt, 256)) {
		lower_string(temp_rcpt);
		rcpt_domain = strchr(temp_rcpt, '@') + 1;
		plist = str_hash_query(g_allow_hash, rcpt_domain);
		if (NULL != plist) {
			b_allowed = FALSE;
			for (pnode=single_list_get_head(plist); NULL!=pnode;
				pnode=single_list_get_after(plist, pnode)) {
				punit = (LIMIT_UNIT*)pnode->pdata;
				if (TRUE == punit->b_domain) {
					if (0 == strcasecmp(punit->object, from_domain)) {
						b_allowed = TRUE;
						break;
					}
				} else {
					if (0 == strcasecmp(punit->object, from)) {
						b_allowed = TRUE;
						break;
					}
				}
			}
			if (FALSE == b_allowed) {
				pthread_rwlock_unlock(&g_allow_lock);
				return FALSE;
			}
		}
	}
	pthread_rwlock_unlock(&g_allow_lock);
	return TRUE;
}

int domain_limit_stop()
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *pnode;
	STR_HASH_ITER *iter;
	
	if (NULL != g_deny_hash) {
		iter = str_hash_iter_init(g_deny_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			plist = str_hash_iter_get_value(iter, NULL);
			while (pnode = single_list_get_from_head(plist)) { 
				free(pnode->pdata);
			}
			single_list_free(plist);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_deny_hash);
		g_deny_hash = NULL;
	}
	if (NULL != g_allow_hash) {
		iter = str_hash_iter_init(g_allow_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			plist = str_hash_iter_get_value(iter, NULL);
			while (pnode = single_list_get_from_head(plist)) { 
				free(pnode->pdata);
			}
			single_list_free(plist);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_allow_hash);
		g_allow_hash = NULL;
	}
	return 0;
}

void domain_limit_free()
{
	g_root_path[0] = '\0';
	pthread_rwlock_destroy(&g_allow_lock);
	pthread_rwlock_destroy(&g_deny_lock);
}

static void domain_limit_remove_deny(const char *domain)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *pnode;
	char temp_domain[256];
	char temp_path[256];

	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	
	pthread_rwlock_wrlock(&g_deny_lock);
	plist = str_hash_query(g_deny_hash, temp_domain);
	if (NULL != plist) {
		while (pnode = single_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		single_list_free(plist);
		str_hash_remove(g_deny_hash, temp_domain);
	}
	pthread_rwlock_unlock(&g_deny_lock);
	sprintf(temp_path, "%s/deny/%s.txt", g_root_path, domain);
	remove(temp_path);
}

static void domain_limit_remove_allow(const char *domain)
{
	SINGLE_LIST *plist;
	SINGLE_LIST_NODE *pnode;
	char temp_domain[256];
	char temp_path[256];

	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	
	pthread_rwlock_wrlock(&g_allow_lock);
	plist = str_hash_query(g_allow_hash, temp_domain);
	if (NULL != plist) {
		while (pnode = single_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		single_list_free(plist);
		str_hash_remove(g_allow_hash, temp_domain);
	}
	pthread_rwlock_unlock(&g_allow_lock);
	sprintf(temp_path, "%s/allow/%s.txt", g_root_path, domain);
	remove(temp_path);
}

static int domain_limit_add_deny(const char *domain)
{
	int i, item_num;
	SINGLE_LIST_NODE *pnode;
	LIMIT_UNIT *punit;
	SINGLE_LIST *plist, temp_list;
	LIST_FILE *plist_file;
	STR_HASH_TABLE *phash;
	STR_HASH_ITER *iter;
	char temp_domain[256];
	char temp_path[256];
	char temp_buff[256];
	char *pitem;

	strcpy(temp_domain, domain);
	lower_string(temp_domain);

	sprintf(temp_path, "%s/deny/%s.txt", g_root_path, temp_domain);
	plist_file = list_file_init(temp_path, "%s:256");
	if (NULL == plist_file) {
		printf("[domain_limit]: fail to get domain deny list file %s\n",
			temp_path);
		return DOMAIN_LIST_FILE_FAIL;
	}
	single_list_init(&temp_list);
	pitem = list_file_get_list(plist_file);
	item_num = list_file_get_item_num(plist_file);
	for (i=0; i<item_num; i++) {
		punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
		punit->node.pdata = punit;
		strcpy(punit->object, pitem + 256 * i);
		if (NULL == strchr(punit->object, '@')) {
			punit->b_domain = TRUE;
		} else {
			punit->b_domain = FALSE;
		}
		single_list_append_as_tail(&temp_list, &punit->node);
	}
	pthread_rwlock_wrlock(&g_deny_lock);
	plist = str_hash_query(g_deny_hash, temp_domain);
	if (NULL != plist) {
		while (pnode = single_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		str_hash_remove(g_deny_hash, temp_domain);
	}
	if (str_hash_add(g_deny_hash, temp_domain, &temp_list) > 0) {
		pthread_rwlock_unlock(&g_deny_lock);
		return DOMAIN_LIST_ADD_OK;
	}
	phash = str_hash_init(g_deny_cap + g_growing_num, sizeof(SINGLE_LIST), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_deny_lock);
		while (pnode = single_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		single_list_free(&temp_list);
		return DOMAIN_LIST_HASH_FAIL;
	}
	iter = str_hash_iter_init(g_deny_hash);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = str_hash_iter_get_value(iter, temp_buff);
		str_hash_add(phash, temp_buff, plist);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_deny_hash);
	g_deny_hash = phash;
	str_hash_add(g_deny_hash, temp_domain, &temp_list);
	g_deny_cap += g_growing_num;
	pthread_rwlock_unlock(&g_deny_lock);
	return DOMAIN_LIST_ADD_OK;
}

static int domain_limit_add_allow(const char *domain)
{
	int i, item_num;
	SINGLE_LIST_NODE *pnode;
	LIMIT_UNIT *punit;
	SINGLE_LIST *plist, temp_list;
	LIST_FILE *plist_file;
	STR_HASH_TABLE *phash;
	STR_HASH_ITER *iter;
	char temp_domain[256];
	char temp_path[256];
	char temp_buff[256];
	char *pitem;

	strcpy(temp_domain, domain);
	lower_string(temp_domain);

	sprintf(temp_path, "%s/allow/%s.txt", g_root_path, temp_domain);
	plist_file = list_file_init(temp_path, "%s:256");
	if (NULL == plist_file) {
		printf("[domain_limit]: fail to get domain allow list file %s\n",
			temp_path);
		return DOMAIN_LIST_FILE_FAIL;
	}
	single_list_init(&temp_list);
	punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
	if (NULL != punit) {
		punit->node.pdata = punit;
		strcpy(punit->object, temp_domain);
		punit->b_domain = TRUE;
		single_list_append_as_tail(&temp_list, &punit->node);
	}
	pitem = list_file_get_list(plist_file);
	item_num = list_file_get_item_num(plist_file);
	for (i=0; i<item_num; i++) {
		punit = (LIMIT_UNIT*)malloc(sizeof(LIMIT_UNIT));
		punit->node.pdata = punit;
		strcpy(punit->object, pitem + 256 * i);
		if (NULL == strchr(punit->object, '@')) {
			punit->b_domain = TRUE;
		} else {
			punit->b_domain = FALSE;
		}
		single_list_append_as_tail(&temp_list, &punit->node);
	}
	pthread_rwlock_wrlock(&g_allow_lock);
	plist = str_hash_query(g_allow_hash, temp_domain);
	if (NULL != plist) {
		while (pnode = single_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		str_hash_remove(g_allow_hash, temp_domain);
	}
	if (str_hash_add(g_allow_hash, temp_domain, &temp_list) > 0) {
		pthread_rwlock_unlock(&g_allow_lock);
		return DOMAIN_LIST_ADD_OK;
	}
	phash = str_hash_init(g_allow_cap + g_growing_num, sizeof(SINGLE_LIST), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_allow_lock);
		while (pnode = single_list_get_from_head(&temp_list)) {
			free(pnode->pdata);
		}
		single_list_free(&temp_list);
		return DOMAIN_LIST_HASH_FAIL;
	}
	iter = str_hash_iter_init(g_allow_hash);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = str_hash_iter_get_value(iter, temp_buff);
		str_hash_add(phash, temp_buff, plist);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_allow_hash);
	g_allow_hash = phash;
	str_hash_add(g_allow_hash, temp_domain, &temp_list);
	g_allow_cap += g_growing_num;
	pthread_rwlock_unlock(&g_allow_lock);
	return DOMAIN_LIST_ADD_OK;
}

void domain_limit_console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 domain rcpt help information:\r\n"
						 "\t%s add deny <domain>\r\n"
						 "\t    --add domain into deny table\r\n"
						 "\t%s add allow <domain>\r\n"
						 "\t    --add domain into allow table\r\n"
						 "\t%s remove deny <domain>\r\n"
						 "\t    --remove domain from deny table\r\n"
						 "\t%s remove allow <domain>\r\n"
						 "\t    --remove domain from allow table";
	
	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0],
			argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (4 == argc && 0 == strcmp("add", argv[1]) &&
		0 == strcmp("deny", argv[2])) {
		switch (domain_limit_add_deny(argv[3])) {
		case DOMAIN_LIST_ADD_OK:
			snprintf(result, length, "250 add domain %s into deny list OK",
				argv[3]);
			break;
		case DOMAIN_LIST_FILE_FAIL:
			snprintf(result, length, "550 fail to open list file of "
				"domain %s in deny directory", argv[3]);
			break;
		case DOMAIN_LIST_HASH_FAIL:
			snprintf(result, length, "550 fail to add deny list of domain %s "
				"into hash table", argv[3]);
			break;
		}
		return;
	}
	if (4 == argc && 0 == strcmp("add", argv[1]) &&
		0 == strcmp("allow", argv[2])) {
		switch (domain_limit_add_allow(argv[3])) {
		case DOMAIN_LIST_ADD_OK:
			snprintf(result, length, "250 add domain %s into allow list OK",
				argv[3]);
			break;
		case DOMAIN_LIST_FILE_FAIL:
			snprintf(result, length, "550 fail to open list file of "
				"domain %s in allow directory", argv[3]);
			break;
		case DOMAIN_LIST_HASH_FAIL:
			snprintf(result, length, "550 fail to add allow list of domain %s "
				"into hash table", argv[3]);
			break;
		}
		return;
	}
	if (4 == argc && 0 == strcmp("remove", argv[1]) &&
		0 == strcmp("deny", argv[2])) {
		domain_limit_remove_deny(argv[3]);
		snprintf(result, length, "250 remove domain %s from deny list OK",
			argv[3]);
		return;
	}
	if (4 == argc && 0 == strcmp("remove", argv[1]) &&
		0 == strcmp("allow", argv[2])) {
		domain_limit_remove_allow(argv[3]);
		snprintf(result, length, "250 remove domain %s from allow list OK",
			argv[3]);
		return;
	}

	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;

}





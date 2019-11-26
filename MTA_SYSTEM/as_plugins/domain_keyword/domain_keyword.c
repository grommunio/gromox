#include <errno.h>
#include <string.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include "domain_keyword.h"
#include "keyword_engine.h"
#include "str_hash.h"
#include "util.h"
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>

enum {
	DOMAIN_KEYWORD_ADD_OK = 0,
	DOMAIN_KEYWORD_FILE_FAIL,
	DOMAIN_KEYWORD_HASH_FAIL
};


static int g_hash_cap;
static int g_growing_num;
static char g_root_path[256];
static STR_HASH_TABLE *g_hash_table;
static pthread_rwlock_t g_hash_lock;

static void domain_keyword_remove(const char *domain);

static int domain_keyword_add(const char *domain);

void domain_keyword_init(int growing_num, const char *root_path)
{
	g_growing_num = growing_num;
	strcpy(g_root_path, root_path);
	pthread_rwlock_init(&g_hash_lock, NULL);
}

int domain_keyword_run()
{
	DIR *dirp;
	int domain_num;
	int i, temp_len;
	char charset_path[256];
	char keyword_path[256];
	char temp_domain[256];
	struct dirent *direntp;
	KEYWORD_ENGINE *pengine;

	dirp = opendir(g_root_path);
	if (NULL == dirp) {
		printf("[domain_keyword]: failed to open directory %s: %s\n",
			g_root_path, strerror(errno));
		return -1;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..") ||
			0 == strcmp(direntp->d_name, "charset.txt")) {
			continue;
		}
		domain_num ++;
	}
	g_hash_cap = domain_num + g_growing_num;
	g_hash_table = str_hash_init(g_hash_cap, sizeof(void*), NULL);
	if (NULL == g_hash_table) {
		closedir(dirp);
		printf("[domain_keyword]: fail to init hash table\n");
		return -2;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..") ||
			0 == strcmp(direntp->d_name, "charset.txt")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		if (temp_len <= 4 && 0 != strcasecmp(temp_domain +
			temp_len - 4, ".txt")) {
			continue;
		}
		temp_domain[temp_len - 4] = '\0';
		for (i=0; i<temp_len-4; i++) {
			if (HX_isupper(temp_domain[i]))
				break;
		}
		if (i < temp_len - 4) {
			continue;
		}
		
		sprintf(charset_path, "%s/charset.txt", g_root_path);
		sprintf(keyword_path, "%s/%s", g_root_path, direntp->d_name);
		pengine = keyword_engine_init(charset_path, keyword_path);
		if (NULL != pengine) {
			str_hash_add(g_hash_table, temp_domain, &pengine);
		}
	}
	closedir(dirp);
	return 0;	
}

BOOL domain_keyword_check(const char *from, MEM_FILE *pf_rcpt_to,
	const char *charset, const char *buff, int length)
{
	char *rcpt_domain;
	char temp_rcpt[256];
	char from_domain[256];
	KEYWORD_ENGINE **ppengine;

	strcpy(from_domain, strchr(from, '@') + 1);
	HX_strlower(from_domain);
	pthread_rwlock_rdlock(&g_hash_lock);
	/* query the hash table */
	ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, from_domain);
	if (NULL != ppengine) {
		if (NULL != keyword_engine_match(*ppengine, charset, buff, length)) {
			pthread_rwlock_unlock(&g_hash_lock);
			return FALSE;
		}
	}
	mem_file_seek(pf_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(pf_rcpt_to, temp_rcpt, 256)) {
		HX_strlower(temp_rcpt);
		rcpt_domain = strchr(temp_rcpt, '@') + 1;
		ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, rcpt_domain);
		if (NULL != ppengine) {
			if (NULL != keyword_engine_match(*ppengine, charset, buff, length)) {
				pthread_rwlock_unlock(&g_hash_lock);
				return FALSE;
			}	
		}
	}
	pthread_rwlock_unlock(&g_hash_lock);
	return TRUE;
}

int domain_keyword_stop()
{
	STR_HASH_ITER *iter;
	KEYWORD_ENGINE **ppengine;
	
	if (NULL != g_hash_table) {
		iter = str_hash_iter_init(g_hash_table);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppengine = (KEYWORD_ENGINE**)str_hash_iter_get_value(iter, NULL);
			keyword_engine_free(*ppengine);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	return 0;
}

void domain_keyword_free()
{
	g_root_path[0] = '\0';
	pthread_rwlock_destroy(&g_hash_lock);
}


static void domain_keyword_remove(const char *domain)
{
	char temp_domain[256];
	char temp_path[256];
	KEYWORD_ENGINE **ppengine;

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	pthread_rwlock_wrlock(&g_hash_lock);
	ppengine= (KEYWORD_ENGINE**)str_hash_query(g_hash_table, temp_domain);
	if (NULL != ppengine) {
		keyword_engine_free(*ppengine);
		str_hash_remove(g_hash_table, temp_domain);
	}
	pthread_rwlock_unlock(&g_hash_lock);
	sprintf(temp_path, "%s/%s.txt", g_root_path, domain);
	remove(temp_path);
}

static int domain_keyword_add(const char *domain)
{
	STR_HASH_TABLE *phash;
	STR_HASH_ITER *iter;
	char temp_buff[256];
	char temp_domain[256];
	char charset_path[256];
	char keyword_path[256];
	KEYWORD_ENGINE *pengine;
	KEYWORD_ENGINE **ppengine;

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	sprintf(charset_path, "%s/charset.txt", g_root_path);
	sprintf(keyword_path, "%s/%s.txt", g_root_path, temp_domain);
	pengine = keyword_engine_init(charset_path, keyword_path);
	if (NULL == pengine) {
		printf("[domain_keyword]: fail to init keyword engine from file %s\n",
			keyword_path);
		return DOMAIN_KEYWORD_FILE_FAIL;
	}
	pthread_rwlock_wrlock(&g_hash_lock);
	ppengine = (KEYWORD_ENGINE**)str_hash_query(g_hash_table, temp_domain);
	if (NULL != ppengine) {
		keyword_engine_free(*ppengine);
		str_hash_remove(g_hash_table, temp_domain);
	}
	if (str_hash_add(g_hash_table, temp_domain, &pengine) > 0) {
		pthread_rwlock_unlock(&g_hash_lock);
		return DOMAIN_KEYWORD_ADD_OK;
	}
	phash = str_hash_init(g_hash_cap + g_growing_num, sizeof(SINGLE_LIST), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_hash_lock);
		keyword_engine_free(pengine);
		return DOMAIN_KEYWORD_HASH_FAIL;
	}
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		ppengine = (KEYWORD_ENGINE**)str_hash_iter_get_value(iter, temp_buff);
		str_hash_add(phash, temp_buff, ppengine);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_hash_table);
	g_hash_table = phash;
	str_hash_add(g_hash_table, temp_domain, &pengine);
	g_hash_cap += g_growing_num;
	pthread_rwlock_unlock(&g_hash_lock);
	return DOMAIN_KEYWORD_ADD_OK;
}


void domain_keyword_console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 domain keyword help information:\r\n"
						 "\t%s add <domain>\r\n"
						 "\t    --add domain keyword into table\r\n"
						 "\t%s remove <domain>\r\n"
						 "\t    --remove domain keyword from table";
	
	if (1 == argc) {
	    strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		switch (domain_keyword_add(argv[2])) {
		case DOMAIN_KEYWORD_ADD_OK:
			snprintf(result, length, "250 add domain keyword %s into table OK",
				argv[2]);
			break;
		case DOMAIN_KEYWORD_FILE_FAIL:
			snprintf(result, length, "550 fail to open list file of "
				"domain %s in directory", argv[2]);
			break;
		case DOMAIN_KEYWORD_HASH_FAIL:
			snprintf(result, length, "550 fail to add keyword list of "
				"domain %s into hash table", argv[2]);
			break;
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		domain_keyword_remove(argv[2]);
		snprintf(result, length, "250 remove domain %s from hash table OK",
			argv[2]);
		return;
	}

	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;

}



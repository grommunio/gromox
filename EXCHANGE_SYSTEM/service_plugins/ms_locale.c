// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <errno.h>
#include <stdbool.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/svc_common.h>
#include "list_file.h"
#include "int_hash.h"
#include "str_hash.h"
#include "util.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct _CPID_ITEM {
	uint32_t cpid;
	char charset[64];
} CPID_ITEM;

DECLARE_API;

static INT_HASH_TABLE *g_cpid_hash;
static INT_HASH_TABLE *g_lcid_hash;
static STR_HASH_TABLE *g_ltag_hash;
static STR_HASH_TABLE *g_charset_hash;

static pthread_mutex_t g_cpid_lock;
static pthread_mutex_t g_lcid_lock;
static pthread_mutex_t g_ltag_lock;
static pthread_mutex_t g_charset_lock;

static BOOL verify_cpid(uint32_t cpid)
{
	if (65000 == cpid || 65001 == cpid || 1200 == cpid ||
		1200 == cpid || 12000 == cpid || 12001 == cpid) {
		return FALSE;	
	}
	pthread_mutex_lock(&g_cpid_lock);
	if (NULL != int_hash_query(g_cpid_hash, cpid)) {
		pthread_mutex_unlock(&g_cpid_lock);
		return TRUE;
	}
	pthread_mutex_unlock(&g_cpid_lock);
	return FALSE;
}

static const char* cpid_to_charset(uint32_t cpid)
{
	const char *charset;
	
	pthread_mutex_lock(&g_cpid_lock);
	charset = int_hash_query(g_cpid_hash, cpid);
	pthread_mutex_unlock(&g_cpid_lock);
	return charset;
}

static uint32_t charset_to_cpid(const char *charset)
{
	uint32_t *pcpid;
	char tmp_charset[32];
	
	strcpy(tmp_charset, charset);
	HX_strlower(tmp_charset);
	pthread_mutex_lock(&g_charset_lock);
	pcpid = str_hash_query(g_charset_hash, tmp_charset);
	pthread_mutex_unlock(&g_charset_lock);
	if (NULL == pcpid) {
		return 0;
	} else {
		return *pcpid;
	}
}

static uint32_t ltag_to_lcid(const char *lang_tag)
{
	uint32_t *plcid;
	char tmp_ltag[32];
	
	strncpy(tmp_ltag, lang_tag, sizeof(tmp_ltag));
	HX_strlower(tmp_ltag);
	pthread_mutex_lock(&g_ltag_lock);
	plcid = str_hash_query(g_ltag_hash, tmp_ltag);
	pthread_mutex_unlock(&g_ltag_lock);
	if (NULL != plcid) {
		return *plcid;
	}
	return 0;
}

static const char* lcid_to_ltag(uint32_t lcid)
{
	const char *pltag;
	
	pthread_mutex_lock(&g_lcid_lock);
	pltag = int_hash_query(g_lcid_hash, lcid);
	pthread_mutex_unlock(&g_lcid_lock);
	return pltag;
}


BOOL SVC_LibMain(int reason, void **ppdata)
{
	int i;
	int item_num;
	uint32_t lcid;
	LIST_FILE *pfile;
	char tmp_path[256];
	CPID_ITEM *pcpid_item;
	
	
	switch(reason) {
	case PLUGIN_INIT: {
		LINK_API(ppdata);
		
		pthread_mutex_init(&g_cpid_lock, NULL);
		pthread_mutex_init(&g_lcid_lock, NULL);
		pthread_mutex_init(&g_ltag_lock, NULL);
		pthread_mutex_init(&g_charset_lock, NULL);
		
		sprintf(tmp_path, "%s/cpid.txt", get_data_path());
		pfile = list_file_init3(tmp_path, "%d%s:64", false);
		if (NULL == pfile) {
			printf("[ms_locale]: list_file_init %s: %s\n",
				tmp_path, strerror(errno));
			return FALSE;
		}
		item_num = list_file_get_item_num(pfile);
		pcpid_item = list_file_get_list(pfile);
		g_cpid_hash = int_hash_init(item_num + 1, 64);
		if (NULL == g_cpid_hash) {
			printf("[ms_locale]: Failed to init cpid hash table\n");
			list_file_free(pfile);
			return FALSE;
		}
		g_charset_hash = str_hash_init(item_num + 1, sizeof(uint32_t), NULL);
		if (NULL == g_charset_hash) {
			printf("[ms_locale]: Failed to init charset hash table\n");
			list_file_free(pfile);
			return FALSE;
		}
		for (i=0; i<item_num; i++) {
			HX_strlower(pcpid_item[i].charset);
			if (1 != int_hash_add(g_cpid_hash,
				pcpid_item[i].cpid, pcpid_item[i].charset)) {
				printf("[ms_locale]: fail to add item into cpid hash\n");
			}
			if (1 != str_hash_add(g_charset_hash,
				pcpid_item[i].charset, &pcpid_item[i].cpid)) {
				printf("[ms_locale]: fail to add item into charset hash\n");
			}
		}
		list_file_free(pfile);
		sprintf(tmp_path, "%s/lcid.txt", get_data_path());
		struct srcitem { char lcid[16], locale[32]; };
		pfile = list_file_init(tmp_path, "%s:16%s:32");
		if (NULL == pfile) {
			printf("[ms_locale]: list_file_init %s: %s\n",
				tmp_path, strerror(errno));
			return FALSE;
		}
		item_num = list_file_get_item_num(pfile);
		printf("[ms_locale]: lcid.txt contains %d items\n", item_num);
		struct srcitem *pitem = reinterpret_cast(struct srcitem *, list_file_get_list(pfile));
		g_lcid_hash = int_hash_init(item_num + 1, 32);
		if (NULL == g_lcid_hash) {
			printf("[ms_locale]: Failed to init lcid hash table\n");
			list_file_free(pfile);
			return FALSE;
		}
		g_ltag_hash = str_hash_init(item_num + 1, sizeof(uint32_t), NULL);
		if (NULL == g_ltag_hash) {
			printf("[ms_locale]: Failed to init ltag hash table\n");
			list_file_free(pfile);
			return FALSE;
		}
		for (i=0; i<item_num; i++) {
			if (strncasecmp(pitem[i].lcid, "0x", 2) != 0) {
				printf("[ms_locale]: lcid %s is not "
					"in hex string\n", pitem[i].lcid);
				continue;
			}
			lcid = strtol(pitem[i].lcid + 2, nullptr, 16);
			HX_strlower(pitem[i].locale);
			if (str_hash_add(g_ltag_hash, pitem[i].locale, &lcid) != 1)
				printf("[ms_locale]: fail to add item into ltag hash\n");
			if (NULL != int_hash_query(g_lcid_hash, lcid)) {
				continue;
			}
			if (int_hash_add(g_lcid_hash, lcid, pitem[i].locale) != 1)
				printf("[ms_locale]: fail to add item into lcid hash\n");
		}
		list_file_free(pfile);
		printf("[ms_locale]: loaded %zu locale IDs\n", g_lcid_hash->item_num);
		printf("[ms_locale]: loaded %zu locale names\n", g_ltag_hash->item_num);
		if (FALSE == register_service("verify_cpid", verify_cpid)) {
			printf("[ms_locale]: failed to register \"verify_cpid\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("cpid_to_charset", cpid_to_charset)) {
			printf("[ms_locale]: failed to register \"cpid_to_charset\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("charset_to_cpid", charset_to_cpid)) {
			printf("[ms_locale]: failed to register \"charset_to_cpid\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("ltag_to_lcid", ltag_to_lcid)) {
			printf("[ms_locale]: failed to register \"ltag_to_lcid\" service\n");
			return FALSE;
		}
		if (FALSE == register_service("lcid_to_ltag", lcid_to_ltag)) {
			printf("[ms_locale]: failed to register \"lcid_to_ltag\" service\n");
			return FALSE;
		}
		printf("[ms_locale]: plugin is loaded into system\n");
		return TRUE;
	}
	case PLUGIN_FREE:
		if (NULL != g_lcid_hash) {
			int_hash_free(g_lcid_hash);
			g_lcid_hash = NULL;
		}
		if (NULL != g_ltag_hash) {
			str_hash_free(g_ltag_hash);
			g_ltag_hash = NULL;
		}
		if (NULL != g_cpid_hash) {
			int_hash_free(g_cpid_hash);
			g_cpid_hash = NULL;
		}
		if (NULL != g_charset_hash) {
			str_hash_free(g_charset_hash);
			g_charset_hash = NULL;
		}
		pthread_mutex_destroy(&g_cpid_lock);
		pthread_mutex_destroy(&g_lcid_lock);
		pthread_mutex_destroy(&g_ltag_lock);
		pthread_mutex_destroy(&g_charset_lock);
		return TRUE;
	}
	return false;
}

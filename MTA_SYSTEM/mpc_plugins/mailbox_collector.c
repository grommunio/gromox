#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/hook_common.h>
#include "util.h"
#include "str_hash.h"
#include "list_file.h"
#include <pthread.h>


typedef BOOL (*CHECK_USER)(const char*, char *path);

enum{
	REFRESH_OK,
	REFRESH_FILE_ERROR,
	REFRESH_HASH_FAIL
};

static char g_list_path[256];
static STR_HASH_TABLE *g_hash_table;
static pthread_rwlock_t g_table_lock;


static CHECK_USER check_user;
static int collector_refresh(void);
static BOOL collector_query(const char *domain, char *fwd_mailbox);

static BOOL collector_hook(MESSAGE_CONTEXT *pcontext);

static void console_talk(int argc, char **argv, char *result, int length);


DECLARE_API;

BOOL HOOK_LibMain(int reason, void **ppdata)
{
    char file_name[256];
    char *psearch;

	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);

		check_user = (CHECK_USER)query_service("check_user");
		if (NULL == check_user) {
			printf("[mailbox_collector]: failed to get service \"check_user\"\n");
			return FALSE;
		}
		/* get the plugin name from system api */
        strcpy(file_name, get_plugin_name());
        psearch = strrchr(file_name, '.');
        if (NULL != psearch) {
            *psearch = '\0';
        }
        sprintf(g_list_path, "%s/%s.txt", get_data_path(), file_name);
		g_hash_table = NULL;
		pthread_rwlock_init(&g_table_lock, NULL);
		
		if (REFRESH_OK != collector_refresh()) {
			printf("[mailbox_collector]: fail to load collector list\n");
			return FALSE;
		}
		
		register_talk(console_talk);
        if (FALSE == register_hook(collector_hook)) {
			printf("[mailbox_collector]: failed to register the hook function\n");
            return FALSE;
        }
        return TRUE;
    case PLUGIN_FREE:
		if (NULL != g_hash_table) {
			str_hash_free(g_hash_table);
			g_hash_table = NULL;
		}
		pthread_rwlock_destroy(&g_table_lock);
        return TRUE;
    }
	return false;
}


static int collector_refresh()
{
	int i, item_num;
	LIST_FILE *plist;
	STR_HASH_TABLE *phash, *phash_temp;
	struct srcitem { char a[256], b[256]; };

	plist = list_file_init(g_list_path, "%s:256%s:256");
	if (NULL == plist) {
		printf("[mailbox_collector]: list_file_init %s: %s\n",
			g_list_path, strerror(errno));
		return REFRESH_FILE_ERROR;
	}
	item_num = list_file_get_item_num(plist);
	phash = str_hash_init(item_num + 1, 256, NULL);
	if (NULL == phash) {
		printf("[mailbox_collector]: fail to init hash table\n", g_list_path);
		list_file_free(plist);
		return REFRESH_HASH_FAIL;
	}
	struct srcitem *pitem = reinterpret_cast(struct srcitem *, list_file_get_list(plist));
	for (i=0; i<item_num; i++) {
		HX_strlower(pitem[i].a);
		str_hash_add(phash, pitem[i].a, pitem[i].b);
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

static BOOL collector_query(const char *domain, char *fwd_mailbox)
{
	char *presult;
	char temp_domain[256];

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	pthread_rwlock_rdlock(&g_table_lock);
	presult = str_hash_query(g_hash_table, temp_domain);
	if (NULL == presult) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	} else {
		strcpy(fwd_mailbox, presult);
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
}

static BOOL collector_hook(MESSAGE_CONTEXT *pcontext)
{
	BOOL b_found;
	char *pdomain;
	char rcpt_to[256];
	char fwd_mailbox[256];
	MEM_FILE temp_file;

	if (BOUND_IN != pcontext->pcontrol->bound_type &&
		BOUND_OUT != pcontext->pcontrol->bound_type &&
		BOUND_RELAY != pcontext->pcontrol->bound_type) {
		return FALSE;
	}

	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	
	b_found = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL != pdomain) {
			pdomain ++;
			if (TRUE == collector_query(pdomain, fwd_mailbox) &&
				FALSE == check_user(rcpt_to, NULL)) {
				b_found = TRUE;
				mem_file_writeline(&temp_file, fwd_mailbox);
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
				"rectify %s to %s", pcontext->pcontrol->queue_ID,
				pcontext->pcontrol->from, rcpt_to, rcpt_to, fwd_mailbox);
				continue;
			}
		}
		mem_file_writeline(&temp_file, rcpt_to);
	}
	if (TRUE == b_found) {
		mem_file_copy(&temp_file, &pcontext->pcontrol->f_rcpt_to);
	}
	mem_file_free(&temp_file);
	return FALSE;		
}

static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 mailbox collector help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the table from list file";
	
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		switch(collector_refresh()) {
		case REFRESH_OK:
			strncpy(result, "250 collector table reload OK", length);
			return;
		case REFRESH_FILE_ERROR:
			strncpy(result, "550 collector list file error", length);
			return;
		case REFRESH_HASH_FAIL:
			strncpy(result, "550 hash map error for collector table", length);
			return;
		}
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


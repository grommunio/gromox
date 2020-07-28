#include <errno.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include "domain_mailbox.h"
#include "util.h"
#include "str_hash.h"
#include "list_file.h"
#include <pthread.h>

static char g_list_path[256];
static STR_HASH_TABLE *g_hash_table;
static pthread_rwlock_t g_table_lock;

static BOOL domain_mailbox_refresh_table(void);
static BOOL domain_mailbox_query(const char *domain, char *fwd_mailbox);

void domain_mailbox_init(const char *path)
{
	strcpy(g_list_path, path);
	g_hash_table = NULL;
	pthread_rwlock_init(&g_table_lock, NULL);
}

int domain_mailbox_run()
{
	if (FALSE == domain_mailbox_refresh_table()) {
		return -1;
	}
	return 0;

}

static BOOL domain_mailbox_refresh_table()
{
	int i, item_num;
	LIST_FILE *plist;
	STR_HASH_TABLE *phash, *phash_temp;
	struct srcitem { char a[256], b[256]; };

	plist = list_file_init3(g_list_path, "%s:256%s:256", false);
	if (NULL == plist) {
		printf("[domain_mailbox]: list_file_init %s: %s\n",
			g_list_path, strerror(errno));
		return FALSE;
	}
	item_num = list_file_get_item_num(plist);
	phash = str_hash_init(item_num + 1, 256, NULL);
	if (NULL == phash) {
		printf("[domain_mailbox]: fail to init hash table\n", g_list_path);
		list_file_free(plist);
		return FALSE;
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
	return TRUE;
}

static BOOL domain_mailbox_query(const char *domain, char *fwd_mailbox)
{
	char *presult;
	char temp_domain[256];

	strcpy(temp_domain, domain);
	HX_strlower(temp_domain);
	pthread_rwlock_rdlock(&g_table_lock);
	if (NULL == g_hash_table) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
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

int domain_mailbox_stop()
{
	if (NULL != g_hash_table) {
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	return 0;
}

void domain_mailbox_free()
{
	g_list_path[0] = '\0';
	pthread_rwlock_destroy(&g_table_lock);
}

BOOL domain_mailbox_hook(MESSAGE_CONTEXT *pcontext)
{
	MEM_FILE tmp_file;
	BOOL b_found, b_outbound;
	char *pdomain, *pdomain1;
	char rcpt_to[256], fwd_mailbox[256];

	
	b_found = FALSE;
	b_outbound = FALSE;
	mem_file_init(&tmp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL == pdomain) {
			mem_file_writeline(&tmp_file, rcpt_to);
			continue;
		}
		pdomain ++;
		if (TRUE == domain_mailbox_query(pdomain, fwd_mailbox)) {
			pdomain1 = strchr(fwd_mailbox, '@');
			if (NULL == pdomain1) {
				mem_file_writeline(&tmp_file, rcpt_to);
				continue;			
			}
			b_found = TRUE;
			pdomain1 ++;
			if (0 != strcasecmp(pdomain, pdomain1)) {
				b_outbound = TRUE;
			}
			
			if (BOUND_IN == pcontext->pcontrol->bound_type ||
				BOUND_OUT == pcontext->pcontrol->bound_type ||
				BOUND_RELAY == pcontext->pcontrol->bound_type) {
				log_info(8, "SMTP message queue-ID: %d, FROM: %s, TO: %s  "
					" redirect domain %s's message to %s",
					pcontext->pcontrol->queue_ID,
					pcontext->pcontrol->from, rcpt_to, pdomain, fwd_mailbox);
			} else {
				log_info(8, "APP created message FROM: %s, TO: %s  "
					" redirect domain %s's message to %s",
					pcontext->pcontrol->from, rcpt_to, pdomain, fwd_mailbox);
			}
			mem_file_writeline(&tmp_file, fwd_mailbox);
		} else {
			mem_file_writeline(&tmp_file, rcpt_to);
		}
	}
	if (FALSE == b_found) {
		mem_file_free(&tmp_file);
		return FALSE;
	}
	mem_file_copy(&tmp_file, &pcontext->pcontrol->f_rcpt_to);
	mem_file_free(&tmp_file);
	if (TRUE == b_outbound && BOUND_IN == pcontext->pcontrol->bound_type) {
		pcontext->pcontrol->bound_type = BOUND_OUT;
	}
	return FALSE;
	
}

void domain_mailbox_console_talk(int argc, char **argv, char *result,
	int length)
{
	char help_string[] = "250 domain mailbox help information:\r\n"
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
		if (TRUE == domain_mailbox_refresh_table()) {
			strncpy(result, "250 table reload OK", length);
		} else {
			strncpy(result, "550 fail to reload table", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


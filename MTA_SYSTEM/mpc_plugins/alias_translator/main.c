#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <gromox/hook_common.h>
#include "str_hash.h"
#include "list_file.h"
#include "util.h"
#include <stdarg.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

DECLARE_API;

enum{
	REFRESH_OK,
	REFRESH_FILE_ERROR,
	REFRESH_HASH_FAIL
};

struct addritem {
	char a[256], b[256];
};

static STR_HASH_TABLE *g_domain_hash;
static STR_HASH_TABLE *g_address_hash;
static pthread_rwlock_t g_domain_lock;
static pthread_rwlock_t g_address_lock;
static char g_domain_path[256];
static char g_address_path[256];

static int domain_table_refresh(void);
static int address_table_refresh(void);
static BOOL domain_table_query(const char *aliasname, char *mainname);

static BOOL address_table_query(const char *aliasname, char *mainname);

static void console_talk(int argc, char **argv, char *result, int length);
static void alias_log_info(MESSAGE_CONTEXT *pcontext, int level, const char *format, ...);
static BOOL mail_hook(MESSAGE_CONTEXT *pcontext);

BOOL HOOK_LibMain(int reason, void **ppdata)
{
	
	/* path contains the config files directory */
    switch (reason) {
    case PLUGIN_INIT:
		LINK_API(ppdata);
		
		sprintf(g_domain_path, "%s/alias_domains.txt", get_data_path());
		sprintf(g_address_path, "%s/alias_addresses.txt", get_data_path());
		
		pthread_rwlock_init(&g_domain_lock, NULL);
		pthread_rwlock_init(&g_address_lock, NULL);
		
		g_domain_hash = NULL;
		g_address_hash = NULL;

		if (REFRESH_OK != domain_table_refresh()) {
			printf("[alias_translator]: fail to load domain alias table\n");
		}
		if (REFRESH_OK != address_table_refresh()) {
			printf("[alias_translator]: fail to load address alias table\n");
			return FALSE;
		}
        if (FALSE == register_hook(mail_hook)) {
			printf("[alias_translator]: failed to register the hook function\n");
            return FALSE;
        }
		register_talk(console_talk);
		printf("[alias_translator]: plugin is loaded into system\n");
        return TRUE;
    case PLUGIN_FREE:
    	if (NULL != g_domain_hash) {
        	str_hash_free(g_domain_hash);
        	g_domain_hash = NULL;
    	}
		
		if (NULL != g_address_hash) {
			str_hash_free(g_address_hash);
			g_address_hash = NULL;
		}
    	pthread_rwlock_destroy(&g_domain_lock);
    	pthread_rwlock_destroy(&g_address_lock);
        return TRUE;
    }
	return false;
}

static BOOL mail_hook(MESSAGE_CONTEXT *pcontext)
{
	BOOL b_replaced;
	char *pdomain;
	char rcpt_to[256];
	char mainname[256];
	MEM_FILE temp_file;
	MEM_FILE rcpt_file;

	if (pcontext->pcontrol->bound_type >= BOUND_SELF) {
		return FALSE;
	}

	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_init(&rcpt_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_copy(&pcontext->pcontrol->f_rcpt_to, &rcpt_file);
	
	pdomain = strchr(pcontext->pcontrol->from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		if (TRUE == domain_table_query(pdomain, mainname)) {
			alias_log_info(pcontext, 8, "replace alias from-domain "
				"from %s to %s", pdomain, mainname);
			strcpy(pdomain, mainname);
		}
		if (TRUE == address_table_query(pcontext->pcontrol->from, mainname)) {
			alias_log_info(pcontext, 8, "replace alias from-address "
					"from %s to %s", pcontext->pcontrol->from, mainname);
			strcpy(pcontext->pcontrol->from, mainname);
		}
	}

	b_replaced = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&rcpt_file, rcpt_to, 256)) {
		pdomain = strchr(rcpt_to, '@');
		if (NULL != pdomain) {
			pdomain ++;
			if (TRUE == domain_table_query(pdomain, mainname)) {
				alias_log_info(pcontext, 8, "replace alias rcpt-domain "
					"from %s to %s", pdomain, mainname);
				strcpy(pdomain, mainname);
				b_replaced = TRUE;
			}
			if (TRUE == address_table_query(rcpt_to, mainname)) {
				alias_log_info(pcontext, 8, "replace alias rcpt-address "
						"from %s to %s", rcpt_to, mainname);
				strcpy(rcpt_to, mainname);
				b_replaced = TRUE;
			}
		}
		mem_file_writeline(&temp_file, rcpt_to);
	}
	if (TRUE == b_replaced) {
		mem_file_copy(&temp_file, &pcontext->pcontrol->f_rcpt_to);
	}
	mem_file_free(&temp_file);
	mem_file_free(&rcpt_file);

	
	return FALSE;
}

static void alias_log_info(MESSAGE_CONTEXT *pcontext, int level,
    const char *format, ...)
{
	char log_buf[2048], rcpt_buff[2048];
	size_t size_read = 0, rcpt_len = 0, i;
	va_list ap;

	va_start(ap, format);
	vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
	log_buf[sizeof(log_buf) - 1] = '\0';

	/* maximum record 8 rcpt to address */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	for (i=0; i<8; i++) {
		size_read = mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
						rcpt_buff + rcpt_len, 256);
		if (size_read == MEM_END_OF_FILE) {
			break;
		}
		rcpt_len += size_read;
		rcpt_buff[rcpt_len] = ' ';
		rcpt_len ++;
	}
	rcpt_buff[rcpt_len] = '\0';

	switch (pcontext->pcontrol->bound_type) {
	case BOUND_IN:
	case BOUND_OUT:
	case BOUND_RELAY:
		log_info(level, "SMTP message queue-ID: %d, FROM: %s, TO: %s %s",
			pcontext->pcontrol->queue_ID, pcontext->pcontrol->from,
			rcpt_buff, log_buf);
		break;
	default:
		log_info(level, "APP created message FROM: %s, TO: %s %s",
			pcontext->pcontrol->from, rcpt_buff, log_buf);
		break;
	}
}


BOOL domain_table_query(const char *aliasname, char *mainname)
{
	char *presult;
	char temp_string[256];
	
	strncpy(temp_string, aliasname, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);
	
	pthread_rwlock_rdlock(&g_domain_lock);
	presult = str_hash_query(g_domain_hash, temp_string);
	if (NULL != presult) {
		strcpy(mainname, presult);
	}
	pthread_rwlock_unlock(&g_domain_lock);
	if (NULL != presult) {
        return TRUE;
    } else {
		return FALSE;
	}
}

BOOL address_table_query(const char *aliasname, char *mainname)
{
	char *presult;
	char temp_string[256];
	
	strncpy(temp_string, aliasname, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);
	
	pthread_rwlock_rdlock(&g_address_lock);
	presult = str_hash_query(g_address_hash, temp_string);
	if (NULL != presult) {
		strcpy(mainname, presult);
	}
	pthread_rwlock_unlock(&g_address_lock);
	if (NULL != presult) {
        return TRUE;
    } else {
		return FALSE;
	}
}
	
static int domain_table_refresh()
{
    int i, list_len;
	LIST_FILE *plist_file;
    STR_HASH_TABLE *phash = NULL;
	
    /* initialize the list filter */
	plist_file = list_file_init3(g_domain_path, "%s:256%s:256", false);
	if (NULL == plist_file) {
		printf("[alias_translator]: Failed to read domain list from %s: %s\n",
			g_domain_path, strerror(errno));
		return REFRESH_FILE_ERROR;
	}
	struct addritem *pitem = reinterpret_cast(struct addritem *, list_file_get_list(plist_file));
	list_len = list_file_get_item_num(plist_file);
	
    phash = str_hash_init(list_len + 1, 256, NULL);
	if (NULL == phash) {
		printf("[alias_translator]: fail to allocate domain hash map\n");
		list_file_free(plist_file);
		return REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
		HX_strlower(pitem[i].a);
		str_hash_add(phash, pitem[i].a, pitem[i].b);
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_domain_lock);
	if (NULL != g_domain_hash) {
		str_hash_free(g_domain_hash);
	}
    g_domain_hash = phash;
    pthread_rwlock_unlock(&g_domain_lock);

    return REFRESH_OK;
}

static int address_table_refresh()
{
    int i, list_len;
	LIST_FILE *plist_file;
    STR_HASH_TABLE *phash = NULL;
	
    /* initialize the list filter */
	plist_file = list_file_init3(g_address_path, "%s:256%s:256", false);
	if (NULL == plist_file) {
		printf("[alias_translator]: Failed to read address list from %s: %s\n",
			g_address_path, strerror(errno));
		return REFRESH_FILE_ERROR;
	}
	struct addritem *pitem = reinterpret_cast(struct addritem *, list_file_get_list(plist_file));
	list_len = list_file_get_item_num(plist_file);
	
    phash = str_hash_init(list_len + 1, 256, NULL);
	if (NULL == phash) {
		printf("[alias_translator]: fail to allocate address hash map\n");
		list_file_free(plist_file);
		return REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
		HX_strlower(pitem[i].a);
		str_hash_add(phash, pitem[i].a, pitem[i].b);
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_address_lock);
	if (NULL != g_address_hash) {
		str_hash_free(g_address_hash);
	}
    g_address_hash = phash;
    pthread_rwlock_unlock(&g_address_lock);

    return REFRESH_OK;
}

/*
 *	string table's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
static void console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 alias translator help information:\r\n"
						 "\t%s reload domains\r\n"
						 "\t    --reload domain alias table from list file\r\n"
						 "\t%s reload addresses\r\n"
						 "\t    --reload address alias table from list file";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (3 == argc && 0 == strcmp("reload", argv[1])) {
		if (0 == strcmp("domains", argv[2])) {
			switch(domain_table_refresh()) {
			case REFRESH_OK:
				strncpy(result, "250 domain alias table reload OK", length);
				return;
			case REFRESH_FILE_ERROR:
				strncpy(result, "550 domain alias list file error", length);
				return;
			case REFRESH_HASH_FAIL:
				strncpy(result, "550 hash map error for domain alias table",
					length);
				return;
			}
		} else if (0 == strcmp("addresses", argv[2])) {
			switch(address_table_refresh()) {
			case REFRESH_OK:
				strncpy(result, "250 address alias table reload OK", length);
				return;
			case REFRESH_FILE_ERROR:
				strncpy(result, "550 address alias list file error", length);
				return;
			case REFRESH_HASH_FAIL:
				strncpy(result, "550 hash map error for address alias table",
					length);
				return;
			}
		}
	}
	
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


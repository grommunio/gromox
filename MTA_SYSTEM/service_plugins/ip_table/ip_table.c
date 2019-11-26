#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ip_table.h"
#include "ip4_hash.h"
#include "util.h"
#include "list_file.h"
#include "mail_func.h"
#include <pthread.h>
#include <stdarg.h>

enum{
	IP_TABLE_REFRESH_OK,
	IP_TABLE_REFRESH_FILE_ERROR,
	IP_TABLE_REFRESH_HASH_FAIL
};

static int ip_table_refresh(void);

static char g_module_name[256];
static IP4_HASH_TABLE *g_ip_list_table;
static pthread_rwlock_t g_refresh_lock;
static char g_list_path[256];
static int g_growing_num;
static int g_hash_cap;

/*
 *	ip table's construct function
 */
void ip_table_init(const char *module_name, const char *path, int growing_num)
{
	strcpy(g_module_name, module_name);
	strcpy(g_list_path, path);
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

/*
 *	ip table's destruct function
 */
void ip_table_free()
{
	g_list_path[0] = '\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

/*
 *	run ip table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int ip_table_run()
{
    pthread_rwlock_init(&g_refresh_lock, NULL);
    if (IP_TABLE_REFRESH_OK != ip_table_refresh()) {
        return -1;
    }
    return 0;
}

/*
 *	stop ip table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int ip_table_stop()
{
    if (NULL != g_ip_list_table) {
        ip4_hash_free(g_ip_list_table);
        g_ip_list_table = NULL;
    }
    pthread_rwlock_destroy(&g_refresh_lock);
    return 0;
}

/*
 *  check if the specified ip is in the table
 *
 *  @param
 *      ip [in]     the checked ip address
 *
 *  @return
 *      TRUE        allow
 *      FALSE       disallow
 */
BOOL ip_table_query(const char* ip)
{
	if (NULL == ip) {
		return FALSE;
	}
	pthread_rwlock_rdlock(&g_refresh_lock);
    if (NULL != ip4_hash_query(g_ip_list_table, (char*)ip)) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return TRUE;
    }
	pthread_rwlock_unlock(&g_refresh_lock);
    return FALSE;
}

/*
 *  refresh the ip list, the list is from the
 *  file which is specified in configuration file.
 *
 *  @return
 *		IP_TABLE_REFRESH_OK				OK
 *		IP_TABLE_REFRESH_FILE_ERROR		fail to open list file
 *		IP_TABLE_REFRESH_HASH_FAIL		fail to open hash map
 */
static int ip_table_refresh()
{
    IP4_HASH_TABLE *phash = NULL;
    int i, list_len, hash_cap;
	LIST_FILE *plist_file;
	char *pitem;
	
    /* initialize the list filter */
	plist_file = list_file_init3(g_list_path, "%s:16", false);
	if (NULL == plist_file) {
		ip_table_echo("list_file_init %s: %s",
			g_list_path, strerror(errno));
		return IP_TABLE_REFRESH_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + g_growing_num;
	
    phash = ip4_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		ip_table_echo("fail to allocate hash map");
		list_file_free(plist_file);
		return IP_TABLE_REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
        ip4_hash_add(phash, pitem + 16*i, &i);   
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_refresh_lock);
	if (NULL != g_ip_list_table) {
		ip4_hash_free(g_ip_list_table);
	}
    g_ip_list_table = phash;
	g_hash_cap = hash_cap;
    pthread_rwlock_unlock(&g_refresh_lock);

    return IP_TABLE_REFRESH_OK;
}

/*
 *	add item into ip file and hash table
 *  @param
 *		ip [in]        ip to be added
 *  @return
 *		TRUE            OK
 *      FALSE           fail
 */
BOOL ip_table_add(const char* ip)
{
	int dummy_val = 0;
	int hash_cap, fd, ip_len;
	char temp_key[17];
	IP4_HASH_ITER *iter;
	IP4_HASH_TABLE *phash;

	if (NULL == ip) {
		return FALSE;
	}
	ip_len = strlen(ip);
	memcpy(temp_key, ip, ip_len);
	temp_key[ip_len] = '\n';
	ip_len ++;
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the ip is already in the table */
	if (NULL != ip4_hash_query(g_ip_list_table, (char*)ip)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	if (ip_len != write(fd, temp_key, ip_len)) {
		close(fd);
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	close(fd);
	if (ip4_hash_add(g_ip_list_table, (char*)ip, &dummy_val) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + g_growing_num;
	phash = ip4_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = ip4_hash_iter_init(g_ip_list_table);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		ip4_hash_iter_get_value(iter, temp_key);
		ip4_hash_add(phash, temp_key, &dummy_val);
	}
	ip4_hash_iter_free(iter);
	ip4_hash_free(g_ip_list_table);
	g_ip_list_table = phash;
	g_hash_cap = hash_cap;
	if (ip4_hash_add(g_ip_list_table, (char*)ip, &dummy_val) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	pthread_rwlock_unlock(&g_refresh_lock);
	return FALSE;
}

/*
 *  remove item from ip file and hash table
 *  @param
 *      ip [in]        ip to be removed
 *  @return
 *      TRUE            OK
 *      FALSE           fail
 */
BOOL ip_table_remove(const char *ip)
{
	int fd, ip_len;
	char temp_key[17];
	IP4_HASH_ITER *iter;

	if (NULL == ip) {
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the ip is in hash table */
	if (NULL == ip4_hash_query(g_ip_list_table, (char*)ip)) {
		return TRUE;
	}
	if (1 != ip4_hash_remove(g_ip_list_table, (char*)ip)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = ip4_hash_iter_init(g_ip_list_table);
	for (ip4_hash_iter_begin(iter); FALSE == ip4_hash_iter_done(iter);
		ip4_hash_iter_forward(iter)) {
		ip4_hash_iter_get_value(iter, temp_key);
		ip_len = strlen(temp_key);
		temp_key[ip_len] = '\n';
		ip_len ++;
		write(fd, temp_key, ip_len);
	}
	ip4_hash_iter_free(iter);
	close(fd);
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

/*
 *	ip table's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
void ip_table_console_talk(int argc, char **argv, char *result, int length)
{
	char ip[16];
	
	char help_string[] = "250 ip table help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the ip table from list file\r\n"
						 "\t%s add <ip>\r\n"
						 "\t    --add ip to ip table\r\n"
						 "\t%s remove <ip>\r\n"
						 "\t    --remove ip from the ip table\r\n"
						 "\t%s search <ip>\r\n"
						 "\t    --search ip in the ip table";

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
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		switch(ip_table_refresh()) {
		case IP_TABLE_REFRESH_OK:
			strncpy(result, "250 ip table reload OK", length);
			return;
		case IP_TABLE_REFRESH_FILE_ERROR:
			strncpy(result, "550 ip list file error", length);
			return;
		case IP_TABLE_REFRESH_HASH_FAIL:
			strncpy(result, "550 hash map error for ip table", length);
			return;
		}
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		if (NULL == extract_ip(argv[2], ip)) {
			snprintf(result, length, "550 %s is not ip address", argv[2]);
			return;
		}
		if (TRUE == ip_table_add(ip)) {
			snprintf(result, length, "250 %s is added", ip);
		} else {
			snprintf(result, length, "550 fail to add %s", ip);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		if (NULL == extract_ip(argv[2], ip)) {
			snprintf(result, length, "550 %s is not ip address", argv[2]);
		}
		if (TRUE == ip_table_remove(ip)) {
			snprintf(result, length, "250 %s is removed", ip);
		} else {
			snprintf(result, length, "550 fail to remove %s", ip);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("search", argv[1])) {
		if (NULL == extract_ip(argv[2], ip)) {
			snprintf(result, length, "550 %s is not ip address", argv[2]);
			return;
		}
		if (TRUE == ip_table_query(ip)) {
			snprintf(result, length, "250 %s is found in the ip table", ip);
		} else {
			snprintf(result, length, "550 cannot find %s in the ip table", ip);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

void ip_table_echo(const char *format, ...)
{
	char msg[256];
	va_list ap;

	memset(msg, 0, sizeof(msg));
	va_start(ap, format);
	vsprintf(msg, format, ap);
	printf("[%s]: %s\n", g_module_name, msg);

}



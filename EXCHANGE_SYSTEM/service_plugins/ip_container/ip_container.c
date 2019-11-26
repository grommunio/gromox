#include <unistd.h>
#include "ip_container.h"
#include "ip4_hash.h"
#include "util.h"
#include "list_file.h"
#include "mail_func.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

static IP4_HASH_TABLE* g_container_table = NULL;
static pthread_mutex_t g_container_lock;
static int g_table_size;
static int g_max_num;

/*
 *	ip container's construct function
 */
void ip_container_init(int table_size, int max_num)
{
	g_table_size = table_size;
	g_max_num = max_num;
	pthread_mutex_init(&g_container_lock, NULL);
}

/*
 *	ip container's destruct function
 */
void ip_container_free()
{
	g_table_size = 0;
	g_max_num = 0;
	pthread_mutex_destroy(&g_container_lock);
}

/*
 *	run ip container
 *	@return
 *		 0		success
 *		<>0		fail
 */
int ip_container_run()
{
    g_container_table = ip4_hash_init(g_table_size, sizeof(int), NULL);
	if (NULL == g_container_table) {
		printf("[ip_container]: fail to allocate hash table\n");
		return -1;
	}
    return 0;
}

/*
 *	stop ip container
 *	@return
 *		 0		success
 *		<>0		fail
 */
int ip_container_stop()
{
    if (NULL != g_container_table) {
        ip4_hash_free(g_container_table);
        g_container_table = NULL;
    }
    return 0;
}

/*
 *	add item into ip file and hash container
 *  @param
 *		ip [in]        ip to be added
 *  @return
 *		TRUE            OK
 *      FALSE           fail
 */
BOOL ip_container_add(const char* ip)
{
	int last_num, *pnum;

	if (NULL == ip) {
		return FALSE;
	}
	pthread_mutex_lock(&g_container_lock);
	/* check first if the ip is already in the container */
	pnum = (int*)ip4_hash_query(g_container_table, (char*)ip);
	if (NULL != pnum) {
		if ((*pnum) >= g_max_num) {
			pthread_mutex_unlock(&g_container_lock);
			return FALSE;
		} else {
			(*pnum) ++;
			pthread_mutex_unlock(&g_container_lock);
			return TRUE;
		}
	} else {
		last_num = 1;
		ip4_hash_add(g_container_table, (char*)ip, &last_num);
		pthread_mutex_unlock(&g_container_lock);
		return TRUE;
	}
}

/*
 *  remove item from ip file and hash container
 *  @param
 *      ip [in]        ip to be removed
 *  @return
 *      TRUE            OK
 *      FALSE           fail
 */
BOOL ip_container_remove(const char *ip)
{
	int *pnum;

	if (NULL == ip) {
		return FALSE;
	}
	pthread_mutex_lock(&g_container_lock);
	/* check first if the ip is in hash container */
	pnum = (int*)ip4_hash_query(g_container_table, (char*)ip);
	if (NULL != pnum) {
		(*pnum) --;
		if (0 == (*pnum)) {
			ip4_hash_remove(g_container_table, (char*)ip);
		}
	}
	pthread_mutex_unlock(&g_container_lock);
	return TRUE;
}

/*
 *	ip container's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
void ip_container_console_talk(int argc, char **argv, char *result, int length)
{
	int fd, len, *pnum;
	char ip[16], temp_string[32];
	IP4_HASH_ITER *iter;
	
	char help_string[] = "250 ip container help information:\r\n"
						 "\t%s dump <path>\r\n"
						 "\t    --dump container's content to file\r\n"
						 "\t%s search <ip>\r\n"
						 "\t    --search ip in the ip container";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (3 == argc && 0 == strcmp("dump", argv[1])) {
		fd = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 == fd) {
			snprintf(result, length, "550 fail to dump items to %s", argv[2]);
			return;
		}
		pthread_mutex_lock(&g_container_lock);
		iter = ip4_hash_iter_init(g_container_table);
		for (ip4_hash_iter_begin(iter); !ip4_hash_iter_done(iter);
			ip4_hash_iter_forward(iter)) {
			pnum = ip4_hash_iter_get_value(iter, temp_string);
			len = strlen(temp_string);
			temp_string[len] = '\t';
			len ++;
			len += sprintf(temp_string + len, "%d\n", (*pnum));
			write(fd, temp_string, len);
		}
		ip4_hash_iter_free(iter);
		pthread_mutex_unlock(&g_container_lock);
		close(fd);
		strncpy(result, "250 ip container items dump OK", length);	
		return;
	}
	if (3 == argc && 0 == strcmp("search", argv[1])) {
		if (NULL == extract_ip(argv[2], ip)) {
			snprintf(result, length, "550 %s is not ip address", argv[2]);
			return;
		}
		pthread_mutex_lock(&g_container_lock);
		pnum = (int*)ip4_hash_query(g_container_table, ip);
		if (NULL == pnum) {
			snprintf(result, length, "550 %s is not in the ip container", ip);	
		} else {
			snprintf(result, length, "250 %s in the ip container with "
				"number %d", ip, (*pnum));
		}
		pthread_mutex_unlock(&g_container_lock);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


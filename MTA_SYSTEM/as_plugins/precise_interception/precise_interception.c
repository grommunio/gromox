#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "precise_interception.h"
#include "int_hash.h"
#include "double_list.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

#define TABLE_GROWING_NUM		100
#define DEF_MODE				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct _ATTACHMENT_DATA{
	DOUBLE_LIST_NODE node;
	char             file_name[256];
	char             *ptr;
} ATTACHMENT_DATA;

static char g_path[256];
static int g_hash_cap;
static INT_HASH_TABLE *g_hash_table;
static pthread_rwlock_t g_table_lock;

static BOOL precise_interception_add(const char *file_name);

static BOOL precise_interception_remove(const char *file_name);
static BOOL precise_interception_refresh(void);
static void precise_interception_free_table(INT_HASH_TABLE *ptable);

/*
 *	module's initial function
 *	@param
 *		path [in]				data directory path
 */
void precise_interception_init(const char *path)
{
	strcpy(g_path, path);
	g_hash_table = NULL;
	g_hash_cap = 0;
	pthread_rwlock_init(&g_table_lock, NULL);
}

/*
 *	run the module
 *	@return
 *		0						OK
 *		<>0						fail
 */
int precise_interception_run()
{
	if (FALSE == precise_interception_refresh()) {
		return -1;
	}
	return 0;
}

/*
 *	stop the module
 *	@return
 *		0						OK
 *		<>0						fail
 */
int precise_interception_stop()
{
	if (NULL != g_hash_table) {
		precise_interception_free_table(g_hash_table);
		g_hash_table = NULL;
		g_hash_cap = 0;
	}
	return 0;
}

/*
 *	module's free function
 *	@param
 *		path [in]				data directory path
 */
void precise_interception_free()
{
	g_path[0] = '\0';
	pthread_rwlock_destroy(&g_table_lock);
}

/*
 *	judge if the buffer is in interception list
 *	@param
 *		ptr [in]				buffer pointer
 *		length					length of buffer
 *	@return
 *		TRUE					not in list, OK
 *		FALSE					found in list, cannot pass
 *
 */
BOOL precise_interception_judge(const char* ptr, int length)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	ATTACHMENT_DATA *pdata;

	pthread_rwlock_rdlock(&g_table_lock);
	plist = int_hash_query(g_hash_table, length);
	if (NULL == plist) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pdata = (ATTACHMENT_DATA*)pnode->pdata;
		if (0 == memcmp(pdata->ptr, ptr, length)) {
			pthread_rwlock_unlock(&g_table_lock);
			return FALSE;
		}
	}
	pthread_rwlock_unlock(&g_table_lock);
	return TRUE;
}

static BOOL precise_interception_add(const char *full_name)
{
	int fd, hash_cap, size;
	struct stat node_stat;
	char file_name[256];
	char temp_path[256];
	char dest_path[256];
	char *ptr, *pslash;
	INT_HASH_TABLE *phash;
	INT_HASH_ITER *iter;
	DOUBLE_LIST *plist, *plist_item, temp_list;
	DOUBLE_LIST_NODE *pnode;
	ATTACHMENT_DATA *pdata;

	pslash = strrchr(full_name, '/');
	if (NULL != pslash) {
		strcpy(file_name, pslash + 1);
		strcpy(temp_path, full_name);
		sprintf(dest_path, "%s/%s", g_path, file_name);
	} else {
		strcpy(file_name, full_name);
		sprintf(temp_path, "%s/%s", g_path, file_name);
	}
	if (0 != stat(temp_path, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_table_lock);
	plist = (DOUBLE_LIST*)int_hash_query(g_hash_table, node_stat.st_size);
	if (NULL != plist) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			if (0 == strcmp(((ATTACHMENT_DATA*)pnode->pdata)->file_name,
				file_name)) {
				pthread_rwlock_unlock(&g_table_lock);
				return TRUE;
			}
		}
	}
	ptr = malloc(node_stat.st_size);
	if (NULL == ptr) {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;	
	}
	pdata = (ATTACHMENT_DATA*)malloc(sizeof(ATTACHMENT_DATA));
	if (NULL == pdata) {
		free(ptr);
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	pdata->node.pdata = pdata;
	strcpy(pdata->file_name, file_name);
	pdata->ptr = ptr;
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(pdata);
		free(ptr);
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
		close(fd);
		free(pdata);
		free(ptr);
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
	close(fd);
	if (NULL == plist) {
		double_list_init(&temp_list);
		if (1 != int_hash_add(g_hash_table, node_stat.st_size, &temp_list)) {
			hash_cap = g_hash_cap + TABLE_GROWING_NUM;
			phash = int_hash_init(hash_cap, sizeof(DOUBLE_LIST), NULL);
			if (NULL == phash) {
				free(pdata);
				free(ptr);
				pthread_rwlock_unlock(&g_table_lock);
				return FALSE;
			}
			iter = int_hash_iter_init(g_hash_table);
			for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
				int_hash_iter_forward(iter)) {
				plist_item = int_hash_iter_get_value(iter, &size);
				int_hash_add(phash, size, plist_item);
			}
			int_hash_iter_free(iter);
			precise_interception_free_table(g_hash_table);
			g_hash_table = phash;
			g_hash_cap = hash_cap;
			int_hash_add(g_hash_table, node_stat.st_size, &temp_list);
		}
		plist = (DOUBLE_LIST*)int_hash_query(g_hash_table, node_stat.st_size);
		if (NULL == plist) {
			free(pdata);
			free(ptr);
			pthread_rwlock_unlock(&g_table_lock);
			return FALSE;
		}
	}
	double_list_append_as_tail(plist, &pdata->node);
	pthread_rwlock_unlock(&g_table_lock);
	if (NULL != pslash) {
		fd = open(dest_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
		if (-1 != fd) {
			write(fd, ptr, node_stat.st_size);
			close(fd);
		}
	}
	return TRUE;
}

static BOOL precise_interception_remove(const char *file_name)
{
	struct stat node_stat;
	char temp_path[256];
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;

	sprintf(temp_path, "%s/%s", g_path, file_name);
	if (0 != stat(temp_path, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_table_lock);
	plist = (DOUBLE_LIST*)int_hash_query(g_hash_table, node_stat.st_size);
	if (NULL == plist) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	}
	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		if (0 == strcmp(((ATTACHMENT_DATA*)pnode->pdata)->file_name,
			file_name)) {
			break;
		}
	}
	if (NULL != pnode) {
		double_list_remove(plist, pnode);
		free(((ATTACHMENT_DATA*)pnode->pdata)->ptr);
		free(pnode->pdata);
		if (0 == double_list_get_nodes_num(plist)) {
			double_list_free(plist);
			int_hash_remove(g_hash_table, node_stat.st_size);
		}
		remove(temp_path);
	}
	pthread_rwlock_unlock(&g_table_lock);
	return TRUE;
	
}

static BOOL precise_interception_refresh()
{
	INT_HASH_TABLE *phash, *phash_temp;
	DOUBLE_LIST *plist, temp_list;
	ATTACHMENT_DATA *pdata;
	int fd, count, hash_cap;
	DIR *dirp;
	char *ptr;
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;

	count = 0;
	errno = 0;
	dirp = opendir(g_path);
	if (dirp != NULL) {
		while ((direntp = readdir(dirp)) != NULL) {
			if (strcmp(direntp->d_name, ".") == 0 ||
			    strcmp(direntp->d_name, "..") == 0)
				continue;
			++count;
		}
		closedir(dirp);
	} else if (errno != ENOENT) {
		printf("[precise_interception]: could not open directory %s: %s\n",
			g_path, strerror(errno));
		return false;
	}
	hash_cap = count + TABLE_GROWING_NUM;
	phash = int_hash_init(hash_cap, sizeof(DOUBLE_LIST), NULL);
	if (NULL == phash) {
		return FALSE;
	}
	if (dirp != NULL) {
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", g_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat) ||
			0 == S_ISREG(node_stat.st_mode)) {
			continue;
		}
		ptr = malloc(node_stat.st_size);
		if (NULL == ptr) {
			continue;
		}
		pdata = (ATTACHMENT_DATA*)malloc(sizeof(ATTACHMENT_DATA));
		if (NULL == pdata) {
			free(ptr);
			continue;
		}
		pdata->node.pdata = pdata;
		strcpy(pdata->file_name, direntp->d_name);
		pdata->ptr = ptr;
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			free(pdata);
			free(ptr);
			continue;
		}
		if (node_stat.st_size != read(fd, ptr, node_stat.st_size)) {
			close(fd);
			free(pdata);
			free(ptr);
			continue;
		}
		close(fd);
		plist = (DOUBLE_LIST*)int_hash_query(phash, node_stat.st_size);
		if (NULL == plist) {
			double_list_init(&temp_list);
			int_hash_add(phash, node_stat.st_size, &temp_list);
			plist = (DOUBLE_LIST*)int_hash_query(phash, node_stat.st_size);
		}
		double_list_append_as_tail(plist, &pdata->node);
	}
	closedir(dirp);
	}
	pthread_rwlock_wrlock(&g_table_lock);
	phash_temp = g_hash_table;
	g_hash_table = phash;
	g_hash_cap = hash_cap;
	pthread_rwlock_unlock(&g_table_lock);
	if (NULL != phash_temp) {
		precise_interception_free_table(phash_temp);
	}
	return TRUE;
}

static void precise_interception_free_table(INT_HASH_TABLE *phash)
{
	INT_HASH_ITER *iter;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;

	iter = int_hash_iter_init(phash);
	for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
		int_hash_iter_forward(iter)) {
		plist = int_hash_iter_get_value(iter, NULL);
		while ((pnode = double_list_get_from_head(plist)) != NULL) {
			free(((ATTACHMENT_DATA*)(pnode->pdata))->ptr);
			free(pnode->pdata);
		}
		double_list_free(plist);
	}
	int_hash_iter_free(iter);
	int_hash_free(phash);
}

void precise_interception_console_talk(int argc, char **argv, char *result,
	int length)
{
	char help_string[] = "250 precise interception help information:\r\n"
		                 "\t%s reload\r\n"
						 "\t    --reload the interception files\r\n"
						 "\t%s add <name>\r\n"
						 "\t    --add file into interception list\r\n"
						 "\t%s remove <name>\r\n"
						 "\t    --remove file from interception list";
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
			    result[length - 1] ='\0';
				    return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		if (TRUE == precise_interception_refresh()) {
			strncpy(result, "250 interception files reload OK", length);
		} else {
			strncpy(result, "550 fail to reload interception files", length);
		}
		return;
	}
	if (3 == argc && 0 == strcmp(argv[1], "add")) {
		if (TRUE == precise_interception_add(argv[2])) {
			snprintf(result, length, "250 %s is added into interception list",
				argv[2]);
		} else {
			snprintf(result, length, "550 cannot add %s into interception list",
				argv[2]);
		}
		return;
	}
	if (3 == argc && 0 == strcmp(argv[1], "remove")) {
		if (NULL != strchr(argv[2], '/')) {
			snprintf(result, length, "550 please do not contain path "
				"information in %s", argv[2]);
			return;
		}
		if (TRUE == precise_interception_remove(argv[2])) {
			snprintf(result, length, "250 %s is removed from interception list",
				argv[2]);
		} else {
			snprintf(result, length, "550 cannot remove %s from interception "
				"list", argv[2]);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


#include <unistd.h>
#include <libHX/string.h>
#include "tagging_table.h"
#include "str_hash.h"
#include "util.h"
#include "list_file.h"
#include <pthread.h>

enum{
	TAGGING_TABLE_REFRESH_OK,
	TAGGING_TABLE_REFRESH_FILE_ERROR,
	TAGGING_TABLE_REFRESH_HASH_FAIL
};

static int tagging_table_refresh();

static BOOL tagging_table_add(const char* str);

static STR_HASH_TABLE *g_tagging_table;
static pthread_rwlock_t g_refresh_lock;
static char g_list_path[256];
static int g_growing_num;
static int g_hash_cap;

/*
 *	string table's construct function
 */
void tagging_table_init(const char *list_path, int growing_num)
{
	strcpy(g_list_path, list_path);
	g_growing_num = growing_num;
	g_hash_cap = 0;
}

/*
 *	string table's destruct function
 */
void tagging_table_free()
{
	g_list_path[0] = '\0';
	g_growing_num = 0;
	g_hash_cap = 0;
}

/*
 *	run string table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int tagging_table_run()
{
    pthread_rwlock_init(&g_refresh_lock, NULL);
    if (TAGGING_TABLE_REFRESH_OK != tagging_table_refresh()) {
        return -1;
    }
    return 0;
}

/*
 *	stop string table
 *	@return
 *		 0		success
 *		<>0		fail
 */
int tagging_table_stop()
{
    if (NULL != g_tagging_table) {
        str_hash_free(g_tagging_table);
        g_tagging_table = NULL;
    }
    pthread_rwlock_destroy(&g_refresh_lock);
    return 0;
}

/*
 *  check if the specified string is in the table
 *
 *  @param
 *      from [in]     string
 *      pfile [in]    rcpt memory file pointer
 *
 *  @return
 *      TRUE        hitting
 *      FALSE       missing
 */
BOOL tagging_table_check(const char* from, MEM_FILE *pfile)
{
	char temp_string[256];
	

	mem_file_seek(pfile, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	
	pthread_rwlock_rdlock(&g_refresh_lock);
	
	strncpy(temp_string, from, 256);
	temp_string[255] = '\0';
	HX_strlower(temp_string);
    if (NULL != str_hash_query(g_tagging_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
        return TRUE;
    }
	
	while (MEM_END_OF_FILE != mem_file_readline(pfile, temp_string, 256)) {
		HX_strlower(temp_string);
		if (NULL != str_hash_query(g_tagging_table, temp_string)) {
			pthread_rwlock_unlock(&g_refresh_lock);
			return TRUE;
		}
	}
	pthread_rwlock_unlock(&g_refresh_lock);
    return FALSE;
}

/*
 *  refresh the tagging list, the list is from the
 *  file which is specified in configuration file.
 *
 *  @return
 *		TAGGING_TABLE_REFRESH_OK			OK
 *		TAGGING_TABLE_REFRESH_FILE_ERROR	fail to open list file
 *		TAGGING_TABLE_REFRESH_HASH_FAIL		fail to open hash map
 */
static int tagging_table_refresh()
{
    STR_HASH_TABLE *phash = NULL;
    int i, list_len, hash_cap;
	LIST_FILE *plist_file;
	char *pitem;
	
    /* initialize the list filter */
	plist_file = list_file_init3(g_list_path, "%s:256", false);
	if (NULL == plist_file) {
		printf("[tagging_table]: fail to open list file\n");
		return TAGGING_TABLE_REFRESH_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + g_growing_num;
	
    phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		printf("[tagging_table]: fail to allocate hash map\n");
		list_file_free(plist_file);
		return TAGGING_TABLE_REFRESH_HASH_FAIL;
	}
    for (i=0; i<list_len; i++) {
		HX_strlower(pitem + 256 * i);
        str_hash_add(phash, pitem + 256*i, &i);   
    }
    list_file_free(plist_file);
	
	pthread_rwlock_wrlock(&g_refresh_lock);
	if (NULL != g_tagging_table) {
		str_hash_free(g_tagging_table);
	}
    g_tagging_table = phash;
	g_hash_cap = hash_cap;
    pthread_rwlock_unlock(&g_refresh_lock);

    return TAGGING_TABLE_REFRESH_OK;
}

/*
 *	add item into string file and hash table
 *	@param
 *		str [in]		string to be added
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
static BOOL tagging_table_add(const char* str)
{
	char temp_string[256];
	char file_item[512];
	int dummy_val = 0;
	int i, j, hash_cap;
	int fd, string_len;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;

	if (NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	HX_strlower(temp_string);
	string_len = strlen(temp_string);
	for (i=0, j=0; i<string_len; i++, j++) {
		if (' ' == temp_string[i] || '\\' == temp_string[i] ||
			'\t' == temp_string[i] || '#' == temp_string[i]) {
			file_item[j] = '\\';
			j ++;
		}
		file_item[j] = temp_string[i];
	}
	string_len = j;
	file_item[string_len] = '\n';
	string_len ++;
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the string is already in the table */
	if (NULL != str_hash_query(g_tagging_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	fd = open(g_list_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	if (string_len != write(fd, file_item, string_len)) {
		close(fd);
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	close(fd);
	if (str_hash_add(g_tagging_table, temp_string, &dummy_val) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	hash_cap = g_hash_cap + g_growing_num;
	phash = str_hash_init(hash_cap, sizeof(int), NULL);
	if (NULL == phash) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_tagging_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, file_item);
		str_hash_add(phash, file_item, &dummy_val);
	}
	str_hash_iter_free(iter);
	str_hash_free(g_tagging_table);
	g_tagging_table = phash;
	g_hash_cap = hash_cap;
	if (str_hash_add(g_tagging_table, temp_string, &dummy_val) > 0) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	pthread_rwlock_unlock(&g_refresh_lock);
	return FALSE;
}

/*
 *	remove item from string file and hash table
 *	@param
 *		str [in]		string to be removed
 *	@return
 *		TRUE			OK
 *		FALSE			fail
 */
BOOL tagging_table_remove(const char* str)
{
	int i, j;
	int fd, string_len;
	char temp_string[256];
	char file_item[512];
	STR_HASH_ITER *iter;
	
	if (NULL == str) {
		return FALSE;
	}
	strncpy(temp_string, str, 255);
	temp_string[255] = '\0';
	HX_strlower(temp_string);
	
	pthread_rwlock_wrlock(&g_refresh_lock);
	/* check first if the string is in hash table */
	if (NULL == str_hash_query(g_tagging_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	if (1 != str_hash_remove(g_tagging_table, temp_string)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	fd = open(g_list_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return FALSE;
	}
	iter = str_hash_iter_init(g_tagging_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		str_hash_iter_get_value(iter, temp_string);
		string_len = strlen(temp_string);
		for (i=0, j=0; i<string_len; i++, j++) {
			if (' ' == temp_string[i] || '\\' == temp_string[i] ||
				'\t' == temp_string[i] || '#' == temp_string[i]) {
				file_item[j] = '\\';
				j ++;
			}
			file_item[j] = temp_string[i];
		}
		string_len = j;
		file_item[string_len] = '\n';
		string_len ++;
		write(fd, file_item, string_len);
	}
	str_hash_iter_free(iter);
	close(fd);
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

/*
 *	string table's console talk
 *	@param
 *		argc			arguments number
 *		argv [in]		arguments value
 *		result [out]	buffer for retrieving result
 *		length			result buffer length
 */
void tagging_table_console_talk(int argc, char **argv, char *result, int length)
{
	char help_string[] = "250 tagging table help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the tagging table from list file\r\n"
						 "\t%s add <address>\r\n"
						 "\t    --add address to the tagging table\r\n"
						 "\t%s remove <address>\r\n"
						 "\t    --remove address from the tagging table";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp("reload", argv[1])) {
		switch(tagging_table_refresh()) {
		case TAGGING_TABLE_REFRESH_OK:
			strncpy(result, "250 tagging table reload OK", length);
			return;
		case TAGGING_TABLE_REFRESH_FILE_ERROR:
			strncpy(result, "550 tagging list file error", length);
			return;
		case TAGGING_TABLE_REFRESH_HASH_FAIL:
			strncpy(result, "550 hash map error for tagging table", length);
			return;
		}
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		if (TRUE == tagging_table_add(argv[2])) {
			snprintf(result, length, "250 %s is added", argv[2]);
		} else {
			snprintf(result, length, "550 fail to add %s", argv[2]);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		if (TRUE == tagging_table_remove(argv[2])) {
			snprintf(result, length, "250 %s is removed", argv[2]);
		} else {
			snprintf(result, length, "550 fail to remove %s", argv[2]);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


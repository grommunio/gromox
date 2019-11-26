#include <libHX/string.h>
#include "auth_cache.h"
#include "str_hash.h"
#include "util.h"
#include <pthread.h>


typedef struct _STR_ITEM {
	char password[256];
    int  times;
} STR_ITEM;

/* private global variable */
static STR_HASH_TABLE  *g_cache_hash;
static int g_cache_size;
static pthread_mutex_t g_hash_lock;


static void auth_cache_collect_entry();

void auth_cache_init(int size) 
{
	g_cache_size = size;
	g_cache_hash = NULL;
	pthread_mutex_init(&g_hash_lock, NULL);
}

int auth_cache_run()
{
	/* invalidate the audit hash table if audit number is less than 0 */
	if (0 == g_cache_size) {
		g_cache_hash = NULL;
		return 0;
	}
    g_cache_hash = str_hash_init(g_cache_size, sizeof(STR_ITEM), NULL);
    if (NULL == g_cache_hash) {
        return -1;
	}
	return 0;
}


int auth_cache_stop() 
{
    if (NULL != g_cache_hash) {
        str_hash_free(g_cache_hash);
        g_cache_hash = NULL;
    }
    return 0;
}

void auth_cache_free()
{
	g_cache_size = 0;
	pthread_mutex_destroy(&g_hash_lock);
}

BOOL auth_cache_login(const char *username, const char *password) 
{
    STR_ITEM *pitem;
	char temp_string[256];

    if (NULL == g_cache_hash) {
        return FALSE;
    }
	strncpy(temp_string, username, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);

	pthread_mutex_lock(&g_hash_lock); 
    pitem = (STR_ITEM*)str_hash_query(g_cache_hash, temp_string);
	if (NULL == pitem) {
		pthread_mutex_unlock(&g_hash_lock);
        return FALSE;
	}
	if (0 == strcasecmp(pitem->password, password)) {
		pitem->times ++;
		pthread_mutex_unlock(&g_hash_lock);
        return TRUE;
    } else {
		str_hash_remove(g_cache_hash, temp_string);
		pthread_mutex_unlock(&g_hash_lock);
        return FALSE;
	}
}

void auth_cache_add(const char *username, const char *password) 
{
	STR_ITEM temp_item;
	char temp_string[256];

    if (NULL == g_cache_hash) {
        return;
    }
	strncpy(temp_string, username, sizeof(temp_string));
	temp_string[sizeof(temp_string) - 1] = '\0';
	HX_strlower(temp_string);
	strcpy(temp_item.password, password);
	temp_item.times = 1;
	
	pthread_mutex_lock(&g_hash_lock);
	if (1 != str_hash_add(g_cache_hash, temp_string, &temp_item)) {
		auth_cache_collect_entry();
	}
	str_hash_add(g_cache_hash, temp_string, &temp_item);
	pthread_mutex_unlock(&g_hash_lock);
}

static void auth_cache_collect_entry()
{
    STR_HASH_ITER *iter = NULL;
    STR_ITEM *iter_item = NULL;
    int i, num;

	for (i=0; i<10; i++) {
	    iter = str_hash_iter_init(g_cache_hash); 
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			iter_item = str_hash_iter_get_value(iter, NULL);
			if (i == iter_item->times) {
				str_hash_iter_remove(iter);
				num++;
				if (num >= g_cache_size/2) {
					break;
				}
			}
		}
		str_hash_iter_free(iter);
		
		if (num >= g_cache_size/2) {
			break;
		}
    }
    return;
}

int auth_cache_get_param(int param)
{
	STR_HASH_ITER *iter;
	int valid_num;
	
	if (AUTH_CACHE_TOTAL_SIZE == param) {
		return g_cache_size;
	} else if (AUTH_CACHE_CURRENT_SIZE == param) {
		if (NULL == g_cache_hash) {
			return 0;
		} else {
			valid_num = 0;
			pthread_mutex_lock(&g_hash_lock);
			iter = str_hash_iter_init(g_cache_hash);
			for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
				str_hash_iter_forward(iter)) {
				valid_num++;
			}
			str_hash_iter_free(iter);
			pthread_mutex_unlock(&g_hash_lock);
			return valid_num;
		}
	}
	return 0;
}


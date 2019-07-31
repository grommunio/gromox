#include "asyncemsmdb_interface.h"
#include "emsmdb_interface.h"
#include "proc_common.h"
#include "common_util.h"
#include "double_list.h"
#include "lib_buffer.h"
#include "int_hash.h"
#include "str_hash.h"
#include "util.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

#define WAITING_INTERVAL						300

#define FLAG_NOTIFICATION_PENDING				0x00000001

typedef struct _ASYNC_WAIT {
	DOUBLE_LIST_NODE node;
	time_t wait_time;
	char username[256];
	uint16_t cxr;
	uint32_t async_id;
	union {
		ECDOASYNCWAITEX_OUT *pout;
		int context_id; /* when async_id is 0 */
	} out_payload;
} ASYNC_WAIT;

static int g_threads_num;
static BOOL g_notify_stop;
static pthread_t g_scan_id;
static pthread_t *g_thread_ids;
static DOUBLE_LIST g_wakeup_list;
static STR_HASH_TABLE *g_tag_hash;
static pthread_mutex_t g_list_lock;
static pthread_cond_t g_waken_cond;
static pthread_mutex_t g_cond_mutex;
static pthread_mutex_t g_async_lock;
static INT_HASH_TABLE *g_async_hash;
static LIB_BUFFER *g_wait_allocator;


static void *scan_work_func(void *param);

static void *thread_work_func(void *param);

static void (*active_hpm_context)(int context_id, BOOL b_pending);

/* called by moh_emsmdb module */
void asyncemsmdb_interface_register_active(void *pproc)
{
	active_hpm_context = pproc;
}

void asyncemsmdb_interface_init(int threads_num)
{
	g_notify_stop = TRUE;
	g_thread_ids = NULL;
	g_threads_num = threads_num;
	pthread_mutex_init(&g_async_lock, NULL);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_cond_mutex, NULL);
	pthread_cond_init(&g_waken_cond, NULL);
	double_list_init(&g_wakeup_list);
}

int asyncemsmdb_interface_run()
{
	int i;
	int context_num;
	
	context_num = get_context_num();
	g_thread_ids = malloc(sizeof(pthread_t)*g_threads_num);
	if (NULL == g_thread_ids) {
		printf("[exchange_emsmdb]: fail to allocate thread id buffer\n");
		return -1;
	}
	g_async_hash = int_hash_init(2*context_num, sizeof(ASYNC_WAIT*), NULL);
	if (NULL == g_async_hash) {
		printf("[exchange_emsmdb]: fail to init async ID hash table\n");
		return -2;
	}
	g_wait_allocator = lib_buffer_init(
		sizeof(ASYNC_WAIT), 2*context_num, TRUE);
	if (NULL == g_wait_allocator) {
		printf("[exchange_emsmdb]: fail to init async wait allocator\n");
		return -3;
	}
	g_tag_hash = str_hash_init(context_num, sizeof(ASYNC_WAIT*), NULL);
	if (NULL == g_tag_hash) {
		printf("[exchange_emsmdb]: fail to init async user hash table\n");
		return -4;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		printf("[exchange_emsmdb]: fail to create"
			" scanning thread for asyncemsmdb\n");
		g_notify_stop = TRUE;
		return -5;
	}
	for (i=0; i<g_threads_num; i++) {
		if (0 != pthread_create(g_thread_ids + i,
			NULL, thread_work_func, NULL)) {
			g_threads_num = i;
			printf("[exchange_emsmdb]: fail to create "
					"wake up thread for asyncemsmdb\n");
			return -6;
		}
	}
	return 0;
}

int asyncemsmdb_interface_stop()
{
	int i;
	
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
		pthread_cond_broadcast(&g_waken_cond);
		for (i=0; i<g_threads_num; i++) {
			pthread_join(g_thread_ids[i], NULL);
		}
	}
	if (NULL != g_thread_ids) {
		free(g_thread_ids);
		g_thread_ids = NULL;
	}
	if (NULL != g_tag_hash) {
		str_hash_free(g_tag_hash);
		g_tag_hash = NULL;
	}
	if (NULL != g_wait_allocator) {
		lib_buffer_free(g_wait_allocator);
		g_wait_allocator = NULL;
	}
	if (NULL != g_async_hash) {
		int_hash_free(g_async_hash);
		g_async_hash = NULL;
	}
	return 0;
}

void asyncemsmdb_interface_free()
{
	pthread_mutex_destroy(&g_async_lock);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_cond_mutex);
	pthread_cond_destroy(&g_waken_cond);
	double_list_free(&g_wakeup_list);
}

int asyncemsmdb_interface_async_wait(uint32_t async_id,
	ECDOASYNCWAITEX_IN *pin, ECDOASYNCWAITEX_OUT *pout)
{
	ASYNC_WAIT *pwait;
	char tmp_tag[256];
	DCERPC_INFO rpc_info;
	
	pwait = lib_buffer_get(g_wait_allocator);
	if (NULL == pwait) {
		pout->flags_out = 0;
		pout->result = EC_ASYNC_WAIT_REJECT;
		return DISPATCH_SUCCESS;
	}
	rpc_info = get_rpc_info();
	if (FALSE == emsmdb_interface_check_acxh(
		&pin->acxh, pwait->username, &pwait->cxr, TRUE) ||
		0 != strcasecmp(rpc_info.username, pwait->username)) {
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = 0;
		pout->result = EC_ASYNC_WAIT_REJECT;
		return DISPATCH_SUCCESS;
	}
	if (TRUE == emsmdb_interface_check_notify(&pin->acxh)) {
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = FLAG_NOTIFICATION_PENDING;
		pout->result = EC_SUCCESS;
		return DISPATCH_SUCCESS;
	}
	pwait->node.pdata = pwait;
	pwait->async_id = async_id;
	lower_string(pwait->username);
	time(&pwait->wait_time);
	if (0 == async_id) {
		pwait->out_payload.context_id = pout->flags_out;
	} else {
		pwait->out_payload.pout = pout;
	}
	sprintf(tmp_tag, "%s:%d", pwait->username, (int)pwait->cxr);
	lower_string(tmp_tag);
	pthread_mutex_lock(&g_async_lock);
	if (0 != async_id) {
		if (1 != int_hash_add(g_async_hash, async_id, &pwait)) {
			pthread_mutex_unlock(&g_async_lock);
			lib_buffer_put(g_wait_allocator, pwait);
			pout->flags_out = 0;
			pout->result = EC_ASYNC_WAIT_REJECT;
			return DISPATCH_SUCCESS;
		}
	}
	if (1 != str_hash_add(g_tag_hash, tmp_tag, &pwait)) {
		if (0 != async_id) {
			int_hash_remove(g_async_hash, async_id);
		}
		pthread_mutex_unlock(&g_async_lock);
		lib_buffer_put(g_wait_allocator, pwait);
		pout->flags_out = 0;
		pout->result = EC_ASYNC_WAIT_REJECT;
		return DISPATCH_SUCCESS;
	}
	pthread_mutex_unlock(&g_async_lock);
	return DISPATCH_PENDING;
}

void asyncemsmdb_interface_reclaim(uint32_t async_id)
{
	char tmp_tag[256];
	ASYNC_WAIT *pwait;
	ASYNC_WAIT **ppwait;
	DOUBLE_LIST **pplist;
	
	pthread_mutex_lock(&g_async_lock);
	ppwait = int_hash_query(g_async_hash, async_id);
	if (NULL == ppwait) {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	pwait = *ppwait;
	sprintf(tmp_tag, "%s:%d", pwait->username, (int)pwait->cxr);
	lower_string(tmp_tag);
	str_hash_remove(g_tag_hash, tmp_tag);
	int_hash_remove(g_async_hash, async_id);
	pthread_mutex_unlock(&g_async_lock);
	lib_buffer_put(g_wait_allocator, pwait);
}

/* called by moh_emsmdb module */
void asyncemsmdb_interface_remove(ACXH *pacxh)
{
	uint16_t cxr;
	ASYNC_WAIT *pwait;
	char tmp_tag[256];
	char username[256];
	ASYNC_WAIT **ppwait;
	
	if (FALSE == emsmdb_interface_check_acxh(
		pacxh, username, &cxr, FALSE)) {
		return;
	}
	sprintf(tmp_tag, "%s:%d", username, cxr);
	lower_string(tmp_tag);
	pthread_mutex_lock(&g_async_lock);
	ppwait = str_hash_query(g_tag_hash, tmp_tag);
	if (NULL == ppwait) {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	pwait = *ppwait;
	if (0 != pwait->async_id) {
		int_hash_remove(g_async_hash, pwait->async_id);
	}
	str_hash_remove(g_tag_hash, tmp_tag);
	pthread_mutex_unlock(&g_async_lock);
	lib_buffer_put(g_wait_allocator, pwait);
}

static void asyncemsmdb_interface_activate(
	ASYNC_WAIT *pwait, BOOL b_pending)
{
	if (0 == pwait->async_id) {
		active_hpm_context(pwait->out_payload.context_id, b_pending);
	} else {
		if (TRUE == rpc_build_environment(pwait->async_id)) {
			pwait->out_payload.pout->result = EC_SUCCESS;
			if (TRUE == b_pending) {
				pwait->out_payload.pout->flags_out =
							FLAG_NOTIFICATION_PENDING;
			} else {
				pwait->out_payload.pout->flags_out = 0;
			}
			async_reply(pwait->async_id, pwait->out_payload.pout);
		}
	}
	lib_buffer_put(g_wait_allocator, pwait);
}

void asyncemsmdb_interface_wakeup(const char *username, uint16_t cxr)
{
	char tmp_tag[256];
	ASYNC_WAIT *pwait;
	ASYNC_WAIT **ppwait;
	
	sprintf(tmp_tag, "%s:%d", username, (int)cxr);
	lower_string(tmp_tag);
	pthread_mutex_lock(&g_async_lock);
	ppwait = str_hash_query(g_tag_hash, tmp_tag);
	if (NULL == ppwait) {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	pwait = *ppwait;
	str_hash_remove(g_tag_hash, tmp_tag);
	if (0 != pwait->async_id) {
		int_hash_remove(g_async_hash, pwait->async_id);
	}
	pthread_mutex_unlock(&g_async_lock);
	pthread_mutex_lock(&g_list_lock);
	double_list_append_as_tail(&g_wakeup_list, &pwait->node);
	pthread_mutex_unlock(&g_list_lock);
	pthread_cond_signal(&g_waken_cond);
}

static void *thread_work_func(void *param)
{
	DOUBLE_LIST_NODE *pnode;
	
	while (FALSE == g_notify_stop) {
		pthread_mutex_lock(&g_cond_mutex);
		pthread_cond_wait(&g_waken_cond, &g_cond_mutex);
		pthread_mutex_unlock(&g_cond_mutex);
NEXT_WAKEUP:
		if (TRUE == g_notify_stop) {
			break;
		}
		pthread_mutex_lock(&g_list_lock);
		pnode = double_list_get_from_head(&g_wakeup_list);
		pthread_mutex_unlock(&g_list_lock);
		if (NULL == pnode) {
			continue;
		}
		asyncemsmdb_interface_activate(pnode->pdata, TRUE);
		goto NEXT_WAKEUP;
	}
	pthread_exit(0);
}

static void *scan_work_func(void *param)
{
	time_t cur_time;
	ASYNC_WAIT *pwait;
	ASYNC_WAIT **ppwait;
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	while (FALSE == g_notify_stop) {
		sleep(1);
		time(&cur_time);
		pthread_mutex_lock(&g_async_lock);
		iter = str_hash_iter_init(g_tag_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppwait = str_hash_iter_get_value(iter, NULL);
			pwait = *ppwait;
			if (cur_time - pwait->wait_time > WAITING_INTERVAL - 3) {
				str_hash_iter_remove(iter);
				if (0 != pwait->async_id) {
					int_hash_remove(g_async_hash, pwait->async_id);
				}
				double_list_append_as_tail(&temp_list, &pwait->node);
			}
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_async_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			asyncemsmdb_interface_activate(pnode->pdata, FALSE);
		}
	}
	double_list_free(&temp_list);
	pthread_exit(0);
}

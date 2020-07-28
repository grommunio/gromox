#include <errno.h>
#include <string.h>
#include <libHX/defs.h>
#include "inbound_ips.h"
#include "dns_adaptor.h"
#include "list_file.h"
#include "vstack.h"
#include <pthread.h>

struct ipitem {
	char ip_addr[16];
};

static char g_list_path[256];
static LIST_FILE *g_inbound_list;
static pthread_rwlock_t g_list_lock;
static LIB_BUFFER *g_stack_allocator;



void inbound_ips_init(const char *path)
{
	strcpy(g_list_path, path);
	pthread_rwlock_init(&g_list_lock, NULL);
}

int inbound_ips_run()
{
	g_stack_allocator = vstack_allocator_init(16, 256*1024, TRUE);
	if (NULL == g_stack_allocator) {
		printf("[dns_adaptor]: fail to allocate buffer pool for inbound-ips\n");
		return -1;
	}
	g_inbound_list = list_file_init(g_list_path, "%s:16");
	if (NULL == g_inbound_list) {
		printf("[dns_adaptor]: Failed to read inbound-ip list from %s: %s\n",
			g_list_path, strerror(errno));
		return -2;
	}
	return 0;
}

BOOL inbound_ips_check_local(const char *domain)
{
	VSTACK stack;
	char *dest_ip;
	int i, item_num;
	
	vstack_init(&stack, g_stack_allocator, 16, 1024);
	if (FALSE == dns_adaptor_query_MX((char*)domain, &stack) &&
		FALSE == dns_adaptor_query_A((char*)domain, &stack)) {
		return FALSE;
	}
	pthread_rwlock_rdlock(&g_list_lock);
	item_num = list_file_get_item_num(g_inbound_list);
	const struct ipitem *pitem = reinterpret_cast(struct ipitem *, list_file_get_list(g_inbound_list));
	while (FALSE == vstack_is_empty(&stack)) {
		dest_ip = vstack_get_top(&stack);
		for (i=0; i<item_num; i++) {
			if (strcmp(dest_ip, pitem[i].ip_addr) == 0) {
				pthread_rwlock_unlock(&g_list_lock);
				vstack_free(&stack);
				return TRUE;
			}
		}
		vstack_pop(&stack);
	}
	pthread_rwlock_unlock(&g_list_lock);
	vstack_free(&stack);
	return FALSE;
}

int inbound_ips_stop()
{
	if (NULL != g_stack_allocator) {
		vstack_allocator_free(g_stack_allocator);
		g_stack_allocator = NULL;
	}
	if (NULL != g_inbound_list) {
		list_file_free(g_inbound_list);
		g_inbound_list = NULL;
	}
	return 0;
}

void inbound_ips_free()
{
	g_list_path[0] = '\0';
	pthread_rwlock_destroy(&g_list_lock);
}

BOOL inbound_ips_refresh()
{
	LIST_FILE *pfile_temp1, *pfile_temp2;
	
	pfile_temp1 = list_file_init(g_list_path, "%s:16");
	if (NULL == pfile_temp1) {
		return FALSE;
	}
	pthread_rwlock_wrlock(&g_list_lock);
	pfile_temp2 = g_inbound_list;
	g_inbound_list = pfile_temp1;
	pthread_rwlock_unlock(&g_list_lock);
	list_file_free(pfile_temp2);
	return TRUE;
}



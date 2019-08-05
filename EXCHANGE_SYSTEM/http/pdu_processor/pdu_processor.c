#include "pdu_processor.h"
#include "hpm_processor.h"
#include "alloc_context.h"
#include "endian_macro.h"
#include "http_parser.h"
#include "lib_buffer.h"
#include "int_hash.h"
#include "resource.h"
#include "service.h"
#include "vstack.h"
#include "guid.h"
#include "util.h"
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>



#define SERVICE_VERSION					0x00000001

#define ASSOC_GROUP_HASH_SIZE			10000
#define ASSOC_GROUP_HASH_GROWING		1000

#define MAX_CONTEXTS_PER_CONNECTION		100

#define MAX_FRAGMENTED_CALLS			100

#define MAX_AYNC_PER_CONTEXT			10


/* this is only used when the client asks for an unknown interface */
#define DUMMY_ASSOC_GROUP 0x0FFFFFFF

#define NDR_STACK_IN					0
#define NDR_STACK_OUT					1


/* structure for describing service reference */
typedef struct _SERVICE_NODE{
	DOUBLE_LIST_NODE node;
	void *service_addr;
	char *service_name;
} SERVICE_NODE;

typedef struct _INTERFACE_NODE {
	DOUBLE_LIST_NODE node;
	DCERPC_ENDPOINT *pendpoint;
	DCERPC_INTERFACE *pinterface;
} INTERFACE_NODE;

typedef struct _NDR_STACK_ROOT {
	ALLOC_CONTEXT in_stack;
	ALLOC_CONTEXT out_stack;
} NDR_STACK_ROOT;

typedef struct _ASYNC_NODE {
	DOUBLE_LIST_NODE node;
	BOOL b_cancelled;
	uint32_t async_id;
	DCERPC_CALL *pcall;
	NDR_STACK_ROOT* pstack_root;
	char vconn_host[128];
	int vconn_port;
	char vconn_cookie[64];
} ASYNC_NODE;

static BOOL g_bigendian;
static int g_connection_num;
static char g_dns_name[128];
static BOOL g_header_signing;
static int g_connection_ratio;
static char g_dns_domain[128];
static char g_netbios_name[128];
static char g_plugins_path[256];
static size_t g_max_request_mem;
static uint32_t g_last_async_id;
static pthread_key_t g_call_key;
static pthread_key_t g_stack_key;
static PROC_PLUGIN *g_cur_plugin;
static DOUBLE_LIST g_plugin_list;
static pthread_mutex_t g_list_lock;
static DOUBLE_LIST g_endpoint_list;
static pthread_mutex_t g_async_lock;
static INT_HASH_TABLE *g_async_hash;
static LIB_BUFFER *g_call_allocator;
static DOUBLE_LIST g_processor_list;
static LIB_BUFFER *g_auth_allocator;
static LIB_BUFFER *g_async_allocator;
static LIB_BUFFER *g_bnode_allocator;
static LIB_BUFFER *g_stack_allocator;
static LIB_BUFFER *g_context_allocator;
static LIB_BUFFER *g_processor_allocator;
static const SYNTAX_ID g_transfer_syntax_ndr = 
	{{0x8a885d04, 0x1ceb, 0x11c9, {0x9f, 0xe8}, {0x08,0x00,0x2b,0x10,0x48,0x60}}, 2};

static const SYNTAX_ID g_transfer_syntax_ndr64 =
	{{0x71710533, 0xbeba, 0x4937, {0x83, 0x19}, {0xb5,0xdb,0xef,0x9c,0xcc,0x36}}, 1};

static void pdu_processor_unload_library(const char* plugin_name);

static int pdu_processor_load_library(const char* plugin_name);


static NDR_STACK_ROOT* pdu_processor_new_stack_root()
{
	NDR_STACK_ROOT *pstack_root;
	
	pstack_root = lib_buffer_get(g_stack_allocator);
	if (NULL == pstack_root) {
		return NULL;
	}
	alloc_context_init(&pstack_root->in_stack);
	alloc_context_init(&pstack_root->out_stack);
	return pstack_root;
}

void* pdu_processor_ndr_stack_alloc(int type, size_t size)
{
	NDR_STACK_ROOT *proot;
	
	proot = (NDR_STACK_ROOT*)pthread_getspecific(g_stack_key);
	if (NULL == proot) {
		return NULL;
	}
	if (NDR_STACK_IN == type) {
		return alloc_context_alloc(&proot->in_stack, size);
	} else if (NDR_STACK_OUT == type) {
		return alloc_context_alloc(&proot->out_stack, size);
	}
	return NULL;
}

static void pdu_processor_free_stack_root(NDR_STACK_ROOT *pstack_root)
{
	alloc_context_free(&pstack_root->in_stack);
	alloc_context_free(&pstack_root->out_stack);
	lib_buffer_put(g_stack_allocator, pstack_root);
}

static size_t pdu_processor_ndr_stack_size(NDR_STACK_ROOT *pstack_root, int type)
{
	if (NDR_STACK_IN == type) {
		return alloc_context_get_total(&pstack_root->in_stack);
	} else if (NDR_STACK_OUT) {
		return alloc_context_get_total(&pstack_root->out_stack);
	}
	return 0;
}

void pdu_processor_init(int connection_num, int connection_ratio,
	const char *netbios_name, const char *dns_name, const char *dns_domain,
	BOOL header_signing, size_t max_request_mem, const char *plugins_path)
{
	union {
		uint32_t i;
		char c[4];
    } e;

	e.i = 0xFF000000;
	if (0 != e.c[0]) {
		g_bigendian = TRUE;
	} else {
		g_bigendian = FALSE;
	}
	g_last_async_id = 0;
	g_connection_ratio = connection_ratio;
	g_connection_num = connection_num;
	g_max_request_mem = max_request_mem;
	strcpy(g_netbios_name, netbios_name);
	strcpy(g_dns_name, dns_name);
	strcpy(g_dns_domain, dns_domain);
	g_header_signing = header_signing;
	strcpy(g_plugins_path, plugins_path);
	double_list_init(&g_plugin_list);
	double_list_init(&g_endpoint_list);
	double_list_init(&g_processor_list);
	pthread_mutex_init(&g_list_lock, NULL);
	pthread_mutex_init(&g_async_lock, NULL);
}

int pdu_processor_run()
{
	DIR *dirp;
	int length;
	int context_num;
	char temp_path[256];
	struct dirent *direntp;
	
	pthread_key_create(&g_call_key, NULL);
	pthread_key_create(&g_stack_key, NULL);
	
	g_call_allocator = lib_buffer_init(sizeof(DCERPC_CALL),
				g_connection_num*g_connection_ratio, TRUE);
	if (NULL == g_call_allocator) {
		return -1;
	}
	context_num = g_connection_num*g_connection_ratio;
	g_context_allocator = lib_buffer_init(
		sizeof(DCERPC_CONTEXT), context_num, TRUE);
	if (NULL == g_context_allocator) {
		return -2;
	}
	g_auth_allocator = lib_buffer_init(
		sizeof(DCERPC_AUTH_CONTEXT), context_num, TRUE);
	if (NULL == g_auth_allocator) {
		return -3;
	}
	g_processor_allocator = lib_buffer_init(
		sizeof(PDU_PROCESSOR), g_connection_num, TRUE);
	if (NULL == g_processor_allocator) {
		return -4;
	}
	g_bnode_allocator = lib_buffer_init(
		sizeof(BLOB_NODE), g_connection_num*32, TRUE);
	if (NULL == g_bnode_allocator) {
		return -5;
	}
	g_async_allocator = lib_buffer_init(
		sizeof(ASYNC_NODE), context_num*2, TRUE);
	if (NULL == g_async_allocator) {
		return -6;
	}
	g_stack_allocator = lib_buffer_init(
		sizeof(NDR_STACK_ROOT), context_num*4, TRUE);
	if (NULL == g_stack_allocator) {
		return -7;
	}
	g_async_hash = int_hash_init(context_num*2,
					sizeof(ASYNC_NODE*), NULL);
	if (NULL == g_async_hash) {
		return -8;
	}
	dirp = opendir(g_plugins_path);
	if (NULL == dirp){
		printf("[pdu_processor]: fail to open "
			"plugins' directory %s\n", g_plugins_path);
		return -9;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		/*extended name ".proc" */
		length = strlen(direntp->d_name);
		if (0 == strcmp(direntp->d_name + length - 5, ".proc")){
			pdu_processor_load_library(direntp->d_name);
		}
	}
	closedir(dirp);
	return 0;
}

void pdu_processor_free_call(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	
	if (TRUE == pcall->pkt_loaded) {
		pdu_ndr_free_ncacnpkt(&pcall->pkt);
	}
	while (pnode=double_list_get_from_head(&pcall->reply_list)) {
		pblob_node = (BLOB_NODE*)pnode->pdata;
		free(pblob_node->blob.data);
		lib_buffer_put(g_bnode_allocator, pblob_node);
	}
	double_list_free(&pcall->reply_list);
	lib_buffer_put(g_call_allocator, pcall);
}

static void pdu_processor_free_context(DCERPC_CONTEXT *pcontext)
{
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	while (TRUE) {
		pthread_mutex_lock(&g_async_lock);
		pnode = double_list_get_from_head(&pcontext->async_list);
		if (NULL == pnode) {
			pthread_mutex_unlock(&g_async_lock);
			break;
		}
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		int_hash_remove(g_async_hash, pasync_node->async_id);
		pthread_mutex_unlock(&g_async_lock);
		if (NULL != pcontext->pinterface->reclaim) {
			pcontext->pinterface->reclaim(pasync_node->async_id);
		}
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		lib_buffer_put(g_async_allocator, pasync_node);
	}
	double_list_free(&pcontext->async_list);
	lib_buffer_put(g_context_allocator, pcontext);
}

int pdu_processor_stop()
{
	VSTACK stack;
	uint64_t handle;
	LIB_BUFFER *pallocator;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DCERPC_CONTEXT *pcontext;
	PDU_PROCESSOR *pprocessor;
	DCERPC_ENDPOINT *pendpoint;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	while (pnode=double_list_get_from_head(&g_processor_list)) {
		pprocessor = (PDU_PROCESSOR*)pnode->pdata;
		while (pnode1=double_list_get_from_head(&pprocessor->context_list)) {
			pcontext = (DCERPC_CONTEXT*)pnode1->pdata;
			if (NULL != pcontext->pinterface->unbind) {
				handle = pcontext->assoc_group_id;
				handle <<= 32;
				handle |= pcontext->context_id;
				pcontext->pinterface->unbind(handle);
			}
			pdu_processor_free_context(pcontext);
		}
		double_list_free(&pprocessor->context_list);
		
		while (pnode=double_list_get_from_head(&pprocessor->auth_list)) {
			pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
			pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
			if (NULL != pauth_ctx->pntlmssp) {
				ntlmssp_destroy(pauth_ctx->pntlmssp);
				pauth_ctx->pntlmssp = NULL;
			}
			lib_buffer_put(g_auth_allocator, pauth_ctx);
		}
		double_list_free(&pprocessor->auth_list);
		
		while (pnode1=double_list_get_from_head(
			&pprocessor->fragmented_list)) {
			pdu_processor_free_call(pnode1->pdata);
		}
		double_list_free(&pprocessor->fragmented_list);
		lib_buffer_put(g_processor_allocator, pprocessor);
	}
	double_list_free(&g_processor_list);
	
	pallocator = vstack_allocator_init(256, 1024, FALSE);
	vstack_init(&stack, pallocator, 256, 1024);
	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		vstack_push(&stack, ((PROC_PLUGIN*)(pnode->pdata))->file_name);
	}
	while (FALSE == vstack_is_empty(&stack)) {
        pdu_processor_unload_library(vstack_get_top(&stack));
        vstack_pop(&stack);
    }
	vstack_free(&stack);
    vstack_allocator_free(pallocator);
	
	while (pnode=double_list_get_from_head(&g_endpoint_list)) {
		double_list_free(&((DCERPC_ENDPOINT*)pnode->pdata)->interface_list);
		free(pnode->pdata);
	}
	
	if (NULL != g_stack_allocator) {
		lib_buffer_free(g_stack_allocator);
		g_stack_allocator = NULL;
	}
	if (NULL != g_async_allocator) {
		lib_buffer_free(g_async_allocator);
		g_async_allocator = NULL;
	}
	if (NULL != g_bnode_allocator) {
		lib_buffer_free(g_bnode_allocator);
		g_bnode_allocator = NULL;
	}
	if (NULL != g_call_allocator) {
		lib_buffer_free(g_call_allocator);
		g_call_allocator = NULL;
	}
	if (NULL != g_context_allocator) {
		lib_buffer_free(g_context_allocator);
		g_context_allocator = NULL;
	}
	if (NULL != g_auth_allocator) {
		lib_buffer_free(g_auth_allocator);
		g_auth_allocator = NULL;
	}
	if (NULL != g_processor_allocator) {
		lib_buffer_free(g_processor_allocator);
		g_processor_allocator = NULL;
	}
	if (NULL != g_async_hash) {
		int_hash_free(g_async_hash);
		g_async_hash = NULL;
	}
	
	pthread_key_delete(g_call_key);
	pthread_key_delete(g_stack_key);
	
	return 0;
}

void pdu_processor_free()
{
	double_list_free(&g_plugin_list);
	double_list_free(&g_endpoint_list);
	double_list_free(&g_processor_list);
	pthread_mutex_destroy(&g_list_lock);
	pthread_mutex_destroy(&g_async_lock);
}


static int pdu_processor_find_secondary(const char *host,
	int tcp_port, GUID *puuid, uint32_t version)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DCERPC_ENDPOINT *pendpoint;
	DCERPC_INTERFACE *pinterface;
	
	for (pnode=double_list_get_head(&g_endpoint_list); NULL!=pnode;
		pnode=double_list_get_after(&g_endpoint_list, pnode)) {
		pendpoint = (DCERPC_ENDPOINT*)pnode->pdata;
		if (0 != strcasecmp(host, pendpoint->host) ||
			pendpoint->tcp_port == tcp_port) {
			continue;
		}
		plist = &pendpoint->interface_list;
		for (pnode1=double_list_get_head(plist); NULL!=pnode1;
			pnode1=double_list_get_after(plist, pnode1)) {
			pinterface = (DCERPC_INTERFACE*)pnode1->pdata;
			if (0 == guid_compare(puuid, &pinterface->uuid) &&
				pinterface->version == version) {
				return pendpoint->tcp_port;
			}
		}
	}
	return tcp_port;
}

/* find the interface operations on an endpoint by uuid */
static DCERPC_INTERFACE* pdu_processor_find_interface_by_uuid(
	DCERPC_ENDPOINT *pendpoint, GUID *puuid, uint32_t if_version)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_INTERFACE *pinterface;
	
	for (pnode=double_list_get_head(&pendpoint->interface_list); NULL!=pnode;
		pnode=double_list_get_after(&pendpoint->interface_list, pnode)) {
		pinterface = (DCERPC_INTERFACE*)pnode->pdata;
		if (0 == guid_compare(&pinterface->uuid, puuid)
			&& pinterface->version == if_version) {
			return pinterface;
		}
	}
	return NULL;
}

PDU_PROCESSOR* pdu_processor_create(const char *host, int tcp_port)
{
	DOUBLE_LIST_NODE *pnode;
	PDU_PROCESSOR *pprocessor;
	DCERPC_ENDPOINT *pendpoint;
	
	pprocessor = lib_buffer_get(g_processor_allocator);
	if (NULL == pprocessor) {
		return NULL;
	}
	memset(pprocessor, 0, sizeof(PDU_PROCESSOR));
	pprocessor->node.pdata = pprocessor;
	for (pnode=double_list_get_head(&g_endpoint_list); NULL!=pnode;
		pnode=double_list_get_after(&g_endpoint_list, pnode)) {
		pendpoint = (DCERPC_ENDPOINT*)pnode->pdata;
		if (tcp_port == pendpoint->tcp_port &&
			0 != wildcard_match(host, pendpoint->host, TRUE)) {
			double_list_init(&pprocessor->context_list);
			double_list_init(&pprocessor->auth_list);
			double_list_init(&pprocessor->fragmented_list);
			pprocessor->pendpoint = pendpoint;
			pthread_mutex_lock(&g_list_lock);
			double_list_append_as_tail(&g_processor_list, &pprocessor->node);
			pthread_mutex_unlock(&g_list_lock);
			return pprocessor;
		}
	}
	lib_buffer_put(g_processor_allocator, pprocessor);
	return NULL;
}

void pdu_processor_destroy(PDU_PROCESSOR *pprocessor)
{
	uint64_t handle;
	DCERPC_CALL *pcall;
	DCERPC_CALL fake_call;
	ASYNC_NODE *pasync_node;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	while (TRUE) {
		pthread_mutex_lock(&g_async_lock);
		if (pprocessor->async_num > 0) {
			pthread_mutex_unlock(&g_async_lock);
			usleep(100000);
		} else {
			pprocessor->async_num = -1;
			pthread_mutex_unlock(&g_async_lock);
			break;
		}
	}
	
	while (pnode=double_list_get_from_head(&pprocessor->context_list)) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		if (NULL != pcontext->pinterface->unbind) {
			fake_call.pprocessor = pprocessor;
			fake_call.pcontext = pcontext;
			pthread_setspecific(g_call_key, (const void*)&fake_call);
			handle = pcontext->assoc_group_id;
			handle <<= 32;
			handle |= pcontext->context_id;
			pcontext->pinterface->unbind(handle);
		}
		pdu_processor_free_context(pcontext);
	}
	double_list_free(&pprocessor->context_list);
	
	while (pnode=double_list_get_from_head(&pprocessor->auth_list)) {
		pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
		if (NULL != pauth_ctx->pntlmssp) {
			ntlmssp_destroy(pauth_ctx->pntlmssp);
			pauth_ctx->pntlmssp = NULL;
		}
		lib_buffer_put(g_auth_allocator, pauth_ctx);
	}
	double_list_free(&pprocessor->auth_list);
	
	while (pnode=double_list_get_from_head(
		&pprocessor->fragmented_list)) {
		pcall = (DCERPC_CALL*)pnode->pdata;
		pdu_processor_free_call(pcall);
	}
	double_list_free(&pprocessor->fragmented_list);
	
	pprocessor->cli_max_recv_frag = 0;
	
	pthread_mutex_lock(&g_list_lock);
	double_list_remove(&g_processor_list, &pprocessor->node);
	pthread_mutex_unlock(&g_list_lock);
	
	pprocessor->pendpoint = NULL;
	lib_buffer_put(g_processor_allocator, pprocessor);
}

static void pdu_processor_set_frag_length(DATA_BLOB *pblob, uint16_t v)
{
	if (CVAL(pblob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(pblob->data, DCERPC_FRAG_LEN_OFFSET, v);
	} else {
		RSSVAL(pblob->data, DCERPC_FRAG_LEN_OFFSET, v);
	}
}

static void pdu_processor_set_auth_length(DATA_BLOB *pblob, uint16_t v)
{
	if (CVAL(pblob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(pblob->data, DCERPC_AUTH_LEN_OFFSET, v);
	} else {
		RSSVAL(pblob->data, DCERPC_AUTH_LEN_OFFSET, v);
	}
}

void pdu_processor_output_stream(DCERPC_CALL *pcall, STREAM *pstream)
{
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&pcall->reply_list)) {
		pblob_node = (BLOB_NODE*)pnode->pdata;
		stream_write(pstream, pblob_node->blob.data, pblob_node->blob.length);
		free(pblob_node->blob.data);
		lib_buffer_put(g_bnode_allocator, pblob_node);
	}
}

void pdu_processor_output_pdu(DCERPC_CALL *pcall, DOUBLE_LIST *ppdu_list)
{
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&pcall->reply_list)) {
		double_list_append_as_tail(ppdu_list, pnode);
	}
}

void pdu_processor_free_blob(BLOB_NODE *pbnode)
{
	lib_buffer_put(g_bnode_allocator, pbnode);
}

static DCERPC_CALL* pdu_processor_get_fragmented_call(
	PDU_PROCESSOR *pprocessor, uint32_t call_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pprocessor->fragmented_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->fragmented_list, pnode)) {
		pcall = (DCERPC_CALL*)pnode->pdata;
		if (pcall->pkt.call_id == call_id) {
			double_list_remove(&pprocessor->fragmented_list, pnode);
			return pcall;
		}
	}
	return NULL;
}

static uint32_t pdu_processor_allocate_group_id(DCERPC_ENDPOINT *pendpoint)
{
	uint32_t group_id;
	
	pendpoint->last_group_id ++;
	group_id = pendpoint->last_group_id;
	if (pendpoint->last_group_id >= 0x7FFFFFFF) {
		pendpoint->last_group_id = 0;
	}
	return group_id;
}

/* find a registered context_id from a bind or alter_context */
static DCERPC_CONTEXT* pdu_processor_find_context(PDU_PROCESSOR *pprocessor, 
	uint32_t context_id)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	
	for (pnode=double_list_get_head(&pprocessor->context_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->context_list, pnode)) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		if (context_id == pcontext->context_id) {
			return pcontext;
		}
	}
	return NULL;
}

static DCERPC_AUTH_CONTEXT* pdu_processor_find_auth_context(
	PDU_PROCESSOR *pprocessor, uint32_t auth_context_id)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	for (pnode=double_list_get_head(&pprocessor->auth_list); NULL!=pnode;
		pnode=double_list_get_after(&pprocessor->auth_list, pnode)) {
		pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		if (auth_context_id == pauth_ctx->auth_info.auth_context_id) {
			return pauth_ctx;
		}
	}
	return NULL;
}

static void pdu_processor_init_hdr(DCERPC_NCACN_PACKET *ppkt, BOOL bigendian)
{
	ppkt->rpc_vers = 5;
	ppkt->rpc_vers_minor = 0;
	if (TRUE == bigendian) {
		ppkt->drep[0] = 0;
	} else {
		ppkt->drep[0] = DCERPC_DREP_LE;
	}
	ppkt->drep[1] = 0;
	ppkt->drep[2] = 0;
	ppkt->drep[3] = 0;
}


static BOOL pdu_processor_pull_auth_trailer(DCERPC_NCACN_PACKET *ppkt,
	DATA_BLOB *ptrailer, DCERPC_AUTH *pauth, uint32_t *pauth_length,
	BOOL auth_data_only)
{
	NDR_PULL ndr;
	uint32_t flags;
	uint32_t data_and_pad;
	
	
	data_and_pad = ptrailer->length -
		(DCERPC_AUTH_TRAILER_LENGTH + ppkt->auth_length);
	if (data_and_pad > ptrailer->length) {
		return FALSE;
	}
	*pauth_length = ptrailer->length - data_and_pad;
	
	flags = 0;
	if (0 == (ppkt->drep[0] & DCERPC_DREP_LE)) {
		flags = NDR_FLAG_BIGENDIAN;
	}
	
	ndr_pull_init(&ndr, ptrailer->data, ptrailer->length, flags);
	if (NDR_ERR_SUCCESS != ndr_pull_advance(&ndr, data_and_pad)) {
		return FALSE;
	}
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_dcerpc_auth(&ndr, pauth)) {
		return FALSE;
	}

	if (TRUE == auth_data_only && data_and_pad != pauth->auth_pad_length) {
		debug_info("[pdu_processor]: WARNING: pad length mismatch, "
			"calculated %u got %u\n", data_and_pad, pauth->auth_pad_length);
		pdu_ndr_free_dcerpc_auth(pauth);
		return FALSE;
	}
	
	return TRUE;
}

/* check credentials on a request */
static BOOL pdu_processor_auth_request(DCERPC_CALL *pcall, DATA_BLOB *pblob)
{
	size_t hdr_size;
	DCERPC_AUTH auth;
	uint32_t auth_length;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_REQUEST *prequest;
	DCERPC_NCACN_PACKET *ppkt;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	ppkt = &pcall->pkt;
	prequest = &ppkt->payload.request;
	hdr_size = DCERPC_REQUEST_LENGTH;
	if (0 == ppkt->auth_length) {
		if (0 == double_list_get_nodes_num(&pcall->pprocessor->auth_list)) {
			return FALSE;
		}
		pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
		pcall->pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
		switch (pcall->pauth_ctx->auth_info.auth_level) {
		case DCERPC_AUTH_LEVEL_EMPTY:
		case DCERPC_AUTH_LEVEL_CONNECT:
		case DCERPC_AUTH_LEVEL_NONE:
			return TRUE;
		default:
			return FALSE;
		}
	}
	if (FALSE == pdu_processor_pull_auth_trailer(ppkt,
		&prequest->stub_and_verifier, &auth, &auth_length, FALSE)) {
		return FALSE;
	}
	pauth_ctx = pdu_processor_find_auth_context(
				pcall->pprocessor, auth.auth_context_id);
	if (NULL == pauth_ctx) {
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	pcall->pauth_ctx = pauth_ctx;
	
	if (ppkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		hdr_size += 16;
	}
	
	switch (pauth_ctx->auth_info.auth_level) {
	case DCERPC_AUTH_LEVEL_EMPTY:
		pdu_ndr_free_dcerpc_auth(&auth);
		return TRUE;
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_CONNECT:
		break;
	case DCERPC_AUTH_LEVEL_NONE:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	default:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	
	ppkt->payload.request.stub_and_verifier.length -= auth_length;

	/* check signature or unseal the packet */
	switch (pauth_ctx->auth_info.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		if (FALSE == ntlmssp_unseal_packet(pauth_ctx->pntlmssp,
			pblob->data + hdr_size, prequest->stub_and_verifier.length, 
			pblob->data, pblob->length - auth.credentials.length,
			&auth.credentials)) {
			pdu_ndr_free_dcerpc_auth(&auth);
			return FALSE;
		}
		memcpy(prequest->stub_and_verifier.data, pblob->data + hdr_size,
			prequest->stub_and_verifier.length);
		break;
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		if (FALSE == ntlmssp_check_packet(pauth_ctx->pntlmssp,
			prequest->stub_and_verifier.data,
			prequest->stub_and_verifier.length, pblob->data,
			pblob->length - auth.credentials.length, &auth.credentials)) {
			pdu_ndr_free_dcerpc_auth(&auth);
			return FALSE;
		}
		break;
	case DCERPC_AUTH_LEVEL_CONNECT:
		/* ignore possible signatures here */
		break;
	default:
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	
	/* remove the indicated amount of padding */
	if (prequest->stub_and_verifier.length < auth.auth_pad_length) {
		pdu_ndr_free_dcerpc_auth(&auth);
		return FALSE;
	}
	prequest->stub_and_verifier.length -= auth.auth_pad_length;
	pdu_ndr_free_dcerpc_auth(&auth);
	return TRUE;
}

static BOOL pdu_processor_ncacn_push_with_auth(DATA_BLOB *pblob,
	DCERPC_NCACN_PACKET *ppkt, DCERPC_AUTH *pauth_info)
{
	void *pdata;
	NDR_PUSH ndr;
	uint32_t flags;
	
	
	pdata = malloc(DCERPC_BASE_MARSHALL_SIZE);
	if (NULL == pdata) {
		return FALSE;
	}
	
	flags = 0;
	if (0 == (ppkt->drep[0] & DCERPC_DREP_LE)) {
		flags = NDR_FLAG_BIGENDIAN;
	}
	if (ppkt->pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		flags |= NDR_FLAG_OBJECT_PRESENT;
	}
	
	ndr_push_init(&ndr, pdata, DCERPC_BASE_MARSHALL_SIZE, flags);
	
	if (NULL != pauth_info) {
		ppkt->auth_length = pauth_info->credentials.length;
	} else {
		ppkt->auth_length = 0;
	}

	if (NDR_ERR_SUCCESS != pdu_ndr_push_ncacnpkt(&ndr, ppkt)) {
		free(pdata);
		return FALSE;
	}

	if (NULL != pauth_info) {
		pauth_info->auth_pad_length = 0;
		if (NDR_ERR_SUCCESS != pdu_ndr_push_dcerpc_auth(&ndr, pauth_info)) {
			free(pdata);
			return FALSE;
		}
	}
	
	pblob->data = ndr.data;
	pblob->length = ndr.offset;
	
	/* fill in the frag length */
	pdu_processor_set_frag_length(pblob, pblob->length);

	return TRUE;
}

static BOOL pdu_processor_fault(DCERPC_CALL *pcall, uint32_t fault_code)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	static uint8_t zeros[4] = {0, 0, 0, 0};
	
	/* setup a bind_ack */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_FAULT;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.fault.alloc_hint = 0;
	pkt.payload.fault.context_id = 0;
	pkt.payload.fault.cancel_count = 0;
	pkt.payload.fault.status = fault_code;
	pkt.payload.fault.pad.data = zeros;
	pkt.payload.fault.pad.length = sizeof(zeros);

	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	return TRUE;
}

/*
  parse any auth information from a dcerpc bind request
  return false if we can't handle the auth request for some 
  reason (in which case we send a bind_nak)
*/
static BOOL pdu_processor_auth_bind(DCERPC_CALL *pcall)
{
	DCERPC_BIND *pbind;
	uint32_t auth_length;
	DCERPC_NCACN_PACKET *ppkt;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	ppkt = &pcall->pkt;
	pbind = &ppkt->payload.bind;
	
	if (double_list_get_nodes_num(&pcall->pprocessor->auth_list) >
		MAX_CONTEXTS_PER_CONNECTION) {
		debug_info("[pdu_processor]: maximum auth contexts"
			" number of connection reached\n");
		return FALSE;
	}
	pauth_ctx = lib_buffer_get(g_auth_allocator);
	if (NULL == pauth_ctx) {
		return FALSE;
	}
	memset(pauth_ctx, 0, sizeof(DCERPC_AUTH_CONTEXT));
	pauth_ctx->node.pdata = pauth_ctx;
	
	if (0 == pbind->auth_info.length) {
		pauth_ctx->auth_info.auth_type = DCERPC_AUTH_TYPE_NONE;
		pauth_ctx->auth_info.auth_level = DCERPC_AUTH_LEVEL_EMPTY;
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	}
	
	if (FALSE == pdu_processor_pull_auth_trailer(ppkt, &pbind->auth_info,
		&pauth_ctx->auth_info, &auth_length, FALSE)) {
		lib_buffer_put(g_auth_allocator, pauth_ctx);
		return FALSE;
	}
	
	if (NULL != pdu_processor_find_auth_context(pcall->pprocessor,
		pauth_ctx->auth_info.auth_context_id)) {
		pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
		lib_buffer_put(g_auth_allocator, pauth_ctx);
		return FALSE;
	}
	
	if (DCERPC_AUTH_TYPE_NONE == pauth_ctx->auth_info.auth_type) {
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	} else if (DCERPC_AUTH_TYPE_NTLMSSP == pauth_ctx->auth_info.auth_type) {
		if (pauth_ctx->auth_info.auth_level <= DCERPC_AUTH_LEVEL_CONNECT ) {
			pauth_ctx->pntlmssp = ntlmssp_init(g_netbios_name,
									g_dns_name, g_dns_domain, TRUE,
									NTLMSSP_NEGOTIATE_128|
									NTLMSSP_NEGOTIATE_56|
									NTLMSSP_NEGOTIATE_NTLM2|
									NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
									http_parser_get_password);
		} else {
			pauth_ctx->pntlmssp = ntlmssp_init(g_netbios_name,
									g_dns_name, g_dns_domain, TRUE,
									NTLMSSP_NEGOTIATE_128|
									NTLMSSP_NEGOTIATE_56|
									NTLMSSP_NEGOTIATE_KEY_EXCH|
									NTLMSSP_NEGOTIATE_NTLM2|
									NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
									http_parser_get_password);
		}
		if (NULL == pauth_ctx->pntlmssp) {
			pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
			lib_buffer_put(g_auth_allocator, pauth_ctx);
			return FALSE;
		}
		double_list_append_as_tail(&pcall->pprocessor->auth_list,
			&pauth_ctx->node);
		return TRUE;
	}
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
	lib_buffer_put(g_auth_allocator, pauth_ctx);
	debug_info("[pdu_processor]: unsupported authentication type\n");
	return FALSE;
}

/*
  add any auth information needed in a bind ack, and 
  process the authentication information found in the bind.
*/
static BOOL pdu_processor_auth_bind_ack(DCERPC_CALL *pcall)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		return TRUE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	if (DCERPC_AUTH_TYPE_NONE == pauth_ctx->auth_info.auth_type &&
		(DCERPC_AUTH_LEVEL_EMPTY == pauth_ctx->auth_info.auth_level ||
		DCERPC_AUTH_LEVEL_NONE == pauth_ctx->auth_info.auth_level)) {
		return TRUE;
	}
	if (FALSE == ntlmssp_update(pauth_ctx->pntlmssp,
		&pauth_ctx->auth_info.credentials)) {
		return FALSE;
	}

	if (NTLMSSP_PROCESS_AUTH == ntlmssp_expected_state(pauth_ctx->pntlmssp)) {
		pauth_ctx->auth_info.auth_pad_length = 0;
		pauth_ctx->auth_info.auth_reserved = 0;
		return TRUE;
	} else {
		return ntlmssp_session_info(pauth_ctx->pntlmssp,
				&pauth_ctx->session_info);
	}
}

/* return a dcerpc bind_nak */
static BOOL pdu_processor_bind_nak(DCERPC_CALL *pcall, uint32_t reason)
{
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_NCACN_PACKET pkt;
	
	
	/* setup a bind_nak */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_BIND_NAK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.bind_nak.reject_reason = reason;
	pkt.payload.bind_nak.num_versions = 0;

	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(
		&pblob_node->blob, &pkt, NULL)) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}

	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_process_bind(DCERPC_CALL *pcall)
{
	int i;
	int port2;
	GUID uuid;
	char bitmap;
	BOOL b_found;
	BOOL b_ndr64;
	uint32_t reason;
	uint32_t result;
	char uuid_str[64];
	DCERPC_BIND *pbind;
	uint32_t context_id;
	uint32_t if_version;
	uint32_t extra_flags;
	BLOB_NODE *pblob_node;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_NCACN_PACKET pkt;
	DCERPC_CONTEXT *pcontext;
	DCERPC_INTERFACE *pinterface;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
#ifdef SUPPORT_NEGOTIATE
	BOOL b_negotiate = FALSE;
#endif

	pbind = &pcall->pkt.payload.bind;

	if (pbind->num_contexts < 1 ||
		pbind->ctx_list[0].num_transfer_syntaxes < 1) {
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	/* can not bind twice on the same connection */
	if (0 != pcall->pprocessor->assoc_group_id) {
		return pdu_processor_bind_nak(pcall, 0);
	}

	context_id = pbind->ctx_list[0].context_id;

	/* bind only there's no context, otherwise, use alter */
	if (double_list_get_nodes_num(&pcall->pprocessor->context_list) > 0) {
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	if_version = pbind->ctx_list[0].abstract_syntax.version;
	uuid = pbind->ctx_list[0].abstract_syntax.uuid;

	b_ndr64 = FALSE;
	b_found = FALSE;
	for (i=0; i<pbind->ctx_list[0].num_transfer_syntaxes; i++) {
		if (0 == guid_compare(&g_transfer_syntax_ndr.uuid,
			&pbind->ctx_list[0].transfer_syntaxes[i].uuid) &&
			pbind->ctx_list[0].transfer_syntaxes[i].version ==
			g_transfer_syntax_ndr.version) {
			b_found = TRUE;
			break;
		}
	}
	
	if (FALSE == b_found) {
		for (i=0; i<pbind->ctx_list[0].num_transfer_syntaxes; i++) {
			if (0 == guid_compare(&g_transfer_syntax_ndr64.uuid,
				&pbind->ctx_list[0].transfer_syntaxes[i].uuid) &&
				pbind->ctx_list[0].transfer_syntaxes[i].version ==
				g_transfer_syntax_ndr64.version) {
				b_found = TRUE;
				break;
			}
		}
		if (FALSE == b_found) {
			debug_info("[pdu_processor]: only NDR or NDR64 transfer syntax "
				"can be accepted by system\n");
			return pdu_processor_bind_nak(pcall, 0);
		}
		b_ndr64 = TRUE;
	}
#ifdef SUPPORT_NEGOTIATE
	if (TRUE == b_found && pbind->num_contexts > 1) {
		if (0 == memcmp(&pbind->ctx_list[0].abstract_syntax,
			&pbind->ctx_list[1].abstract_syntax, sizeof(SYNTAX_ID)) &&
			pbind->ctx_list[1].num_transfer_syntaxes > 0) {
			guid_to_string(&pbind->ctx_list[1].transfer_syntaxes[0].uuid,
				uuid_str, sizeof(uuid_str));
			if (0 == strncmp("6cb71c2c-9812-4540", uuid_str, 18)) {
				b_negotiate = TRUE;
			}
		}
	}
#endif
	pinterface = pdu_processor_find_interface_by_uuid(
					pcall->pprocessor->pendpoint, &uuid, if_version);
	if (NULL == pinterface) {
		guid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		debug_info("[pdu_processor]: interface %s/%d unkown when binding\n",
			uuid_str, if_version);
		/* we don't know about that interface */
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		pcontext = NULL;
	} else {
		/* add this context to the list of available context_ids */
		pcontext = lib_buffer_get(g_context_allocator);
		if (NULL == pcontext) {
			return pdu_processor_bind_nak(pcall, 0);
		}
		pcontext->node.pdata = pcontext;
		pcontext->pinterface = pinterface;
		pcontext->context_id = context_id;
		pcontext->b_ndr64 = b_ndr64;
		pcontext->stat_flags = 0;
		pcontext->pendpoint = pcall->pprocessor->pendpoint;
		if (0 == pbind->assoc_group_id) {
			pcall->pprocessor->assoc_group_id = 
				pdu_processor_allocate_group_id(pcall->pprocessor->pendpoint);
		} else {
			pcall->pprocessor->assoc_group_id = pbind->assoc_group_id;
		}
		pcontext->assoc_group_id = pcall->pprocessor->assoc_group_id;
		double_list_init(&pcontext->async_list);
		pcall->pcontext = pcontext;
		result = 0;
		reason = 0;
	}

	if (0 == pcall->pprocessor->cli_max_recv_frag) {
		if (pbind->max_recv_frag > 0x2000) {
			pcall->pprocessor->cli_max_recv_frag = 0x2000;
		} else {
			pcall->pprocessor->cli_max_recv_frag = pbind->max_recv_frag;
		}
	}

	extra_flags = 0;
	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN &&
		TRUE == g_header_signing) {
		if (NULL != pcontext) {
			pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
		}
		extra_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
	}

	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) {
		if (NULL != pcontext) {
			pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
		}
		extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
	}

	/* handle any authentication that is being requested */
	if (FALSE == pdu_processor_auth_bind(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall,
					DCERPC_BIND_REASON_INVALID_AUTH_TYPE);
	}
	
	if (FALSE == pdu_processor_auth_bind_ack(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}

	/* setup a bind_ack */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_BIND_ACK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.payload.bind_ack.max_xmit_frag = pcall->pprocessor->cli_max_recv_frag;
	pkt.payload.bind_ack.max_recv_frag = 0x2000;
	pkt.payload.bind_ack.pad.data = NULL;
	pkt.payload.bind_ack.pad.length = 0;
	
	if (NULL != pcall->pcontext) {
		pkt.payload.bind_ack.assoc_group_id = pcall->pcontext->assoc_group_id;
	} else {
		pkt.payload.bind_ack.assoc_group_id = DUMMY_ASSOC_GROUP;
	}

	if (NULL != pinterface) {
		port2 = pdu_processor_find_secondary(
					pcall->pprocessor->pendpoint->host,
					pcall->pprocessor->pendpoint->tcp_port,
					&pinterface->uuid, pinterface->version);
		snprintf(pkt.payload.bind_ack.secondary_address, 64, "%d", port2);
	} else {
		pkt.payload.bind_ack.secondary_address[0] = '\0';
	}
#ifdef SUPPORT_NEGOTIATE
	if (FALSE == b_negotiate) {
#endif
		pkt.payload.bind_ack.num_contexts = 1;
		pkt.payload.bind_ack.ctx_list = malloc(sizeof(DCERPC_ACK_CTX));
		if (NULL == pkt.payload.bind_ack.ctx_list) {
			if (NULL != pcontext) {
				pdu_processor_free_context(pcontext);
			}
			return pdu_processor_bind_nak(pcall, 0);
		}
#ifdef SUPPORT_NEGOTIATE
	} else {
		pkt.payload.bind_ack.num_contexts = 2;
		pkt.payload.bind_ack.ctx_list = malloc(2*sizeof(DCERPC_ACK_CTX));
		if (NULL == pkt.payload.bind_ack.ctx_list) {
			if (NULL != pcontext) {
				pdu_processor_free_context(pcontext);
			}
			return pdu_processor_bind_nak(pcall, 0);
		}
		pkt.payload.bind_ack.ctx_list[1].result =
				DCERPC_BIND_RESULT_NEGOTIATE_ACK;
		if (FALSE == pcall->b_bigendian) {
			bitmap = pbind->ctx_list[1].transfer_syntaxes[0].uuid.clock_seq[0];
		} else {
			bitmap = pbind->ctx_list[1].transfer_syntaxes[0].uuid.node[5];
		}
		if (DCERPC_SECURITY_CONTEXT_MULTIPLEXING & bitmap) {
			pkt.payload.bind_ack.ctx_list[1].reason =
				DCERPC_SECURITY_CONTEXT_MULTIPLEXING;
		} else {
			pkt.payload.bind_ack.ctx_list[1].reason = 0;
		}
		memset(&pkt.payload.bind_ack.ctx_list[1].syntax, 0, sizeof(SYNTAX_ID));
	}
#endif
	pkt.payload.bind_ack.ctx_list[0].result = result;
	pkt.payload.bind_ack.ctx_list[0].reason = reason;
	pkt.payload.bind_ack.ctx_list[0].syntax = g_transfer_syntax_ndr;
	pkt.payload.bind_ack.auth_info.data = NULL;
	pkt.payload.bind_ack.auth_info.length = 0;
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		debug_info("[pdu_processor]: fata error in pdu_processor_process_bind"
			" cannot get auth_context from list\n");
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, &pauth_ctx->auth_info)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return pdu_processor_bind_nak(pcall, 0);
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	if (NULL != pcontext) {
		double_list_insert_as_head(&pcall->pprocessor->context_list,
			&pcontext->node);
	}
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_process_auth3(DCERPC_CALL *pcall)
{
	uint32_t auth_length;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_NCACN_PACKET *ppkt;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	ppkt = &pcall->pkt;
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		return TRUE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	/* can't work without an existing state, and an new blob to feed it */
	if ((DCERPC_AUTH_TYPE_NONE == pauth_ctx->auth_info.auth_type &&
		DCERPC_AUTH_LEVEL_EMPTY == pauth_ctx->auth_info.auth_level) ||
		NULL == pauth_ctx->pntlmssp ||
	    0 == ppkt->payload.auth3.auth_info.length) {
		goto AUTH3_FAIL;
	}
	
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);

	if (FALSE == pdu_processor_pull_auth_trailer(ppkt,
		&ppkt->payload.auth3.auth_info, &pauth_ctx->auth_info,
		&auth_length, TRUE)) {
		goto AUTH3_FAIL;
	}
	
	if (FALSE == ntlmssp_update(pauth_ctx->pntlmssp,
		&pauth_ctx->auth_info.credentials)) {
		goto AUTH3_FAIL;
	}

	if (FALSE == ntlmssp_session_info(pauth_ctx->pntlmssp,
		&pauth_ctx->session_info)) {
		debug_info("[pdu_processor]: failed to establish session_info\n");
		goto AUTH3_FAIL;
	}
	
	if (DCERPC_AUTH_TYPE_NONE != pauth_ctx->auth_info.auth_type) {
		pauth_ctx->is_login = TRUE;
	}
	
	return TRUE;
	
AUTH3_FAIL:
	double_list_remove(&pcall->pprocessor->auth_list, pnode);
	pdu_ndr_free_dcerpc_auth(&pauth_ctx->auth_info);
	if (NULL != pauth_ctx->pntlmssp) {
		ntlmssp_destroy(pauth_ctx->pntlmssp);
		pauth_ctx->pntlmssp = NULL;
	}
	lib_buffer_put(g_auth_allocator, pauth_ctx);
	return TRUE;
}

static BOOL pdu_processor_auth_alter(DCERPC_CALL *pcall)
{
	return pdu_processor_auth_bind(pcall);
}

static BOOL pdu_processor_auth_alter_ack(DCERPC_CALL *pcall)
{
	return pdu_processor_auth_bind_ack(pcall);
}

static BOOL pdu_processor_process_alter(DCERPC_CALL *pcall)
{
	int i;
	int port2;
	GUID uuid;
	BOOL b_ndr64;
	BOOL b_found;
	uint32_t result;
	uint32_t reason;
	char uuid_str[64];
	uint32_t if_version;
	uint32_t context_id;
	DCERPC_BIND *palter;
	uint32_t extra_flags;
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	DOUBLE_LIST_NODE *pnode;
	DCERPC_CONTEXT *pcontext;
	PDU_PROCESSOR *pprocessor;
	DCERPC_INTERFACE *pinterface;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	
	
	palter = &pcall->pkt.payload.alter;
	pprocessor = pcall->pprocessor;
	
	
	if (palter->num_contexts < 1 ||
	    palter->ctx_list[0].num_transfer_syntaxes < 1) {
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		goto ALTER_ACK;
	}
	
	/* cannot process alter before bind */
	if (0 == pcall->pprocessor->assoc_group_id) {
		result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
		reason = DCERPC_BIND_REASON_ASYNTAX;
		goto ALTER_ACK;
	}
		
	if_version = palter->ctx_list[0].abstract_syntax.version;
	uuid = palter->ctx_list[0].abstract_syntax.uuid;
	context_id = palter->ctx_list[0].context_id;

	/* check if they are asking for a new interface */
	pcontext = NULL;
	pcall->pcontext = pdu_processor_find_context(pprocessor, context_id);
	if (NULL == pcall->pcontext) {
		b_ndr64 = FALSE;
		b_found = FALSE;
		
		for (i=0; i<palter->ctx_list[0].num_transfer_syntaxes; i++) {
			if (0 == guid_compare(&g_transfer_syntax_ndr.uuid,
				&palter->ctx_list[0].transfer_syntaxes[i].uuid) &&
				palter->ctx_list[0].transfer_syntaxes[i].version ==
				g_transfer_syntax_ndr.version) {
				b_found = TRUE;
				break;
			}
		}
		
		if (FALSE == b_found) {
			for (i=0; i<palter->ctx_list[0].num_transfer_syntaxes; i++) {
				if (0 == guid_compare(&g_transfer_syntax_ndr64.uuid,
					&palter->ctx_list[0].transfer_syntaxes[i].uuid) &&
					palter->ctx_list[0].transfer_syntaxes[i].version ==
					g_transfer_syntax_ndr64.version) {
					b_found = TRUE;
					break;
				}
			}
			if (FALSE == b_found) {
				debug_info("[pdu_processor]: only NDR or NDR64 transfer syntax "
					"can be accepted by system\n");
				result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
				reason = DCERPC_BIND_REASON_ASYNTAX;
				goto ALTER_ACK;
			}
			b_ndr64 = TRUE;
		}

		pinterface = pdu_processor_find_interface_by_uuid(pprocessor->pendpoint,
						&uuid, if_version);
		if (NULL == pinterface) {
			guid_to_string(&uuid, uuid_str, sizeof(uuid_str));
			debug_info("[pdu_processor]: interface %s/%d unkown when altering\n",
				uuid_str, if_version);
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DCERPC_BIND_REASON_ASYNTAX;
			goto ALTER_ACK;
		}

		if (double_list_get_nodes_num(&pprocessor->context_list) >
			MAX_CONTEXTS_PER_CONNECTION) {
			debug_info("[pdu_processor]: maximum rpc contexts"
				" number of connection reached\n");
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DECRPC_BIND_REASON_LOCAL_LIMIT_EXCEEDED;
			goto ALTER_ACK;
		}
		/* add this context to the list of available context_ids */
		pcontext = lib_buffer_get(g_context_allocator);
		if (NULL == pcontext) {
			result = DCERPC_BIND_RESULT_PROVIDER_REJECT;
			reason = DECRPC_BIND_REASON_LOCAL_LIMIT_EXCEEDED;
			goto ALTER_ACK;
		}
		pcontext->node.pdata = pcontext;
		pcontext->pinterface = pinterface;
		pcontext->context_id = context_id;
		pcontext->b_ndr64 = b_ndr64;
		pcontext->pendpoint = pprocessor->pendpoint;
		pcontext->assoc_group_id = pprocessor->assoc_group_id;
		
		double_list_init(&pcontext->async_list);
		pcall->pcontext = pcontext;
		result = 0;
		reason = 0;
	}
	
ALTER_ACK:
	extra_flags = 0;
	if (0 == result) {
		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN &&
			TRUE == g_header_signing) {
			if (NULL != pcontext) {
				pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
			}
			extra_flags |= DCERPC_PFC_FLAG_SUPPORT_HEADER_SIGN;
		} else {
			if (NULL != pcontext) {
				pcontext->stat_flags &= ~DCERPC_CALL_STAT_FLAG_HEADER_SIGNING;
			}
		}
		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_CONC_MPX) {
			if (NULL != pcontext) {
				pcontext->stat_flags |= DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
			}
			extra_flags |= DCERPC_PFC_FLAG_CONC_MPX;
		} else {
			if (NULL != pcontext) {
				pcontext->stat_flags &= ~DCERPC_CALL_STAT_FLAG_MULTIPLEXED;
			}
		}
	}
	
	if (FALSE == pdu_processor_auth_alter(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	
	if (FALSE == pdu_processor_auth_alter_ack(pcall)) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_ALTER_ACK;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST | extra_flags;
	pkt.payload.alter_ack.max_xmit_frag = 0x2000;
	pkt.payload.alter_ack.max_recv_frag = 0x2000;
	pkt.payload.alter_ack.pad.data = NULL;
	pkt.payload.alter_ack.pad.length = 0;
	
	if (NULL != pcontext) {
		pkt.payload.alter_ack.assoc_group_id = pcall->pcontext->assoc_group_id;
	} else {
		pkt.payload.alter_ack.assoc_group_id = DUMMY_ASSOC_GROUP;
	}
	
	pkt.payload.alter_ack.secondary_address[0] = '\0';
	
	pkt.payload.alter_ack.num_contexts = 1;
	pkt.payload.alter_ack.ctx_list = malloc(sizeof(DCERPC_ACK_CTX));
	if (NULL == pkt.payload.alter_ack.ctx_list) {
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pkt.payload.alter_ack.ctx_list[0].result = result;
	pkt.payload.alter_ack.ctx_list[0].reason = reason;
	pkt.payload.alter_ack.ctx_list[0].syntax = g_transfer_syntax_ndr;
	pkt.payload.alter_ack.auth_info.data = NULL;
	pkt.payload.alter_ack.auth_info.length = 0;
	
	pnode = double_list_get_tail(&pcall->pprocessor->auth_list);
	if (NULL == pnode) {
		debug_info("[pdu_processor]: fata error in pdu_processor_process_alter"
			" cannot get auth_context from list\n");
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pauth_ctx = (DCERPC_AUTH_CONTEXT*)pnode->pdata;
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = FALSE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(
		&pblob_node->blob, &pkt, &pauth_ctx->auth_info)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		if (NULL != pcontext) {
			pdu_processor_free_context(pcontext);
		}
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	if (NULL != pcontext) {
		double_list_insert_as_head(&pprocessor->context_list, &pcontext->node);
	}
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

/* push a signed or sealed dcerpc request packet into a blob */
static BOOL pdu_processor_auth_response(DCERPC_CALL *pcall,
	DATA_BLOB *pblob, size_t sig_size, DCERPC_NCACN_PACKET *ppkt)
{
	void *pdata;
	NDR_PUSH ndr;
	uint32_t flags;
	DATA_BLOB creds2;
	char creds2_buff[16];
	uint32_t payload_length;
	DCERPC_AUTH_CONTEXT *pauth_ctx;
	char ndr_buff[DCERPC_BASE_MARSHALL_SIZE];

	
	creds2.data = creds2_buff;
	creds2.length = 0;
	pauth_ctx = pcall->pauth_ctx;
	/* non-signed packets are simple */
	if (0 == sig_size) {
		return pdu_processor_ncacn_push_with_auth(pblob, ppkt, NULL);
	}

	switch (pauth_ctx->auth_info.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		break;
	case DCERPC_AUTH_LEVEL_CONNECT:
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_EMPTY:
		return pdu_processor_ncacn_push_with_auth(pblob, ppkt, NULL);
	default:
		return FALSE;
	}
	
	flags = 0;
	if (pcall->b_bigendian) {
		flags |= NDR_FLAG_BIGENDIAN;
	}
	if (TRUE == pcall->pcontext->b_ndr64) {
		flags |= NDR_FLAG_NDR64;
	}
	ndr_push_init(&ndr, ndr_buff, DCERPC_BASE_MARSHALL_SIZE, flags);
	
	if (NDR_ERR_SUCCESS != pdu_ndr_push_ncacnpkt(&ndr, ppkt)) {
		return FALSE;
	}
	
	pauth_ctx->auth_info.auth_pad_length =
		(16 - (ppkt->payload.response.stub_and_verifier.length & 15)) & 15;
	if (NDR_ERR_SUCCESS != ndr_push_zero(&ndr,
		pauth_ctx->auth_info.auth_pad_length)) {
		return FALSE;
	}

	payload_length = ppkt->payload.response.stub_and_verifier.length +
						pauth_ctx->auth_info.auth_pad_length;

	/* start without signature, will be appended later */
	if (NULL != pauth_ctx->auth_info.credentials.data) {
		free(pauth_ctx->auth_info.credentials.data);
		pauth_ctx->auth_info.credentials.data = NULL;
	}
	pauth_ctx->auth_info.credentials.length = 0;
	
	/* change back into NDR */
	if (TRUE == pcall->pcontext->b_ndr64) {
		ndr.flags &= ~NDR_FLAG_NDR64;
	}

	/* add the auth verifier */
	if (NDR_ERR_SUCCESS != pdu_ndr_push_dcerpc_auth(&ndr,
		&pauth_ctx->auth_info)) {
		return FALSE;
	}

	/* extract the whole packet as a blob */
	pblob->data = ndr.data;
	pblob->length = ndr.offset;
	
	pdu_processor_set_frag_length(pblob, pblob->length + sig_size);
	pdu_processor_set_auth_length(pblob, sig_size);

	/* sign or seal the packet */
	switch (pauth_ctx->auth_info.auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		if (FALSE == ntlmssp_seal_packet(pauth_ctx->pntlmssp,
			ndr.data + DCERPC_REQUEST_LENGTH, payload_length,
			pblob->data, pblob->length, &creds2)) {
			return FALSE;
		}
		break;
	case DCERPC_AUTH_LEVEL_INTEGRITY:
		if (FALSE == ntlmssp_sign_packet(pauth_ctx->pntlmssp,
			ndr.data + DCERPC_REQUEST_LENGTH, payload_length,
			pblob->data, pblob->length, &creds2)) {
			return FALSE;
		}
		break;

	default:
		return FALSE;
	}

	if (creds2.length != sig_size) {
		debug_info("[pdu_processor]: auth_response: creds2.length[%u] != "
			"sig_size[%u] pad[%u] stub[%u]\n", creds2.length, (uint32_t)sig_size,
			pauth_ctx->auth_info.auth_pad_length,
			ppkt->payload.response.stub_and_verifier.length);
		pdu_processor_set_frag_length(pblob, pblob->length + creds2.length);
		pdu_processor_set_auth_length(pblob, creds2.length);
	}

	pdata = malloc(pblob->length + creds2.length);
	if (NULL == pdata) {
		return FALSE;
	}
	memcpy(pdata, pblob->data, pblob->length);
	memcpy(pdata + pblob->length, creds2.data, creds2.length);
	pblob->data = pdata;
	pblob->length += creds2.length;
	
	return TRUE;
}

static DCERPC_CALL* pdu_processor_get_call()
{
	return (DCERPC_CALL*)pthread_getspecific(g_call_key);
}

static BOOL pdu_processor_reply_request(DCERPC_CALL *pcall,
	NDR_STACK_ROOT *pstack_root, void *pout)
{
	void *pdata;
	uint32_t flags;
	DATA_BLOB stub;
	uint32_t length;
	size_t sig_size;
	size_t alloc_size;
	NDR_PUSH ndr_push;
	uint32_t chunk_size;
	uint32_t total_length;
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	DCERPC_REQUEST *prequest;
	
	
	flags = 0;
	if (TRUE == pcall->b_bigendian) {
		flags |= NDR_FLAG_BIGENDIAN;
	}
	if (TRUE == pcall->pcontext->b_ndr64) {
		flags |= NDR_FLAG_NDR64;
	}
	
	prequest = &pcall->pkt.payload.request;
	
	alloc_size = pdu_processor_ndr_stack_size(pstack_root, NDR_STACK_OUT);
	alloc_size = 2 * alloc_size + 1024;
	pdata = malloc(alloc_size);
	if (NULL == pdata) {
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: push fail on RPC call %u on %s\n",
			prequest->opnum, pcall->pcontext->pinterface->name);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
	}
	ndr_push_init(&ndr_push, pdata, alloc_size, flags);
	
	ndr_push_set_ptrcnt(&ndr_push, pcall->ptr_cnt);
	
	/* marshaling the NDR out param data */
	if (NDR_ERR_SUCCESS != pcall->pcontext->pinterface->ndr_push(
		prequest->opnum, &ndr_push, pout)) {
		free(pdata);
		pdu_processor_free_stack_root(pstack_root);
		return pdu_processor_fault(pcall, DCERPC_FAULT_NDR);
	}
	pdu_processor_free_stack_root(pstack_root);
	
	stub.data = ndr_push.data;
	stub.length = ndr_push.offset;

	total_length = stub.length;
	
	sig_size = 0;
	
	/* full max_recv_frag size minus the dcerpc request header size */
	chunk_size = pcall->pprocessor->cli_max_recv_frag;
	chunk_size -= DCERPC_REQUEST_LENGTH;
	if (DCERPC_AUTH_TYPE_NONE != pcall->pauth_ctx->auth_info.auth_type &&
		DCERPC_AUTH_LEVEL_EMPTY != pcall->pauth_ctx->auth_info.auth_level &&
		DCERPC_AUTH_LEVEL_NONE != pcall->pauth_ctx->auth_info.auth_level &&
		NULL != pcall->pauth_ctx->pntlmssp) {
		sig_size = ntlmssp_sig_size();
		if (0 != sig_size) {
			chunk_size -= DCERPC_AUTH_TRAILER_LENGTH;
			chunk_size -= sig_size;
		}
	}
	chunk_size -= chunk_size % 16;

	do {
		pblob_node = lib_buffer_get(g_bnode_allocator);
		if (NULL == pblob_node) {
			free(pdata);
			return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
		}
		pblob_node->node.pdata = pblob_node;
		pblob_node->b_rts = FALSE;

		if (chunk_size > stub.length) {
			length = stub.length;
		} else {
			length = chunk_size;
		}

		/* form the dcerpc response packet */
		pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
		pkt.auth_length = 0;
		pkt.call_id = pcall->pkt.call_id;
		pkt.pkt_type = DCERPC_PKT_RESPONSE;
		pkt.pfc_flags = 0;
		if (stub.length == total_length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_FIRST;
		}
		if (length == stub.length) {
			pkt.pfc_flags |= DCERPC_PFC_FLAG_LAST;
		}
		pkt.payload.response.alloc_hint = stub.length;
		pkt.payload.response.context_id = prequest->context_id;
		pkt.payload.response.cancel_count = 0;
		pkt.payload.response.pad.data = prequest->pad.data;
		pkt.payload.response.pad.length = prequest->pad.length;
		pkt.payload.response.stub_and_verifier.data = stub.data;
		pkt.payload.response.stub_and_verifier.length = length;

		if (FALSE == pdu_processor_auth_response(pcall,
			&pblob_node->blob, sig_size, &pkt)) {
			lib_buffer_put(g_bnode_allocator, pblob_node);
			free(pdata);
			return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
		}

		double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);

		stub.data += length;
		stub.length -= length;
	} while (stub.length != 0);
	free(pdata);
	return TRUE;
}

static uint32_t pdu_processor_apply_async_id()
{
	int async_id;
	DCERPC_CALL *pcall;
	HTTP_CONTEXT *pcontext;
	ASYNC_NODE *pasync_node;
	ASYNC_NODE *pfake_async;
	NDR_STACK_ROOT *pstack_root;
	RPC_IN_CHANNEL *pchannel_in;
	
	async_id = 0;
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return 0;
	}
	pstack_root = (NDR_STACK_ROOT*)pthread_getspecific(g_stack_key);
	if (NULL == pstack_root) {
		return 0;
	}
	if (double_list_get_nodes_num(&pcall->pcontext->async_list) >=
		MAX_AYNC_PER_CONTEXT) {
		debug_info("[pdu_processor]: maximum async contexts"
			" number of connection reached\n");
		return 0;
	}
	pcontext = http_parser_get_context();
	if (NULL == pcontext) {
		return 0;
	}
	if (CHANNEL_TYPE_IN != pcontext->channel_type) {
		return 0;
	}
	pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
	pasync_node = lib_buffer_get(g_async_allocator);
	if (NULL == pasync_node) {
		return 0;
	}
	pasync_node->node.pdata = pasync_node;
	pasync_node->b_cancelled = FALSE;
	pasync_node->pcall = pcall;
	pasync_node->pstack_root = pstack_root;
	strcpy(pasync_node->vconn_host, pcontext->host);
	pasync_node->vconn_port = pcontext->port;
	strcpy(pasync_node->vconn_cookie, pchannel_in->connection_cookie);
	
	pthread_mutex_lock(&g_async_lock);
	g_last_async_id ++;
	async_id = g_last_async_id;
	if (g_last_async_id >= 0x7FFFFFFF) {
		g_last_async_id = 0;
	}
	pfake_async = NULL;
	if (1 != int_hash_add(g_async_hash, async_id, &pfake_async)) {
		pthread_mutex_unlock(&g_async_lock);
		lib_buffer_put(g_async_allocator, pasync_node);
		return 0;
	}
	pasync_node->async_id = async_id;
	double_list_append_as_tail(&pcall->pcontext->async_list,
		&pasync_node->node);
	pthread_mutex_unlock(&g_async_lock);
	return async_id;
}

static void pdu_processor_activate_async_id(uint32_t async_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	ASYNC_NODE **ppasync_node;
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	pthread_mutex_lock(&g_async_lock);
	ppasync_node = int_hash_query(g_async_hash, async_id);
	if (NULL == ppasync_node || NULL != *ppasync_node) {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			*ppasync_node = pasync_node;
			break;
		}
	}
	pthread_mutex_unlock(&g_async_lock);
}

static void pdu_processor_cancel_async_id(uint32_t async_id)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	ASYNC_NODE **ppasync_node;
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	pthread_mutex_lock(&g_async_lock);
	ppasync_node = int_hash_query(g_async_hash, async_id);
	if (NULL == ppasync_node || NULL != *ppasync_node) {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			int_hash_remove(g_async_hash, async_id);
			double_list_remove(&pcall->pcontext->async_list, pnode);
			break;
		}
	}
	pthread_mutex_unlock(&g_async_lock);
	if (NULL != pnode) {
		lib_buffer_put(g_async_allocator, pasync_node);
	}
}

/* to check if the async_id is still available and
   then lock the async_id in async hash table */
static BOOL pdu_processor_rpc_build_environment(int async_id)
{
	ASYNC_NODE *pasync_node;
	ASYNC_NODE **ppasync_node;
	
BUILD_BEGIN:
	pthread_mutex_lock(&g_async_lock);
	ppasync_node = int_hash_query(g_async_hash, async_id);
	if (NULL == ppasync_node) {
		pthread_mutex_unlock(&g_async_lock);
		return FALSE;
	} else if (NULL == *ppasync_node) {
		pthread_mutex_unlock(&g_async_lock);
		usleep(10000);
		goto BUILD_BEGIN;
	}
	pasync_node = *ppasync_node;
	/* remove from async hash table to forbidden
		cancel pdu while async replying */
	int_hash_remove(g_async_hash, async_id);
	pthread_mutex_unlock(&g_async_lock);
	pthread_setspecific(g_call_key,
			(const void*)pasync_node->pcall);
	pthread_setspecific(g_stack_key,
			(const void*)pasync_node->pstack_root);
	return TRUE;
}

/* only can be invoked in non-rpc thread!!! */
BOOL pdu_processor_rpc_new_environment()
{
	NDR_STACK_ROOT *pstack_root;
	
	pstack_root = pdu_processor_new_stack_root();
	if (NULL == pstack_root) {
		return FALSE;
	}
	pthread_setspecific(g_stack_key, pstack_root);
	return TRUE;
}

/* only can be invoked in non-rpc thread!!! */
void pdu_processor_rpc_free_environment()
{
	NDR_STACK_ROOT *pstack_root;
	
	pstack_root = (NDR_STACK_ROOT*)pthread_getspecific(g_stack_key);
	if (NULL != pstack_root) {
		pthread_setspecific(g_stack_key, NULL);
		pdu_processor_free_stack_root(pstack_root);
	}
}

static void pdu_processor_async_reply(int async_id, void *pout)
{
	DCERPC_CALL *pcall;
	DOUBLE_LIST_NODE *pnode;
	ASYNC_NODE *pasync_node;
	
	
	pcall = pdu_processor_get_call();
	if (NULL == pcall) {
		return;
	}
	pthread_mutex_lock(&g_async_lock);
	for (pnode=double_list_get_head(&pcall->pcontext->async_list); NULL!=pnode;
		pnode=double_list_get_after(&pcall->pcontext->async_list, pnode)) {
		pasync_node = (ASYNC_NODE*)pnode->pdata;
		if (pasync_node->async_id == async_id) {
			break;
		}
	}
	if (NULL != pnode) {
		double_list_remove(&pcall->pcontext->async_list, pnode);
	} else {
		pthread_mutex_unlock(&g_async_lock);
		return;
	}
	if (pcall->pprocessor->async_num < 0 ||
		TRUE == pasync_node->b_cancelled) {
		pthread_mutex_unlock(&g_async_lock);
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		lib_buffer_put(g_async_allocator, pasync_node);
		return;
	}
	pcall->pprocessor->async_num ++;
	pthread_mutex_unlock(&g_async_lock);
	/* stack root will be freed in pdu_processor_reply_request */
	if (TRUE == pdu_processor_reply_request(pcall, pasync_node->pstack_root, pout)) {
		pthread_mutex_lock(&g_async_lock);
		pcall->pprocessor->async_num --;
		pthread_mutex_unlock(&g_async_lock);
		http_parser_vconnection_async_reply(pasync_node->vconn_host,
			pasync_node->vconn_port, pasync_node->vconn_cookie,
			pasync_node->pcall);
	} else {
		pthread_mutex_lock(&g_async_lock);
		pcall->pprocessor->async_num --;
		pthread_mutex_unlock(&g_async_lock);
	}
	pdu_processor_free_call(pasync_node->pcall);
	lib_buffer_put(g_async_allocator, pasync_node);
}

static BOOL pdu_processor_process_request(DCERPC_CALL *pcall, BOOL *pb_aync)
{
	GUID *pobject;
	uint32_t flags;
	uint64_t handle;
	void *pin, *pout;
	NDR_PULL ndr_pull;
	DCERPC_REQUEST *prequest;
	DCERPC_CONTEXT *pcontext;
	PDU_PROCESSOR *pprocessor;
	NDR_STACK_ROOT *pstack_root;
	
	
	pprocessor = pcall->pprocessor;
	prequest = &pcall->pkt.payload.request;
	pcontext = pdu_processor_find_context(pprocessor, prequest->context_id);
	if (NULL == pcontext) {
		return pdu_processor_fault(pcall, DCERPC_FAULT_UNK_IF);
	}
	
	/* normally, stack root will be freed in pdu_processor_reply_request */
	pstack_root = pdu_processor_new_stack_root();
	if (NULL == pstack_root) {
		return pdu_processor_fault(pcall, DCERPC_FAULT_OTHER);
	}
	
	pthread_setspecific(g_call_key, (const void*)pcall);
	pthread_setspecific(g_stack_key, (const void*)pstack_root);
	
	flags = 0;
	if (TRUE == pcall->b_bigendian) {
		flags |= NDR_FLAG_BIGENDIAN;
	}
	if (TRUE == pcontext->b_ndr64) {
		flags |= NDR_FLAG_NDR64;
	}
	ndr_pull_init(&ndr_pull, prequest->stub_and_verifier.data,
		prequest->stub_and_verifier.length, flags);
	
	pcall->pcontext	= pcontext;
	
	/* unmarshaling the NDR in param data */
	if (NDR_ERR_SUCCESS != pcontext->pinterface->ndr_pull(
		prequest->opnum, &ndr_pull, &pin)) {
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: pull fail on RPC call %u on %s\n",
			prequest->opnum, pcontext->pinterface->name);
		return pdu_processor_fault(pcall, DCERPC_FAULT_NDR);
	}
	
	pcall->ptr_cnt = ndr_pull_get_ptrcnt(&ndr_pull);
	
	if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_OBJECT_UUID) {
		pobject = &prequest->object.object;
	} else {
		pobject = NULL;
	}
	
	handle = pcall->pcontext->assoc_group_id;
	handle <<= 32;
	handle |= pcall->pcontext->context_id;
	*pb_aync = FALSE;
	/* call the dispatch function */
	switch (pcontext->pinterface->dispatch(prequest->opnum,
			pobject, handle, pin, &pout)) {
	case DISPATCH_FAIL:
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: RPC excution fault in call %s:%02x\n",
			pcontext->pinterface->name, prequest->opnum);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OP_RNG_ERROR);
	case DISPATCH_PENDING:
		*pb_aync = TRUE;
		return TRUE;
	case DISPATCH_SUCCESS:
		return pdu_processor_reply_request(pcall, pstack_root, pout);
	default:
		pdu_processor_free_stack_root(pstack_root);
		debug_info("[pdu_processor]: unknown return value by %s:%02x\n",
			pcontext->pinterface->name, prequest->opnum);
		return pdu_processor_fault(pcall, DCERPC_FAULT_OP_RNG_ERROR);
	}
}

static void pdu_processor_process_cancel(DCERPC_CALL *pcall)
{
	int async_id;
	BOOL b_cancel;
	uint32_t call_id;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DCERPC_CONTEXT *pcontext;
	ASYNC_NODE *pasync_node;
	ASYNC_NODE **ppasync_node;
	
	async_id = 0;
	b_cancel = FALSE;
	pthread_mutex_lock(&g_async_lock);
	plist = &pcall->pprocessor->context_list;
	for (pnode=double_list_get_from_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pcontext = (DCERPC_CONTEXT*)pnode->pdata;
		for (pnode1=double_list_get_head(&pcontext->async_list); NULL!=pnode1;
			pnode1=double_list_get_after(&pcontext->async_list, pnode1)) {
			pasync_node = (ASYNC_NODE*)pnode1->pdata;
			if (pasync_node->pcall->pkt.call_id == pcall->pkt.call_id) {
				async_id = pasync_node->async_id;
				pasync_node->b_cancelled = TRUE;
				break;
			}
		}
	}
	if (0 != async_id) {
		ppasync_node = int_hash_query(g_async_hash, async_id);
		if (NULL != ppasync_node && NULL != *ppasync_node) {
			b_cancel = TRUE;
			int_hash_remove(g_async_hash, async_id);
			double_list_remove(&pcontext->async_list, pnode1);
		}
	}
	pthread_mutex_unlock(&g_async_lock);
	if (TRUE == b_cancel) {
		if (NULL != pcontext->pinterface->reclaim) {
			pcontext->pinterface->reclaim(async_id);
		}
		pdu_processor_free_stack_root(pasync_node->pstack_root);
		pdu_processor_free_call(pasync_node->pcall);
		lib_buffer_put(g_async_allocator, pasync_node);
	}
}

static void pdu_processor_process_orphaned(DCERPC_CALL *pcall)
{
	DCERPC_CALL *pcallx;
	
	pcallx = pdu_processor_get_fragmented_call(
		pcall->pprocessor, pcall->pkt.call_id);
	if (NULL != pcallx) {
		pdu_processor_free_call(pcallx);
	}
}

void pdu_processor_rts_echo(char *pbuff)
{
	int flags;
	NDR_PUSH ndr;
	DCERPC_NCACN_PACKET pkt;
	
	/* setup a echo */
	pdu_processor_init_hdr(&pkt, g_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = 0;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_ECHO;
	pkt.payload.rts.num = 0;
	pkt.payload.rts.commands = NULL;
	
	if (TRUE == g_bigendian) {
		flags = NDR_FLAG_BIGENDIAN;
	} else {
		flags = 0;
	}
	ndr_push_init(&ndr, pbuff, 20, flags);
	pdu_ndr_push_ncacnpkt(&ndr, &pkt);
	ndr_push_destroy(&ndr);
}

BOOL pdu_processor_rts_ping(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	/* setup a echo */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_PING;
	pkt.payload.rts.num = 0;
	pkt.payload.rts.commands = NULL;

	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;

	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}

	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_conn_b1(DCERPC_CALL *pcall,
	char *connection_cookie, char *channel_cookie, uint32_t *plife_time,
	uint32_t *pclient_keepalive, char *associationgroupid)
{
	DCERPC_RTS *prts;
	
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (6 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, connection_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[2].command.cookie, channel_cookie, 64);
	
	if (RTS_CMD_CHANNEL_LIFETIME != prts->commands[3].command_type) {
		return FALSE;
	}
	*plife_time = prts->commands[3].command.channellifetime;
	
	if (RTS_CMD_CLIENT_KEEPALIVE != prts->commands[4].command_type) {
		return FALSE;
	}
	*pclient_keepalive = prts->commands[4].command.clientkeepalive;
	
	if (RTS_CMD_ASSOCIATION_GROUP_ID !=
		prts->commands[5].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[5].command.associationgroupid,
		associationgroupid, 64);
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_conn_a1(DCERPC_CALL *pcall,
	char *connection_cookie, char *channel_cookie, uint32_t *pwindow_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (4 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, connection_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[2].command.cookie, channel_cookie, 64);
	
	if (RTS_CMD_RECEIVE_WINDOW_SIZE != prts->commands[3].command_type) {
		return FALSE;
	}
	*pwindow_size = prts->commands[3].command.receivewindowsize;
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_inr2_a1(DCERPC_CALL *pcall,
	char *connection_cookie, char *pred_cookie, char *succ_cookie)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (4 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_VERSION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, connection_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[2].command.cookie, pred_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[3].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[3].command.cookie, succ_cookie, 64);
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_inr2_a5(DCERPC_CALL *pcall,
	char *succ_cookie)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, succ_cookie, 64);
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_a7(DCERPC_CALL *pcall,
	char *succ_cookie)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (3 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_DESTINATION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, succ_cookie, 64);
	
	if (RTS_CMD_VERSION != prts->commands[2].command_type) {
		return FALSE;
	}
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_a3(DCERPC_CALL *pcall,
	char *connection_cookie, char *pred_cookie, char *succ_cookie,
	uint32_t *pwindow_size)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (5 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_VERSION != prts->commands[0].command_type) {
		return FALSE;
	}
	if (RTS_CMD_COOKIE != prts->commands[1].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[1].command.cookie, connection_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[2].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[2].command.cookie, pred_cookie, 64);
	
	if (RTS_CMD_COOKIE != prts->commands[3].command_type) {
		return FALSE;
	}
	guid_to_string(&prts->commands[3].command.cookie, succ_cookie, 64);
		
	if (RTS_CMD_RECEIVE_WINDOW_SIZE != prts->commands[4].command_type) {
		return FALSE;
	}
	*pwindow_size = prts->commands[4].command.receivewindowsize;
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_outr2_c1(DCERPC_CALL *pcall)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_EMPTY != prts->commands[0].command_type &&
		RTS_CMD_PADDING != prts->commands[0].command_type) {
		return FALSE;
	}
	
	return TRUE;
	
}

static BOOL pdu_processor_retrieve_keep_alive(DCERPC_CALL *pcall,
	uint32_t *pkeep_alive)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (1 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_CLIENT_KEEPALIVE != prts->commands[0].command_type) {
		return FALSE;
	}
	
	*pkeep_alive = prts->commands[0].command.clientkeepalive;
	
	return TRUE;
}

static BOOL pdu_processor_retrieve_flowcontrolack_withdestination(
	DCERPC_CALL *pcall)
{
	DCERPC_RTS *prts;
	
	if (DCERPC_PKT_RTS != pcall->pkt.pkt_type) {
		return FALSE;
	}
	
	prts = &pcall->pkt.payload.rts;
	
	if (2 != prts->num) {
		return FALSE;
	}
	
	if (RTS_CMD_DESTINATION != prts->commands[0].command_type ||
		RTS_CMD_FLOW_CONTROL_ACK != prts->commands[1].command_type) {
		return FALSE;
	}
	return TRUE;
}

static BOOL pdu_processor_rts_conn_a3(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a conn/a3 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = malloc(sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_CONNECTION_TIMEOUT;
	pkt.payload.rts.commands[0].command.connectiontimeout =
							http_parser_get_param(HTTP_SESSION_TIMEOUT)*1000;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_conn_c2(DCERPC_CALL *pcall, uint32_t in_window_size)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a conn/c2 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 3;
	pkt.payload.rts.commands = malloc(3*sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_VERSION;
	pkt.payload.rts.commands[0].command.version = 1;
	pkt.payload.rts.commands[1].command_type = RTS_CMD_RECEIVE_WINDOW_SIZE;
	pkt.payload.rts.commands[1].command.receivewindowsize = in_window_size;
	pkt.payload.rts.commands[2].command_type = RTS_CMD_CONNECTION_TIMEOUT;
	pkt.payload.rts.commands[2].command.connectiontimeout =
							http_parser_get_param(HTTP_SESSION_TIMEOUT)*1000;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_inr2_a4(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a r2/a4 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = malloc(sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_a2(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a r2/a4 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_RECYCLE_CHANNEL;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = malloc(sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_a6(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a r2/a6 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_NONE;
	pkt.payload.rts.num = 2;
	pkt.payload.rts.commands = malloc(2*sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	pkt.payload.rts.commands[1].command_type = RTS_CMD_ANCE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_outr2_b3(DCERPC_CALL *pcall)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a r2/b3 */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = pcall->pkt.call_id;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_EOF;
	pkt.payload.rts.num = 1;
	pkt.payload.rts.commands = malloc(sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_ANCE;
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

BOOL pdu_processor_rts_flowcontrolack_withdestination(
	DCERPC_CALL *pcall, uint32_t bytes_received,
	uint32_t available_window, const char *channel_cookie)
{
	BLOB_NODE *pblob_node;
	DCERPC_NCACN_PACKET pkt;
	
	
	pblob_node = lib_buffer_get(g_bnode_allocator);
	if (NULL == pblob_node) {
		return FALSE;
	}
	pblob_node->node.pdata = pblob_node;
	pblob_node->b_rts = TRUE;
	/* setup a FlowControlAckWithDestination */
	pdu_processor_init_hdr(&pkt, pcall->b_bigendian);
	pkt.auth_length = 0;
	pkt.call_id = 0;
	pkt.pkt_type = DCERPC_PKT_RTS;
	pkt.pfc_flags = DCERPC_PFC_FLAG_FIRST | DCERPC_PFC_FLAG_LAST;
	pkt.payload.rts.flags = RTS_FLAG_OTHER_CMD;
	pkt.payload.rts.num = 2;
	pkt.payload.rts.commands = malloc(2*sizeof(RTS_CMD));
	if (NULL == pkt.payload.rts.commands) {
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pkt.payload.rts.commands[0].command_type = RTS_CMD_DESTINATION;
	pkt.payload.rts.commands[0].command.destination = FD_CLIENT;
	
	pkt.payload.rts.commands[1].command_type = RTS_CMD_FLOW_CONTROL_ACK;
	pkt.payload.rts.commands[1].command.flowcontrolack.bytes_received = bytes_received;
	pkt.payload.rts.commands[1].command.flowcontrolack.available_window = available_window;
	guid_from_string(&pkt.payload.rts.commands[1].command.flowcontrolack.channel_cookie,
		channel_cookie);
	
	if (FALSE == pdu_processor_ncacn_push_with_auth(&pblob_node->blob,
		&pkt, NULL)) {
		pdu_ndr_free_ncacnpkt(&pkt);
		lib_buffer_put(g_bnode_allocator, pblob_node);
		return FALSE;
	}
	
	pdu_ndr_free_ncacnpkt(&pkt);
	
	double_list_append_as_tail(&pcall->reply_list, &pblob_node->node);
	
	return TRUE;
}

int pdu_processor_rts_input(const char *pbuff, uint16_t length,
	DCERPC_CALL **ppcall)
{
	NDR_PULL ndr;
	uint32_t flags;
	BOOL b_bigendian;
	DCERPC_CALL *pcall;
	uint32_t keep_alive;
	HTTP_CONTEXT *pcontext;
	char channel_cookie[64];
	RPC_IN_CHANNEL *pchannel_in;
	RPC_OUT_CHANNEL *pchannel_out;
	
	/* only rts pdu can be processed by this function */
	if (DCERPC_PKT_RTS != CVAL(pbuff, DCERPC_PTYPE_OFFSET)) {
		return PDU_PROCESSOR_FORWARD;
	}
	
	flags = 0;
	
	if (0 == (CVAL(pbuff, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE)) {
		flags |= NDR_FLAG_BIGENDIAN;
		b_bigendian = TRUE;
	} else {
		b_bigendian = FALSE;
	}

	if (CVAL(pbuff, DCERPC_PFC_OFFSET) & DCERPC_PFC_FLAG_OBJECT_UUID) {
		flags |= NDR_FLAG_OBJECT_PRESENT;
	}
	
	pcontext = http_parser_get_context();
	if (NULL == pcontext) {
		return PDU_PROCESSOR_ERROR;
	}
	
	ndr_pull_init(&ndr, (uint8_t *)pbuff, length, flags);
	
	pcall = (DCERPC_CALL*)lib_buffer_get(g_call_allocator);
	if (NULL == pcall) {
		return PDU_PROCESSOR_ERROR;
	}
	memset(pcall, 0, sizeof(DCERPC_CALL));
	pcall->node.pdata = pcall;
	pcall->pprocessor = NULL;
	pcall->b_bigendian = b_bigendian;
	gettimeofday(&pcall->time, NULL);
	double_list_init(&pcall->reply_list);
	
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_ncacnpkt(&ndr, &pcall->pkt)) {
		ndr_pull_destroy(&ndr);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	ndr_pull_destroy(&ndr);
	
	pcall->pkt_loaded = TRUE;
	
	
	if (CHANNEL_TYPE_OUT == pcontext->channel_type) {
		pchannel_out = (RPC_OUT_CHANNEL*)pcontext->pchannel;
		if (76 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (FALSE == pdu_processor_retrieve_conn_a1(pcall,
				pchannel_out->connection_cookie,
				pchannel_out->channel_cookie,
				&pchannel_out->window_size)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_out->available_window = pchannel_out->window_size;
			if (FALSE == http_parser_try_create_vconnection(pcontext)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (FALSE == pdu_processor_rts_conn_a3(pcall)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		} else if (96 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_RECYCLE_CHANNEL != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process outr2/a3 rts pdu and do recycling */
			if (FALSE == pdu_processor_retrieve_outr2_a3(pcall,
				pchannel_out->connection_cookie, channel_cookie,
				pchannel_out->channel_cookie,
				&pchannel_out->window_size)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_out->available_window = pchannel_out->window_size;
			pdu_processor_free_call(pcall);
			if (FALSE == http_parser_recycle_outchannel(pcontext, channel_cookie)) {
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_out->channel_stat = CHANNEL_STAT_RECYCLING;
			return PDU_PROCESSOR_INPUT;
		} else if (24 == length) {
			if (CHANNEL_STAT_RECYCLING != pchannel_out->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (RTS_FLAG_PING != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			if (FALSE == pdu_processor_retrieve_outr2_c1(pcall)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		}
	} else if (CHANNEL_TYPE_IN == pcontext->channel_type) {
		pchannel_in = (RPC_IN_CHANNEL*)pcontext->pchannel;
		if (104 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process conn/b1 rts pdu and do connection to out channel */ 
			if (FALSE == pdu_processor_retrieve_conn_b1(pcall,
				pchannel_in->connection_cookie,
				pchannel_in->channel_cookie,
				&pchannel_in->life_time,
				&pchannel_in->client_keepalive,
				pchannel_in->assoc_group_id)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pdu_processor_free_call(pcall);
			/* notify out channel to send conn/c2 to client */
			if (FALSE == http_parser_try_create_vconnection(pcontext)) {
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_in->channel_stat = CHANNEL_STAT_OPENED;
			return PDU_PROCESSOR_INPUT;
		} else if (88 == length) {
			if (CHANNEL_STAT_OPENSTART != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_RECYCLE_CHANNEL != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			/* process inr2/a1 rts pdu and do recycling */
			if (FALSE == pdu_processor_retrieve_inr2_a1(pcall,
				pchannel_in->connection_cookie, channel_cookie,
				pchannel_in->channel_cookie)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (FALSE == http_parser_recycle_inchannel(pcontext, channel_cookie)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pchannel_in->channel_stat = CHANNEL_STAT_OPENED;
			pdu_processor_rts_inr2_a4(pcall);
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		} else if (28 == length) {
			/*
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*/
			if (RTS_FLAG_OTHER_CMD != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (FALSE == pdu_processor_retrieve_keep_alive(pcall,
				&keep_alive)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			/* MS-RPCH 2.2.3.5.6 */
			if (0 == keep_alive) {
				keep_alive = 300000;
			} else if (keep_alive < 60000) {
				keep_alive = 60000;
			}
			pchannel_in->client_keepalive = keep_alive;
			http_parser_set_keep_alive(pcontext, keep_alive);
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_INPUT;
		} else if (40 == length) {
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_NONE != pcall->pkt.payload.rts.flags) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (FALSE == pdu_processor_retrieve_inr2_a5(pcall,
				channel_cookie)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			pdu_processor_free_call(pcall);
			if (TRUE == http_parser_activate_inrecycling(pcontext,
				channel_cookie)) {
				return PDU_PROCESSOR_TERMINATE;
			}
			return PDU_PROCESSOR_INPUT;
		} else if (56 == length) {
			if (CHANNEL_STAT_OPENED != pchannel_in->channel_stat) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			if (RTS_FLAG_OTHER_CMD == pcall->pkt.payload.rts.flags) {
				if (FALSE == pdu_processor_retrieve_flowcontrolack_withdestination(
					pcall)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				http_parser_set_outchannel_flowcontrol(pcontext,
					pcall->pkt.payload.rts.commands[1].command.flowcontrolack.bytes_received,
					pcall->pkt.payload.rts.commands[1].command.flowcontrolack.available_window);
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_INPUT;
			} else if (RTS_FLAG_OUT_CHANNEL == pcall->pkt.payload.rts.flags) {
				if (FALSE == pdu_processor_retrieve_outr2_a7(pcall,
					channel_cookie)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				pdu_processor_free_call(pcall);
				http_parser_activate_outrecycling(pcontext, channel_cookie);
				return PDU_PROCESSOR_INPUT;
			} else {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
		} else if (20 == length) {
			if (RTS_FLAG_PING == pcall->pkt.payload.rts.flags &&
				0 == pcall->pkt.payload.rts.num) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_INPUT;
			}
		}
	}
	
	debug_info("[pdu_processor]: unknown pdu in RTS process procedure\n");
	
	pdu_processor_free_call(pcall);
	return PDU_PROCESSOR_ERROR;
}

int pdu_processor_input(PDU_PROCESSOR *pprocessor, const char *pbuff,
	uint16_t length, DCERPC_CALL **ppcall)
{
	void *pdata;
	NDR_PULL ndr;
	BOOL b_async;
	BOOL b_result;
	uint32_t flags;
	BOOL b_bigendian;
	DATA_BLOB tmp_blob;
	DCERPC_CALL *pcall;
	DCERPC_CALL *pcallx;
	uint32_t alloc_size;
	DCERPC_REQUEST *prequest;
	DCERPC_REQUEST *prequestx;
	
	
	flags = 0;
	*ppcall = NULL;
	if (0 == (CVAL(pbuff, DCERPC_DREP_OFFSET) & DCERPC_DREP_LE)) {
		flags |= NDR_FLAG_BIGENDIAN;
		b_bigendian = TRUE;
	} else {
		b_bigendian = FALSE;
	}
	if (CVAL(pbuff, DCERPC_PFC_OFFSET) & DCERPC_PFC_FLAG_OBJECT_UUID) {
		flags |= NDR_FLAG_OBJECT_PRESENT;
	}
	
	ndr_pull_init(&ndr, (uint8_t *)pbuff, length, flags);
	
	pcall = (DCERPC_CALL*)lib_buffer_get(g_call_allocator);
	if (NULL == pcall) {
		return PDU_PROCESSOR_ERROR;
	}
	memset(pcall, 0, sizeof(DCERPC_CALL));
	pcall->node.pdata = pcall;
	pcall->pprocessor = pprocessor;
	pcall->b_bigendian = b_bigendian;
	gettimeofday(&pcall->time, NULL);
	double_list_init(&pcall->reply_list);
	
	if (NDR_ERR_SUCCESS != pdu_ndr_pull_ncacnpkt(&ndr, &pcall->pkt)) {
		ndr_pull_destroy(&ndr);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	ndr_pull_destroy(&ndr);
	
	pcall->pkt_loaded = TRUE;
	
	if (pcall->pkt.frag_length != length) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	}
	
	/* we only allow fragmented requests, no other packet types */
	if ((0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) ||
		0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) &&
		pcall->pkt.pkt_type != DCERPC_PKT_REQUEST) {
		if (FALSE == pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_ERROR;
		}
		*ppcall = pcall;
		return PDU_PROCESSOR_OUTPUT;
	}
	
	if (DCERPC_PKT_REQUEST == pcall->pkt.pkt_type) {
		prequest = &pcall->pkt.payload.request;
		tmp_blob.data = (uint8_t*)pbuff;
		tmp_blob.length = length;
		if (FALSE == pdu_processor_auth_request(pcall, &tmp_blob)) {
			if (FALSE == pdu_processor_fault(pcall,
				DCERPC_FAULT_ACCESS_DENIED)) {
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			*ppcall = pcall;
			return PDU_PROCESSOR_OUTPUT;
		}

		if (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_FIRST) {
			if (0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
				alloc_size = prequest->alloc_hint;
				if (alloc_size < prequest->stub_and_verifier.length) {
					alloc_size = prequest->stub_and_verifier.length * 8;
				}
				if (alloc_size > g_max_request_mem) {
					if (FALSE == pdu_processor_fault(pcall,
						DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				alloc_size = ((alloc_size - 1) / (16*1024) + 1) * (16*1024);
				pdata = malloc(alloc_size);
				if (NULL == pdata) {
					if (FALSE == pdu_processor_fault(pcall,
						DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				
				memcpy(pdata, prequest->stub_and_verifier.data,
					prequest->stub_and_verifier.length);
				free(prequest->stub_and_verifier.data);
				prequest->stub_and_verifier.data = pdata;
				pcall->alloc_size = alloc_size;
			}
		} else {
			pcallx = pdu_processor_get_fragmented_call(
						pprocessor, pcall->pkt.call_id);
			if (NULL == pcallx) {
				if (FALSE == pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				*ppcall = pcall;
				return PDU_PROCESSOR_OUTPUT;
			}
			
			if (pcallx->pkt.pkt_type != pcall->pkt.pkt_type) {
				pdu_processor_free_call(pcallx);
				if (FALSE == pdu_processor_fault(pcall, DCERPC_FAULT_OTHER)) {
					pdu_processor_free_call(pcall);
					return PDU_PROCESSOR_ERROR;
				}
				
				*ppcall = pcall;
				return PDU_PROCESSOR_OUTPUT;
			}
			
			prequestx = &pcallx->pkt.payload.request;

			alloc_size = prequestx->stub_and_verifier.length +
							prequest->stub_and_verifier.length;
			if (prequestx->alloc_hint > alloc_size) {
				alloc_size = prequestx->alloc_hint;
			}
			
			if (pcallx->alloc_size < alloc_size) {
				if (alloc_size > g_max_request_mem) {
					pdu_processor_free_call(pcallx);
					if (FALSE == pdu_processor_fault(pcall,
						DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}	
				
				alloc_size = ((alloc_size - 1) / (16*1024) + 1) * (16*1024);

				pdata = malloc(alloc_size);
				if (NULL == pdata) {
					pdu_processor_free_call(pcallx);
					if (FALSE == pdu_processor_fault(pcall,
						DCERPC_FAULT_OTHER)) {
						pdu_processor_free_call(pcall);
						return PDU_PROCESSOR_ERROR;
					}
					*ppcall = pcall;
					return PDU_PROCESSOR_OUTPUT;
				}
				memcpy(pdata, prequestx->stub_and_verifier.data,
					prequestx->stub_and_verifier.length);
				free(prequestx->stub_and_verifier.data);
				prequestx->stub_and_verifier.data = pdata;
				pcallx->alloc_size = alloc_size;
			}
				
			memcpy(prequestx->stub_and_verifier.data +
				prequestx->stub_and_verifier.length,
				prequest->stub_and_verifier.data,
				prequest->stub_and_verifier.length);
			
			prequestx->stub_and_verifier.length +=
				prequest->stub_and_verifier.length;

			pcallx->pkt.pfc_flags |= pcall->pkt.pfc_flags&DCERPC_PFC_FLAG_LAST;
			pdu_processor_free_call(pcall);
			pcall = pcallx;
		}
		

		/* this may not be the last pdu in the chain - if its isn't then
		just put it on the fragmented_list and wait for the rest */
		if (0 == (pcall->pkt.pfc_flags & DCERPC_PFC_FLAG_LAST)) {
			if (double_list_get_nodes_num(&pprocessor->fragmented_list) >
				MAX_FRAGMENTED_CALLS) {
				debug_info("[pdu_processor]: maximum fragments"
					" number of call reached\n");
				pdu_processor_free_call(pcall);
				return PDU_PROCESSOR_ERROR;
			}
			
			double_list_append_as_tail(&pprocessor->fragmented_list,
				&pcall->node);
			*ppcall = pcall;
			return PDU_PROCESSOR_INPUT;
		}
	}
	
	switch (pcall->pkt.pkt_type) {
	case DCERPC_PKT_BIND:
		b_result = pdu_processor_process_bind(pcall);
		break;
	case DCERPC_PKT_AUTH3:
		b_result = pdu_processor_process_auth3(pcall);
		if (TRUE == b_result) {
			pdu_processor_free_call(pcall);
			return PDU_PROCESSOR_INPUT;
		}
		break;
	case DCERPC_PKT_ALTER:
		b_result = pdu_processor_process_alter(pcall);
		break;
	case DCERPC_PKT_REQUEST:
		b_result = pdu_processor_process_request(pcall, &b_async);
		if (TRUE == b_result && TRUE == b_async) {
			return PDU_PROCESSOR_INPUT;
		}
		break;
	case DCERPC_PKT_CO_CANCEL:
		pdu_processor_process_cancel(pcall);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_INPUT;
	case DCERPC_PKT_ORPHANED:
		pdu_processor_process_orphaned(pcall);
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_INPUT;
	default:
		b_result = FALSE;
		debug_info("[pdu_processor]: invalid ncancn packet type "
			"in process procedure\n");
		break;
	}
	
	if (FALSE == b_result) {
		pdu_processor_free_call(pcall);
		return PDU_PROCESSOR_ERROR;
	} else {
		*ppcall = pcall;
		return PDU_PROCESSOR_OUTPUT;
	}
}

static DCERPC_ENDPOINT* pdu_processor_register_endpoint(const char *host,
	int tcp_port)
{
	DOUBLE_LIST_NODE *pnode;
	DCERPC_ENDPOINT *pendpoint;
	
	for (pnode=double_list_get_head(&g_endpoint_list); NULL!=pnode;
		pnode=double_list_get_after(&g_endpoint_list, pnode)) {
		pendpoint = (DCERPC_ENDPOINT*)pnode->pdata;
		if (0 == strcasecmp(pendpoint->host, host) &&
			tcp_port == pendpoint->tcp_port) {
			return pendpoint;
		}
	}
	pendpoint = malloc(sizeof(DCERPC_ENDPOINT));
	if (NULL == pendpoint) {
		return NULL;
	}
	pendpoint->node.pdata = pendpoint;
	strcpy(pendpoint->host, host);
	pendpoint->tcp_port = tcp_port;
	pendpoint->last_group_id = 0;
	double_list_init(&pendpoint->interface_list);
	double_list_append_as_tail(&g_endpoint_list, &pendpoint->node);
	return pendpoint;
}

static BOOL pdu_processor_register_interface(DCERPC_ENDPOINT *pendpoint,
	DCERPC_INTERFACE *pinterface)
{
	DOUBLE_LIST_NODE *pnode;
	INTERFACE_NODE *pif_node;
	DCERPC_INTERFACE *pinterface1;
	
	
	if (NULL == pinterface->ndr_pull) {
		printf("[pdu_processor]: ndr_pull of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	if (NULL == pinterface->dispatch) {
		printf("[pdu_processor]: dispatch of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	if (NULL == pinterface->ndr_push) {
		printf("[pdu_processor]: ndr_push of interface %s cannot be NULL\n",
			pinterface->name);
		return FALSE;
	}
	for (pnode=double_list_get_head(&pendpoint->interface_list); NULL!=pnode;
		pnode=double_list_get_after(&pendpoint->interface_list, pnode)) {
		pinterface1 = (DCERPC_INTERFACE*)pnode->pdata;
		if (pinterface1->version == pinterface->version &&
			0 == guid_compare(&pinterface1->uuid, &pinterface->uuid)) {
			printf("[pdu_processor]: interface already exists under "
				"endpoint %s:%d\n", pendpoint->host, pendpoint->tcp_port);
			return FALSE;
		}
	}
	
	pnode = malloc(sizeof(DOUBLE_LIST_NODE));
	if (NULL == pnode) {
		return FALSE;
	}
	
	pnode->pdata = malloc(sizeof(DCERPC_INTERFACE));
	if (NULL == pnode->pdata) {
		free(pnode);
		return FALSE;
	}
	pif_node = malloc(sizeof(INTERFACE_NODE));
	if (NULL == pif_node) {
		free(pnode->pdata);
		free(pnode);
		return FALSE;
	}
	memcpy(pnode->pdata, pinterface, sizeof(DCERPC_INTERFACE));
	double_list_append_as_tail(&pendpoint->interface_list, pnode);
	pif_node->node.pdata = pif_node;
	pif_node->pendpoint = pendpoint;
	pif_node->pinterface = pnode->pdata;
	double_list_append_as_tail(&g_cur_plugin->interface_list, &pif_node->node);
	return TRUE;
}

static void pdu_processor_unload_library(const char* plugin_name)
{
	PLUGIN_MAIN func;
	DOUBLE_LIST *plist;
	PROC_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	INTERFACE_NODE *pif_node;
	
	
    /* first find the plugin node in lib list */
    for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)){
		pplugin = (PROC_PLUGIN*)pnode->pdata;
		if (0 == strcmp(pplugin->file_name, plugin_name)) {
			break;
		}
	}
    if (NULL == pnode){
        return;
    }
	
	while (pnode=double_list_get_from_head(&pplugin->interface_list)) {
		pif_node = (INTERFACE_NODE*)pnode->pdata;
		plist = &pif_node->pendpoint->interface_list;
		for (pnode1=double_list_get_head(plist); NULL!=pnode1;
			pnode1=double_list_get_after(plist, pnode1)) {
			if (pif_node->pinterface == pnode1->pdata) {
				double_list_remove(plist, pnode1);
				free(pnode1->pdata);
				free(pnode1);
				break;
			}
		}
		free(pif_node);
	}
	double_list_free(&pplugin->interface_list);
	
	func = (PLUGIN_MAIN)pplugin->lib_main;
	/* notify the plugin that it willbe unloaded */
	func(PLUGIN_FREE, NULL);
	
	/* free the reference list */
	while ((pnode = double_list_get_from_head(&pplugin->list_reference))) {
		service_release(((SERVICE_NODE*)(pnode->pdata))->service_name,
			pplugin->file_name);
		free(((SERVICE_NODE*)(pnode->pdata))->service_name);
		free(pnode->pdata);
	}
	double_list_free(&pplugin->list_reference);
	
	double_list_remove(&g_plugin_list, &pplugin->node);
	dlclose(pplugin->handle);
	free(pplugin);
}

static BOOL pdu_processor_register_talk(TALK_MAIN talk)
{
    if(NULL == g_cur_plugin) {
        return FALSE;
    }
    g_cur_plugin->talk_main = talk;
    return TRUE;
}

static BOOL pdu_processor_unregister_talk(TALK_MAIN talk)
{
	PROC_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (PROC_PLUGIN*)(pnode->pdata);
		if (pplugin->talk_main == talk) {
			pplugin->talk_main = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

static const char *pdu_processor_get_host_ID()
{
	return resource_get_string(RES_HOST_ID);
}

static const char* pdu_processor_get_default_domain()
{
	return resource_get_string(RES_DEFAULT_DOMAIN);
}

static const char* pdu_processor_get_plugin_name()
{
	if (NULL == g_cur_plugin) {
		return NULL;
	}
	return g_cur_plugin->file_name;
}

static const char* pdu_processor_get_config_path()
{
    const char *ret_value;

    ret_value = resource_get_string(RES_CONFIG_FILE_PATH);
    if (NULL == ret_value) {
        ret_value = "../config";
    }
    return ret_value;
}

static const char* pdu_processor_get_data_path()
{
    const char *ret_value;

    ret_value = resource_get_string(RES_DATA_FILE_PATH);
    if (NULL == ret_value) {
        ret_value = "../data";
    }
    return ret_value;
}

static int pdu_processor_get_context_num()
{
	return g_connection_num;
}

static int pdu_processor_getversion()
{
	return SERVICE_VERSION;
}

/* this function can also be invoked from hpm_plugins,
	you should firt set context TLS before call this
	function, if you don't do that, you will get nothing
*/
static DCERPC_INFO pdu_processor_get_rpc_info()
{
	DCERPC_INFO info;
	DCERPC_CALL *pcall;
	HTTP_CONTEXT *pcontext;
	
	memset(&info, 0, sizeof(DCERPC_INFO));
	pcall = pdu_processor_get_call();
	pcontext = http_parser_get_context();
	if (NULL != pcontext) {
		info.client_ip = pcontext->connection.client_ip;
		info.client_port = pcontext->connection.client_port;
		info.server_ip = pcontext->connection.server_ip;
		info.server_port = pcontext->connection.server_port;
		info.ep_host = pcontext->host;
		info.ep_port = pcontext->port;
		info.username = pcontext->username;
		info.maildir = pcontext->maildir;
		info.lang = pcontext->lang;
	}
	if (NULL != pcall) {
		if (NULL == pcall->pauth_ctx) {
			info.is_login = FALSE;
		} else {
			info.is_login = pcall->pauth_ctx->is_login;
		}
		if (NULL != pcall->pcontext) {
			info.stat_flags = pcall->pcontext->stat_flags;
		}
	} else {
		if (NULL == pcontext || '\0' == pcontext->username[0]) {
			info.is_login = FALSE;
		} else {
			info.is_login = TRUE;
		}
		info.stat_flags = 0;
	}
	return info;
}

static BOOL pdu_processor_is_rpc_bigendian()
{
	DCERPC_CALL *pcall;
	
	pcall = pdu_processor_get_call();
	if (NULL != pcall) {
		return pcall->b_bigendian;
	}
	return g_bigendian;
}

static uint64_t pdu_processor_get_binding_handle()
{
	uint64_t handle;
	DCERPC_CALL *pcall;
	
	pcall = pdu_processor_get_call();
	if (NULL != pcall) {
		handle = pcall->pcontext->assoc_group_id;
		handle <<= 32;
		handle |= pcall->pcontext->context_id;
		return handle;
	}
	return 0;
}

static void* pdu_processor_queryservice(char *service)
{
	DOUBLE_LIST_NODE *pnode;
	SERVICE_NODE *pservice;
	void *ret_addr;

	if (NULL == g_cur_plugin) {
		return NULL;
	}
	if (strcmp(service, "register_endpoint") == 0) {
		return pdu_processor_register_endpoint;
	}
	if (strcmp(service, "register_interface") == 0) {
		return pdu_processor_register_interface;
	}
	if (strcmp(service, "register_talk") == 0) {
		return pdu_processor_register_talk;
	}
	if (strcmp(service, "unregister_talk") == 0) {
		return pdu_processor_unregister_talk;
	}
	if (strcmp(service, "get_host_ID") == 0) {
		return pdu_processor_get_host_ID;
	}
	if (strcmp(service, "get_default_domain") == 0) {
		return pdu_processor_get_default_domain;
	}
	if (strcmp(service, "get_plugin_name") == 0) {
		return pdu_processor_get_plugin_name;
	}
	if (strcmp(service, "get_config_path") == 0) {
		return pdu_processor_get_config_path;
	}
	if (strcmp(service, "get_data_path") == 0) {
		return pdu_processor_get_data_path;
	}
	if (strcmp(service, "get_context_num") == 0) {
		return pdu_processor_get_context_num;
	}
	if (strcmp(service, "get_binding_handle") == 0) {
		return pdu_processor_get_binding_handle;
	}
	if (strcmp(service, "get_rpc_info") == 0) {
		return pdu_processor_get_rpc_info;
	}
	if (strcmp(service, "is_rpc_bigendian") == 0) {
		return pdu_processor_is_rpc_bigendian;
	}
	if (strcmp(service, "ndr_stack_alloc") == 0) {
		return pdu_processor_ndr_stack_alloc;
	}
	if (strcmp(service, "apply_async_id") == 0) {
		return pdu_processor_apply_async_id;
	}
	if (strcmp(service, "activate_async_id") == 0) {
		return pdu_processor_activate_async_id;
	}
	if (strcmp(service, "cancel_async_id") == 0) {
		return pdu_processor_cancel_async_id;
	}
	if (strcmp(service, "rpc_build_environment") == 0) {
		return pdu_processor_rpc_build_environment;
	}
	if (strcmp(service, "rpc_new_environment") == 0) {
		return pdu_processor_rpc_new_environment;
	}
	if (strcmp(service, "rpc_free_environment") == 0) {
		return pdu_processor_rpc_free_environment;
	}
	if (strcmp(service, "async_reply") == 0) {
		return pdu_processor_async_reply;
	}
	/* check if already exists in the reference list */
	for (pnode=double_list_get_head(&g_cur_plugin->list_reference);
		NULL!=pnode;
		pnode=double_list_get_after(&g_cur_plugin->list_reference, pnode)) {
        pservice =  (SERVICE_NODE*)(pnode->pdata);
		if (0 == strcmp(service, pservice->service_name)) {
			return pservice->service_addr;
		}
	}
	ret_addr = service_query(service, g_cur_plugin->file_name);
	if (NULL == ret_addr) {
		return NULL;
	}
	pservice = (SERVICE_NODE*)malloc(sizeof(SERVICE_NODE));
	if (NULL == pservice) {
		debug_info("[pdu_processor]: fail to allocate memory "
			"for service node\n");
		service_release(service, g_cur_plugin->file_name);
		return NULL;
	}
	pservice->service_name = (char*)malloc(strlen(service) + 1);
	if (NULL == pservice->service_name) {
		debug_info("[pdu_processor]: fail to allocate memory "
			"for service name\n");
		service_release(service, g_cur_plugin->file_name);
		free(pservice);
		return NULL;
	}
	strcpy(pservice->service_name, service);
	pservice->node.pdata = pservice;
	pservice->service_addr = ret_addr;
	double_list_append_as_tail(&g_cur_plugin->list_reference,
		&pservice->node);
	return ret_addr;
}

/*
 *	load the hook plugin
 *	@param
 *		path [in]					plugin name
 *	@return
 *		PLUGIN_LOAD_OK				OK
 *		PLUGIN_ALREADY_LOADED		plugin is already loaded
 *		PLUGIN_FAIL_OPEN			fail to open share library
 *		PLUGIN_NO_MAIN				cannot find main entry
 *		PLUGIN_FAIL_ALLOCNODE		fail to allocate node for plugin
 *		PLUGIN_FAIL_EXCUTEMAIN		main entry in plugin returns FALSE
 */
static int pdu_processor_load_library(const char* plugin_name)
{
	void *handle;
	PLUGIN_MAIN func;
	PROC_PLUGIN *pplugin;
	void* two_server_funcs[2];
	char buf[256], fake_path[256];
	
	two_server_funcs[0] = (void*)pdu_processor_getversion;
	two_server_funcs[1] = (void*)pdu_processor_queryservice;
	
	snprintf(fake_path, 256, "%s/%s", g_plugins_path, plugin_name);

	handle = dlopen(fake_path, RTLD_LAZY);
	if (NULL == handle){
		printf("[pdu_processor]: error to load %s reason: %s\n", fake_path,
			dlerror());
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
    }
	func = (PLUGIN_MAIN)dlsym(handle, "PROC_LibMain");
	if (NULL == func) {
		printf("[pdu_processor]: error to find PROC_LibMain function in %s\n",
			fake_path);
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_NO_MAIN;
	}
	pplugin = malloc(sizeof(PROC_PLUGIN));
    if (NULL == pplugin) {
		printf("[pdu_processor]: fail to allocate memory for %s\n", fake_path);
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_FAIL_ALLOCNODE;
	}
	
	memset(pplugin, 0, sizeof(PROC_PLUGIN));
	pplugin->node.pdata = pplugin;
	double_list_init(&pplugin->list_reference);
	double_list_init(&pplugin->interface_list);
	strncpy(pplugin->file_name, plugin_name, 255);
	pplugin->handle = handle;
	pplugin->lib_main = func;
	
	/* append the pendpoint node into endpoint list */
	double_list_append_as_tail(&g_plugin_list, &pplugin->node);
	g_cur_plugin = pplugin;
    /* invoke the plugin's main function with the parameter of PLUGIN_INIT */
    if (FALSE == func(PLUGIN_INIT, (void**)two_server_funcs)) {
		printf("[pdu_processor]: error to excute plugin's init function "
			"in %s\n", fake_path);
		printf("[pdu_processor]: the plugin %s is not loaded\n", fake_path);
		/*
		 *  the lib node will automatically removed from plugin list in
		 *  pdu_processor_unload_library function
		 */
        pdu_processor_unload_library(plugin_name);
		g_cur_plugin = NULL;
		return PLUGIN_FAIL_EXCUTEMAIN;
	}
		
	g_cur_plugin = NULL;
	return PLUGIN_LOAD_OK;
}

int pdu_processor_console_talk(int argc, char** argv, char *result, int length)
{
	PROC_PLUGIN *pplugin;
	DOUBLE_LIST_NODE *pnode;

	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		pplugin = (PROC_PLUGIN*)(pnode->pdata);
		if (0 == strncmp(pplugin->file_name, argv[0], 256)) {
			if (NULL != pplugin->talk_main) {
				pplugin->talk_main(argc, argv, result, length);
				return PLUGIN_TALK_OK;
			} else {
				return PLUGIN_NO_TALK;
			}
		}
	}
	return PLUGIN_NO_FILE;
}

void pdu_processor_enum_plugins(ENUM_PLUGINS enum_func)
{
	DOUBLE_LIST_NODE *pnode;

	if (NULL == enum_func) {
		return;
	}
	for (pnode=double_list_get_head(&g_plugin_list); NULL!=pnode;
		pnode=double_list_get_after(&g_plugin_list, pnode)) {
		enum_func(((PROC_PLUGIN*)(pnode->pdata))->file_name);
	}
}

void pdu_processor_enum_endpoints(void (*enum_ep)(DCERPC_ENDPOINT*))
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&g_endpoint_list); NULL!=pnode;
		pnode=double_list_get_after(&g_endpoint_list, pnode)) {
		enum_ep(pnode->pdata);
	}
}

void pdu_processor_enum_interfaces(DCERPC_ENDPOINT *pendpoint,
	void (*enum_if)(DCERPC_INTERFACE*))
{
	DOUBLE_LIST_NODE *pnode;
	
	for (pnode=double_list_get_head(&pendpoint->interface_list); NULL!=pnode;
		pnode=double_list_get_after(&pendpoint->interface_list, pnode)) {
		enum_if(pnode->pdata);
	}
}


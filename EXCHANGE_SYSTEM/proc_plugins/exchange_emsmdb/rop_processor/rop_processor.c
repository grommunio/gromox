#include "subscription_object.h"
#include "fastdownctx_object.h"
#include "attachment_object.h"
#include "icsdownctx_object.h"
#include "fastupctx_object.h"
#include "emsmdb_interface.h"
#include "icsupctx_object.h"
#include "notify_response.h"
#include "processor_types.h"
#include "message_object.h"
#include "rop_processor.h"
#include "stream_object.h"
#include "folder_object.h"
#include "table_object.h"
#include "rop_dispatch.h"
#include "exmdb_client.h"
#include "common_util.h"
#include "proc_common.h"
#include "simple_tree.h"
#include "lib_buffer.h"
#include "aux_types.h"
#include "str_hash.h"
#include "int_hash.h"
#include "rop_ext.h"
#include "util.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>


#define RPCEXT2_FLAG_NOCOMPRESSION		0x00000001
#define RPCEXT2_FLAG_NOXORMAGIC			0x00000002
#define RPCEXT2_FLAG_CHAIN				0x00000004

#define MAX_ROP_PAYLOADS				96

#define HGROWING_SIZE					250


/* maximum handle number per session */
#define MAX_HANDLE_NUM					500

typedef struct _LOGON_ITEM {
	INT_HASH_TABLE *phash;
	SIMPLE_TREE tree;
} LOGON_ITEM;

typedef struct _OBJECT_NODE {
	SIMPLE_TREE_NODE node;
	uint32_t handle;
	int type;
	void *pobject;
} OBJECT_NODE;

static int g_scan_interval;
static pthread_t g_scan_id;
static int g_average_handles;
static BOOL g_notify_stop = TRUE;
static pthread_mutex_t g_hash_lock;
static STR_HASH_TABLE *g_logon_hash;
static LIB_BUFFER *g_logmap_allocator;
static LIB_BUFFER *g_handle_allocator;
static LIB_BUFFER *g_logitem_allocator;


void* rop_processor_create_logmap()
{
	void *plogmap;
	
	plogmap = lib_buffer_get(g_logmap_allocator);
	if (NULL != plogmap) {
		memset(plogmap, 0, sizeof(LOGON_ITEM*)*256);
	}
	return plogmap;
}

static void rop_processor_enum_objnode(SIMPLE_TREE_NODE *pnode,
	void *pparam)
{
	LOGON_ITEM *plogitem;
	OBJECT_NODE *pobjnode;
	
	plogitem = (LOGON_ITEM*)pparam;
	pobjnode = (OBJECT_NODE*)pnode->pdata;
	int_hash_remove(plogitem->phash, pobjnode->handle);
}

static void rop_processor_free_object(void *pobject, int type)
{
	switch (type) {
	case OBJECT_TYPE_LOGON:
		logon_object_free(pobject);
		break;
	case OBJECT_TYPE_FOLDER:
		folder_object_free(pobject);
		break;
	case OBJECT_TYPE_MESSAGE:
		message_object_free(pobject);
		break;
	case OBJECT_TYPE_ATTACHMENT:
		attachment_object_free(pobject);
		break;
	case OBJECT_TYPE_TABLE:
		table_object_free(pobject);
		break;
	case OBJECT_TYPE_STREAM:
		stream_object_free(pobject);
		break;
	case OBJECT_TYPE_FASTDOWNCTX:
		fastdownctx_object_free(pobject);
		break;
	case OBJECT_TYPE_FASTUPCTX:
		fastupctx_object_free(pobject);
		break;
	case OBJECT_TYPE_ICSDOWNCTX:
		icsdownctx_object_free(pobject);
		break;
	case OBJECT_TYPE_ICSUPCTX:
		icsupctx_object_free(pobject);
		break;
	case OBJECT_TYPE_SUBSCRIPTION:
		subscription_object_free(pobject);
		break;
	}
}

static void rop_processor_free_objnode(SIMPLE_TREE_NODE *pnode)
{
	OBJECT_NODE *pobjnode;
	
	pobjnode = (OBJECT_NODE*)pnode->pdata;
	rop_processor_free_object(pobjnode->pobject, pobjnode->type);
	pobjnode->type = 0;
	pobjnode->pobject = NULL;
	lib_buffer_put(g_handle_allocator, pobjnode);
}

static void rop_processor_release_objnode(
	LOGON_ITEM *plogitem, OBJECT_NODE *pobjnode)
{
	BOOL b_root;
	void *pobject;
	uint32_t *pref;
	SIMPLE_TREE_NODE *proot;
	
	/* root is the logon object, free logon object
		will cause the logon item to be released
	*/
	if (simple_tree_get_root(&plogitem->tree) == &pobjnode->node) {
		proot = simple_tree_get_root(&plogitem->tree);
		pobject = ((OBJECT_NODE*)proot->pdata)->pobject;
		pthread_mutex_lock(&g_hash_lock);
		pref = str_hash_query(g_logon_hash,
				logon_object_get_dir(pobject));
		(*pref) --;
		if (0 == *pref) {
			str_hash_remove(g_logon_hash, logon_object_get_dir(pobject));
		}
		pthread_mutex_unlock(&g_hash_lock);
		b_root = TRUE;
	} else {
		b_root = FALSE;
	}
	simple_tree_enum_from_node(&pobjnode->node,
		rop_processor_enum_objnode, plogitem);
	simple_tree_destroy_node(&plogitem->tree,
		&pobjnode->node, rop_processor_free_objnode);
	if (TRUE == b_root) {
		simple_tree_free(&plogitem->tree);
		int_hash_free(plogitem->phash);
		plogitem->phash = NULL;
		lib_buffer_put(g_logitem_allocator, plogitem);
	}
}

static void rop_processor_release_logon_item(LOGON_ITEM *plogitem)
{
	SIMPLE_TREE_NODE *proot;
	
	proot = simple_tree_get_root(&plogitem->tree);
	if (NULL == proot) {
		debug_info("[exchange_emsmdb]: fatal error in"
				" rop_processor_release_logon_item\n");
	} else {
		rop_processor_release_objnode(plogitem, proot->pdata);
	}
}

void rop_processor_release_logmap(void *plogmap)
{
	int i;
	
	for (i=0; i<256; i++) {
		if (NULL != ((LOGON_ITEM**)plogmap)[i]) {
			rop_processor_release_logon_item(((LOGON_ITEM**)plogmap)[i]);
			((LOGON_ITEM**)plogmap)[i] = NULL;
		}
	}
	lib_buffer_put(g_logmap_allocator, plogmap);
}

int rop_processor_create_logon_item(void *plogmap,
	uint8_t logon_id, LOGON_OBJECT *plogon)
{
	int handle;
	uint32_t *pref;
	uint32_t tmp_ref;
	LOGON_ITEM *plogitem;
	
	plogitem = ((LOGON_ITEM**)plogmap)[logon_id];
	/* MS-OXCROPS 3.1.4.2 */
	if (NULL != plogitem) {
		rop_processor_release_logon_item(plogitem);
		((LOGON_ITEM**)plogmap)[logon_id] = NULL;
	}
	plogitem = lib_buffer_get(g_logitem_allocator);
	if (NULL == plogitem) {
		return -1;
	}
	plogitem->phash = int_hash_init(HGROWING_SIZE,
						sizeof(OBJECT_NODE*), NULL);
	if (NULL == plogitem->phash) {
		lib_buffer_put(g_logitem_allocator, plogitem);
		return -2;
	}
	simple_tree_init(&plogitem->tree);
	((LOGON_ITEM**)plogmap)[logon_id] = plogitem;
	handle = rop_processor_add_object_handle(plogmap,
				logon_id, -1, OBJECT_TYPE_LOGON, plogon);
	if (handle < 0) {
		lib_buffer_put(g_logitem_allocator, plogitem);
		return -3;
	}
	pthread_mutex_lock(&g_hash_lock);
	pref = str_hash_query(g_logon_hash, logon_object_get_dir(plogon));
	if (NULL == pref) {
		tmp_ref = 1;
		str_hash_add(g_logon_hash, logon_object_get_dir(plogon), &tmp_ref);
	} else {
		(*pref) ++;
	}
	pthread_mutex_unlock(&g_hash_lock);
	return handle;
}

int rop_processor_add_object_handle(void *plogmap, uint8_t logon_id,
	int parent_handle, int type, void *pobject)
{
	int tmp_handle;
	INT_HASH_ITER *iter;
	LOGON_ITEM *plogitem;
	INT_HASH_TABLE *phash;
	OBJECT_NODE *pobjnode;
	OBJECT_NODE *ptmphanle;
	OBJECT_NODE **ppparent;
	EMSMDB_INFO *pemsmdb_info;
	
	plogitem = ((LOGON_ITEM**)plogmap)[logon_id];
	if (NULL == plogitem) {
		return -1;
	}
	if (simple_tree_get_nodes_num(&plogitem->tree) > MAX_HANDLE_NUM) {
		return -3;
	}
	if (parent_handle < 0) {
		if (NULL != simple_tree_get_root(&plogitem->tree)) {
			return -4;
		}
		ppparent = NULL;
	} else if (parent_handle >= 0 && parent_handle < 0x7FFFFFFF) {
		ppparent = int_hash_query(plogitem->phash, parent_handle);
		if (NULL == ppparent) {
			return -5;
		}
	} else {
		return -6;
	}
	pobjnode = lib_buffer_get(g_handle_allocator);
	if (NULL == pobjnode) {
		return -7;
	}
	if (FALSE == emsmdb_interface_alloc_hanlde_number(
		&pobjnode->handle)) {
		return -8;
	}
	pobjnode->node.pdata = pobjnode;
	pobjnode->type = type;
	pobjnode->pobject = pobject;
	if (1 != int_hash_add(plogitem->phash, pobjnode->handle, &pobjnode)) {
		phash = int_hash_init(plogitem->phash->capacity + HGROWING_SIZE,
					sizeof(OBJECT_NODE*), NULL);
		if (NULL == phash) {
			lib_buffer_put(g_handle_allocator, pobjnode);
			return -8;
		}
		iter = int_hash_iter_init(plogitem->phash);
		for (int_hash_iter_begin(iter); !int_hash_iter_done(iter);
			int_hash_iter_forward(iter)) {
			ptmphanle = int_hash_iter_get_value(iter, &tmp_handle);
			int_hash_add(phash, tmp_handle, ptmphanle);
		}
		int_hash_iter_free(iter);
		int_hash_free(plogitem->phash);
		plogitem->phash = phash;
		int_hash_add(plogitem->phash, pobjnode->handle, &pobjnode);
	}
	if (NULL == ppparent) {
		simple_tree_set_root(&plogitem->tree, &pobjnode->node);
	} else {
		simple_tree_add_child(&plogitem->tree, &(*ppparent)->node,
			&pobjnode->node, SIMPLE_TREE_ADD_LAST);
	}
	if (OBJECT_TYPE_ICSUPCTX == type) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref ++;
	}
	return pobjnode->handle;
}

void* rop_processor_get_object(void *plogmap,
	uint8_t logon_id, uint32_t obj_handle, int *ptype)
{
	LOGON_ITEM *plogitem;
	OBJECT_NODE **ppobjnode;
	
	if (obj_handle >= 0x7FFFFFFF) {
		return NULL;
	}
	plogitem = ((LOGON_ITEM**)plogmap)[logon_id];
	if (NULL == plogitem) {
		return NULL;
	}
	ppobjnode = int_hash_query(plogitem->phash, obj_handle);
	if (NULL == ppobjnode) {
		return NULL;
	}
	*ptype = (*ppobjnode)->type;
	return (*ppobjnode)->pobject;
}

void rop_processor_release_object_handle(void *plogmap,
	uint8_t logon_id, uint32_t obj_handle)
{
	LOGON_ITEM *plogitem;
	OBJECT_NODE **ppobjnode;
	EMSMDB_INFO *pemsmdb_info;
	
	if (obj_handle >= 0x7FFFFFFF) {
		return;
	}
	plogitem = ((LOGON_ITEM**)plogmap)[logon_id];
	if (NULL == plogitem) {
		return;
	}
	ppobjnode = int_hash_query(plogitem->phash, obj_handle);
	if (NULL == ppobjnode) {
		return;
	}
	if (OBJECT_TYPE_ICSUPCTX == (*ppobjnode)->type) {
		pemsmdb_info = emsmdb_interface_get_emsmdb_info();
		pemsmdb_info->upctx_ref --;
	}
	rop_processor_release_objnode(plogitem, *ppobjnode);
	if (NULL == plogitem->phash) {
		((LOGON_ITEM**)plogmap)[logon_id] = NULL;
	}
}

LOGON_OBJECT* rop_processor_get_logon_object(void *plogmap, uint8_t logon_id)
{
	LOGON_ITEM *plogitem;
	SIMPLE_TREE_NODE *proot;
	
	plogitem = ((LOGON_ITEM**)plogmap)[logon_id];
	if (NULL == plogitem) {
		return 0;
	}
	proot = simple_tree_get_root(&plogitem->tree);
	if (NULL == proot) {
		return 0;
	}
	return ((OBJECT_NODE*)proot->pdata)->pobject;
}

static void *scan_work_func(void *param)
{
	int count;
	char tmp_dir[256];
	STR_HASH_ITER *iter;
	DOUBLE_LIST temp_list;
	DOUBLE_LIST_NODE *pnode;
	
	double_list_init(&temp_list);
	count = 0;
	while (FALSE == g_notify_stop) {
		sleep(1);
		count ++;
		if (count < g_scan_interval) {
			count ++;
			continue;
		} else {
			count = 0;
		}
		pthread_mutex_lock(&g_hash_lock);
		iter = str_hash_iter_init(g_logon_hash);
		for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			str_hash_iter_get_value(iter, tmp_dir);
			pnode = malloc(sizeof(DOUBLE_LIST_NODE));
			if (NULL == pnode) {
				continue;
			}
			pnode->pdata = strdup(tmp_dir);
			if (NULL == pnode->pdata) {
				free(pnode);
				continue;
			}
			double_list_append_as_tail(&temp_list, pnode);
		}
		str_hash_iter_free(iter);
		pthread_mutex_unlock(&g_hash_lock);
		while (pnode=double_list_get_from_head(&temp_list)) {
			exmdb_client_ping_store(pnode->pdata);
			free(pnode->pdata);
			free(pnode);
		}
	}
	double_list_free(&temp_list);
	pthread_exit(0);
}

void rop_processor_init(int average_handles, int scan_interval)
{
	g_average_handles = average_handles;
	g_scan_interval = scan_interval;
	pthread_mutex_init(&g_hash_lock, NULL);
}

int rop_processor_run()
{
	int context_num;
	
	context_num = get_context_num();
	g_logmap_allocator = lib_buffer_init(256*sizeof(LOGON_ITEM*),
							context_num*MAX_HANDLES_ON_CONTEXT, TRUE);
	if (NULL == g_logmap_allocator) {
		printf("[exchange_emsmdb]: fail to init logon map allocator\n");
		return -1;
	}
	g_logitem_allocator = lib_buffer_init(sizeof(LOGON_ITEM),
									256*context_num, TRUE);
	if (NULL == g_logitem_allocator) {
		printf("[exchange_emsmdb]: fail to init object map allocator\n");
		return -2;
	}
	g_handle_allocator = lib_buffer_init(sizeof(OBJECT_NODE),
							g_average_handles*context_num, TRUE);
	if (NULL == g_handle_allocator) {
		printf("[exchange_emsmdb]: fail to init object handle allocator\n");
		return -3;
	}
	g_logon_hash = str_hash_init(get_context_num()*256,
								sizeof(uint32_t), NULL);
	if (NULL == g_logon_hash) {
		printf("[exchange_emsmdb]: fail to init logon hash\n");
		return -4;
	}
	g_notify_stop = FALSE;
	if (0 != pthread_create(&g_scan_id, NULL, scan_work_func, NULL)) {
		g_notify_stop = TRUE;
		printf("[exchange_emsmdb]: fail to create "
			"scanning thread for logon hash table\n");
		return -5;
	}
	return 0;
}

int rop_processor_stop()
{
	if (FALSE == g_notify_stop) {
		g_notify_stop = TRUE;
		pthread_join(g_scan_id, NULL);
	}
	if (NULL != g_logmap_allocator) {
		lib_buffer_free(g_logmap_allocator);
		g_logmap_allocator = NULL;
	}
	if (NULL != g_logitem_allocator) {
		lib_buffer_free(g_logitem_allocator);
		g_logitem_allocator = NULL;
	}
	if (NULL != g_handle_allocator) {
		lib_buffer_free(g_handle_allocator);
		g_handle_allocator = NULL;
	}
	if (NULL != g_logon_hash) {
		str_hash_free(g_logon_hash);
	}
	return 0;
}

void rop_processor_free()
{
	pthread_mutex_destroy(&g_hash_lock);
}

static int rop_processor_excute_and_push(uint8_t *pbuff,
	uint32_t *pbuff_len, ROP_BUFFER *prop_buff,
	BOOL b_notify, DOUBLE_LIST *presponse_list)
{
	int type;
	int status;
	int rop_num;
	BOOL b_icsup;
	void *pobject;
	BINARY tmp_bin;
	uint32_t result;
	uint32_t tmp_len;
	EXT_PUSH ext_push;
	EXT_PUSH ext_push1;
	PROPERTY_ROW tmp_row;
	uint32_t last_offset;
	char ext_buff[0x8000];
	char ext_buff1[0x8000];
	TPROPVAL_ARRAY propvals;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	NOTIFY_RESPONSE *pnotify;
	EMSMDB_INFO *pemsmdb_info;
	DOUBLE_LIST *pnotify_list;
	PENDING_RESPONSE tmp_pending;
	const PROPTAG_ARRAY *pcolumns;
	
	
	/* ms-oxcrpc 3.1.4.2.1.2 */
	if (*pbuff_len > 0x8000) {
		*pbuff_len = 0x8000;
	}
	tmp_len = *pbuff_len - 5*sizeof(uint16_t)
			- sizeof(uint32_t)*prop_buff->hnum;
	ext_buffer_push_init(&ext_push, ext_buff, tmp_len, EXT_FLAG_UTF16);
	rop_num = double_list_get_nodes_num(&prop_buff->rop_list);
	emsmdb_interface_set_rop_num(rop_num);
	b_icsup = FALSE;
	pemsmdb_info = emsmdb_interface_get_emsmdb_info();
	for (pnode=double_list_get_head(&prop_buff->rop_list); NULL!=pnode;
		pnode=double_list_get_after(&prop_buff->rop_list, pnode)) {
		pnode1 = common_util_alloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode1) {
			return EC_OUT_OF_MEMORY;
		}
		emsmdb_interface_set_rop_left(tmp_len - ext_push.offset);
		result = rop_dispatch(pnode->pdata,
				(ROP_RESPONSE**)&pnode1->pdata,
				prop_buff->phandles, prop_buff->hnum);
		switch (result) {
		case EC_SUCCESS:
			/* disable compression when RopReadStream
				RopFastTransferSourceGetBuffer success.
				in many cases, lzxpress will make buffer inflate! */
			if (ROP_ID_READSTREAM == ((ROP_REQUEST*)pnode->pdata)->rop_id
				|| ROP_ID_FASTTRANSFERSOURCEGETBUFFER ==
				((ROP_REQUEST*)pnode->pdata)->rop_id) {
				prop_buff->rhe_flags &= ~RHE_FLAG_COMPRESSED;
			}
			break;
		case EC_BUFFER_TOO_SMALL:
			((ROP_RESPONSE*)pnode1->pdata)->rop_id = ROP_ID_BUFFERTOOSMALL;
			((ROP_RESPONSE*)pnode1->pdata)->ppayload =
				common_util_alloc(sizeof(BUFFERTOOSMALL_RESPONSE));
			if (NULL == ((ROP_RESPONSE*)pnode1->pdata)->ppayload) {
				return EC_OUT_OF_MEMORY;
			}
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->size_needed = 0x8000;
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->buffer =
					((ROP_REQUEST*)pnode->pdata)->bookmark;
			if (EXT_ERR_SUCCESS != rop_ext_push_rop_response(
				&ext_push, ((ROP_REQUEST*)pnode->pdata)->logon_id,
				pnode1->pdata)) {
				return EC_BUFFER_TOO_SMALL;	
			}
			goto MAKE_RPC_EXT;
		default:
			return result;
		}
		if (0 != pemsmdb_info->upctx_ref) {
			b_icsup = TRUE;	
		}
		/* some ROPs do not have response, for example ROP_ID_RELEASE */
		if (NULL == pnode1->pdata) {
			continue;
		}
		last_offset = ext_push.offset;
		status = rop_ext_push_rop_response(&ext_push,
				((ROP_REQUEST*)pnode->pdata)->logon_id,
				pnode1->pdata);
		switch (status) {
		case EXT_ERR_SUCCESS:
			double_list_append_as_tail(presponse_list, pnode1);
			break;
		case EXT_ERR_BUFSIZE:
			if (ROP_ID_GETPROPERTIESALL ==
				((ROP_REQUEST*)pnode->pdata)->rop_id) {
				/* MS-OXCPRPT 3.2.5.2, fail to whole RPC */
				if (pnode == double_list_get_head(&prop_buff->rop_list)) {
					return EC_SERVER_OOM;
				}
			}
			((ROP_RESPONSE*)pnode1->pdata)->rop_id = ROP_ID_BUFFERTOOSMALL;
			((ROP_RESPONSE*)pnode1->pdata)->ppayload =
				common_util_alloc(sizeof(BUFFERTOOSMALL_RESPONSE));
			if (NULL == ((ROP_RESPONSE*)pnode1->pdata)->ppayload) {
				return EC_OUT_OF_MEMORY;
			}
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->size_needed = 0x8000;
			((BUFFERTOOSMALL_RESPONSE*)((ROP_RESPONSE*)
				pnode1->pdata)->ppayload)->buffer =
					((ROP_REQUEST*)pnode->pdata)->bookmark;
			ext_push.offset = last_offset;
			if (EXT_ERR_SUCCESS != rop_ext_push_rop_response(
				&ext_push, ((ROP_REQUEST*)pnode->pdata)->logon_id,
				pnode1->pdata)) {
				return EC_BUFFER_TOO_SMALL;	
			}
			goto MAKE_RPC_EXT;
		case EXT_ERR_ALLOC:
			return EC_OUT_OF_MEMORY;
		default:
			return EC_RPC_FAIL;
		}
	}
	
	if (FALSE == b_notify || TRUE == b_icsup) {
		goto MAKE_RPC_EXT;
	}
	while (TRUE) {
		pnotify_list = emsmdb_interface_get_notify_list();
		if (NULL == pnotify_list) {
			return EC_RPC_FAIL;
		}
		pnode = double_list_get_from_head(pnotify_list);
		emsmdb_interface_put_notify_list();
		if (NULL == pnode) {
			break;
		}
		last_offset = ext_push.offset;
		pnotify = ((ROP_RESPONSE*)pnode->pdata)->ppayload;
		pobject = rop_processor_get_object(pemsmdb_info->plogmap,
					pnotify->logon_id, pnotify->handle, &type);
		if (NULL != pobject) {
			if (OBJECT_TYPE_TABLE == type &&
				NULL != pnotify->notification_data.ptable_event &&
				(TABLE_EVENT_ROW_ADDED ==
				*pnotify->notification_data.ptable_event ||
				TABLE_EVENT_ROW_MODIFIED ==
				*pnotify->notification_data.ptable_event)) {
				pcolumns = table_object_get_columns(pobject);
				ext_buffer_push_init(&ext_push1, ext_buff1,
					sizeof(ext_buff1), EXT_FLAG_UTF16);
				if (pnotify->notification_data.notification_flags
					&NOTIFICATION_FLAG_MOST_MESSAGE) {
					if (FALSE == table_object_read_row(pobject,
						*pnotify->notification_data.prow_message_id,
						*pnotify->notification_data.prow_instance,
						&propvals) || 0 == propvals.count) {
						goto NEXT_NOTIFY;
					}
					
				} else {
					if (FALSE == table_object_read_row(pobject,
						*pnotify->notification_data.prow_folder_id,
						0, &propvals) || 0 == propvals.count) {
						goto NEXT_NOTIFY;
					}
				}
				if (FALSE == common_util_propvals_to_row(
					&propvals, pcolumns, &tmp_row) ||
					EXT_ERR_SUCCESS != ext_buffer_push_property_row(
					&ext_push1, pcolumns, &tmp_row)) {
					goto NEXT_NOTIFY;
				}	
				tmp_bin.cb = ext_push1.offset;
				tmp_bin.pb = ext_push1.data;
				pnotify->notification_data.prow_data = &tmp_bin;
			}
			if (EXT_ERR_SUCCESS != rop_ext_push_notify_response(
				&ext_push, pnotify)) {
				ext_push.offset = last_offset;
				double_list_insert_as_head(pnotify_list, pnode);
				emsmdb_interface_get_cxr(&tmp_pending.session_index);
				status = rop_ext_push_pending_response(
								&ext_push, &tmp_pending);
				if (EXT_ERR_SUCCESS != status) {
					ext_push.offset = last_offset;
				}
				break;
			}
		}
NEXT_NOTIFY:
		notify_response_free(((ROP_RESPONSE*)pnode->pdata)->ppayload);
		free(pnode->pdata);
		free(pnode);
	}
	
MAKE_RPC_EXT:
	if (EXT_ERR_SUCCESS != rop_ext_make_rpc_ext(ext_buff,
		ext_push.offset, prop_buff, pbuff, pbuff_len)) {
		return EC_ERROR;	
	}
	return EC_SUCCESS;
}

uint32_t rop_processor_proc(uint32_t flags, const uint8_t *pin,
	uint32_t cb_in, uint8_t *pout, uint32_t *pcb_out)
{
	int count;
	uint32_t result;
	uint32_t tmp_cb;
	uint32_t offset;
	EXT_PULL ext_pull;
	ROP_BUFFER rop_buff;
	uint32_t last_offset;
	ROP_REQUEST *prequest;
	ROP_RESPONSE *presponse;
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST response_list;
	
	ext_buffer_pull_init(&ext_pull, pin, cb_in,
			common_util_alloc, EXT_FLAG_UTF16);
	switch(rop_ext_pull_rop_buffer(&ext_pull, &rop_buff)) {
	case EXT_ERR_SUCCESS:
		break;
	case EXT_ERR_ALLOC:
		return EC_OUT_OF_MEMORY;
	default:
		return EC_RPC_FORMAT;
	}
	rop_buff.rhe_flags = 0;
	if (0 == (flags & RPCEXT2_FLAG_NOXORMAGIC)) {
		rop_buff.rhe_flags |= RHE_FLAG_XORMAGIC;
	}
	if (0 == (flags & RPCEXT2_FLAG_NOCOMPRESSION)) {
		rop_buff.rhe_flags |= RHE_FLAG_COMPRESSED;
	}
	double_list_init(&response_list);
	tmp_cb = *pcb_out;
	result = rop_processor_excute_and_push(pout,
		&tmp_cb, &rop_buff, TRUE, &response_list);
	if (EC_SUCCESS != result) {
		return result;
	}
	offset = tmp_cb;
	last_offset = 0;
	count = double_list_get_nodes_num(&response_list);
	pnode = double_list_get_tail(&rop_buff.rop_list);
	pnode1 = double_list_get_tail(&response_list);
	if (NULL == pnode || NULL == pnode1) {
		goto PROC_SUCCESS;
	}
	prequest = (ROP_REQUEST*)pnode->pdata;
	presponse = (ROP_RESPONSE*)pnode1->pdata;
	if (prequest->rop_id != presponse->rop_id) {
		goto PROC_SUCCESS;
	}
	double_list_free(&rop_buff.rop_list);
	double_list_init(&rop_buff.rop_list);
	double_list_append_as_tail(&rop_buff.rop_list, pnode);
	double_list_free(&response_list);
	double_list_init(&response_list);
	
	if (ROP_ID_QUERYROWS == presponse->rop_id) {
		if (QUERY_ROWS_FLAGS_ENABLEPACKEDBUFFERS ==
			((QUERYROWS_REQUEST*)prequest->ppayload)->flags) {
			goto PROC_SUCCESS;
		}
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (EC_SUCCESS == presponse->result &&
			*pcb_out - offset >= 0x8000 && count < MAX_ROP_PAYLOADS) {
			if (0 != ((QUERYROWS_REQUEST*)
				prequest->ppayload)->forward_read) {
				if (SEEK_POS_END == ((QUERYROWS_RESPONSE*)
					presponse->ppayload)->seek_pos) {
					break;
				}
			} else {
				if (SEEK_POS_BEGIN == ((QUERYROWS_RESPONSE*)
					presponse->ppayload)->seek_pos) {
					break;
				}
			}
			((QUERYROWS_REQUEST*)prequest->ppayload)->row_count -=
				((QUERYROWS_RESPONSE*)presponse->ppayload)->count;
			if (0 == ((QUERYROWS_REQUEST*)
				prequest->ppayload)->row_count) {
				break;
			}
			tmp_cb = *pcb_out - offset;
			result = rop_processor_excute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (EC_SUCCESS != result) {
				break;
			}
			pnode1 = double_list_get_from_head(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (ROP_ID_QUERYROWS != presponse->rop_id ||
				EC_SUCCESS != presponse->result) {
				break;
			}
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (ROP_ID_READSTREAM == presponse->rop_id) {
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (EC_SUCCESS == presponse->result &&
			*pcb_out - offset >= 0x2000 && count < MAX_ROP_PAYLOADS) {
			if (0 == ((READSTREAM_RESPONSE*)
				presponse->ppayload)->data.cb) {
				break;
			}
			tmp_cb = *pcb_out - offset;
			result = rop_processor_excute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (EC_SUCCESS != result) {
				break;
			}
			pnode1 = double_list_get_from_head(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (ROP_ID_READSTREAM != presponse->rop_id ||
				EC_SUCCESS != presponse->result) {
				break;
			}
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	} else if (ROP_ID_FASTTRANSFERSOURCEGETBUFFER == presponse->rop_id) {
		/* ms-oxcrpc 3.1.4.2.1.2 */
		while (EC_SUCCESS == presponse->result &&
			*pcb_out - offset >= 0x2000 && count < MAX_ROP_PAYLOADS) {
			if (TRANSFER_STATUS_ERROR == 
				((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)
				presponse->ppayload)->transfer_status ||
				TRANSFER_STATUS_DONE == 
				((FASTTRANSFERSOURCEGETBUFFER_RESPONSE*)
				presponse->ppayload)->transfer_status) {
				break;
			}
			tmp_cb = *pcb_out - offset;
			result = rop_processor_excute_and_push(pout + offset,
						&tmp_cb, &rop_buff, FALSE, &response_list);
			if (EC_SUCCESS != result) {
				break;
			}
			pnode1 = double_list_get_from_head(&response_list);
			if (NULL == pnode1) {
				break;
			}
			presponse = (ROP_RESPONSE*)pnode1->pdata;
			if (ROP_ID_FASTTRANSFERSOURCEGETBUFFER != presponse->rop_id
				|| EC_SUCCESS != presponse->result) {
				break;
			}
			last_offset = offset;
			offset += tmp_cb;
			count ++;
		}
	}
	
PROC_SUCCESS:
	rop_ext_set_rhe_flag_last(pout, last_offset);
	*pcb_out = offset;
	return EC_SUCCESS;
}

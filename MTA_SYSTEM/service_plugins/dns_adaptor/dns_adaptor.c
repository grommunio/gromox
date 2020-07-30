#include <libHX/defs.h>
#include <libHX/misc.h>
#include <libHX/string.h>
#include <gromox/resolv.h>
#include "dns_adaptor.h"
#include "inbound_ips.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#undef NOERROR                  /* in <sys/streams.h> on solaris 2.x */
#include <arpa/nameser.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>

#define ITEM_RATIO			5
#define MAXPACKET			8192 /* max size of packet */
#define MAXBUF				256          
#define MAXMXHOSTS			32   /* max num of mx records we want to see */
#define MAXMXBUFSIZ			(MAXMXHOSTS * (MAXBUF+1)) 

enum{
	DNS_ENTRY_ADD_OK,
	DNS_ENTRY_ADD_FAIL,
	DNS_ENTRY_ADD_EXIST
};

typedef struct _DNS_ENTRY {
	time_t		created_time;           /* the add or update time */
	int			access_times;
	SINGLE_LIST	ip_list;
} DNS_ENTRY;

typedef struct _IP_NODE {
	SINGLE_LIST_NODE	node;
	char				ip[16];
} IP_NODE;

/* private global variable declaration */
static char				g_path[256];
static int				g_capacity;
static time_t			g_valid_interval;
static STR_HASH_TABLE   *g_A_table; /* domain hash table */
static STR_HASH_TABLE   *g_MX_table; /* domain hash table */
static LIB_BUFFER		*g_ip_pool;      /* ip node pool */
static pthread_mutex_t	g_A_lock;
static pthread_mutex_t	g_MX_lock;

static BOOL dns_adaptor_get_A_into_list(char *a_name, SINGLE_LIST *plist);

static BOOL dns_adaptor_get_MX_into_list(char *mx_name, SINGLE_LIST *plist);

static BOOL dns_adaptor_query_A_table_into_list(char *name, SINGLE_LIST *plist);

static BOOL dns_adaptor_query_table(char *name, VSTACK *pstack,
	STR_HASH_TABLE *ptable, pthread_mutex_t *plock);

static int dns_adaptor_add_table(char *name, DNS_ENTRY *pentry,
	STR_HASH_TABLE *ptable, pthread_mutex_t *plock);

static void dns_adaptor_collect_garbage(STR_HASH_TABLE *ptable);
static BOOL dns_adaptor_refresh(void);

/*
 *	dns adaptor's construct function
 *	@param
 *		capacity			table capacity
 *		valid_interval		valid interval of item
 *		path				dns list path
 */
void dns_adaptor_init(const char *path, int capacity, time_t valid_interval)
{
	strcpy(g_path, path);
	g_capacity = capacity;
	g_valid_interval = valid_interval;
	pthread_mutex_init(&g_A_lock, NULL);
	pthread_mutex_init(&g_MX_lock, NULL);
}

/*
 *	dns adaptor's destruct function
 */
void dns_adaptor_free()
{
	g_path[0] = '\0';
	g_capacity = 0;
	g_valid_interval = 0;
	pthread_mutex_destroy(&g_A_lock);
	pthread_mutex_destroy(&g_MX_lock);
}

/*
 *	run the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int dns_adaptor_run()
{
	g_ip_pool = lib_buffer_init(sizeof(IP_NODE), g_capacity*ITEM_RATIO, TRUE);
	if (NULL== g_ip_pool) {
		printf("[dns_adaptor]: Failed to init ipaddr node pool\n");
		return -1;
	}
	g_A_table = str_hash_init(g_capacity, sizeof(DNS_ENTRY), NULL);
	if (NULL == g_A_table) {
		printf("[dns_adaptor]: Failed to init DNS A record table\n");
		return -2;
	}
	g_MX_table = str_hash_init(g_capacity, sizeof(DNS_ENTRY), NULL);
	if (NULL == g_MX_table) {
		printf("[dns_adaptor]: Failed to init DNS MX record table\n");
		return -3;
	}
	dns_adaptor_refresh();
    return 0;
}

static BOOL dns_adaptor_refresh()
{
	LIST_FILE *plist_file;
	DNS_ENTRY temp_entry, removed_entry, *pentry;
	STR_HASH_ITER *iter;
	IP_NODE *p_ip;
	SINGLE_LIST_NODE *pnode;
	char tmp_ip[16], ip_buff[16];
	const char *pcomma, *pbegin;
	int i, list_num, ip_len;
	BOOL normal_exist;
	STR_HASH_TABLE *ptable;
	pthread_mutex_t *plock;
	struct srcitem {
		char dns_type[4], dns_name[256], dns_ip_addrs[1024];
	};

	plist_file = list_file_init(g_path, "%s:4%s:256%s:1024");
	if (NULL == plist_file) {
		return FALSE;
	}
	
	/* clear all fix items in MX table and A table */
	
	/* MX record table */
	pthread_mutex_lock(&g_MX_lock);
	iter = str_hash_iter_init(g_MX_table);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pentry = (DNS_ENTRY*)str_hash_iter_get_value(iter, NULL);
		if (0 != pentry->created_time) {
			continue;
		}
		while ((pnode = single_list_get_from_head(&pentry->ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&pentry->ip_list);
		str_hash_iter_remove(iter);
	}
	str_hash_iter_free(iter);
	/* make the MX table clean as best as possible */
	dns_adaptor_collect_garbage(g_MX_table);
	pthread_mutex_unlock(&g_MX_lock);
	/* A record table */
	pthread_mutex_lock(&g_A_lock);
	iter = str_hash_iter_init(g_A_table);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pentry = (DNS_ENTRY*)str_hash_iter_get_value(iter, NULL);
		if (0 != pentry->created_time) {
			continue;
		}
		while ((pnode = single_list_get_from_head(&pentry->ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&pentry->ip_list);
		str_hash_iter_remove(iter);
	}
	str_hash_iter_free(iter);
	/* make the A table clean as best as possible */
	dns_adaptor_collect_garbage(g_A_table);
	pthread_mutex_unlock(&g_A_lock);
	/* end of clear */
	
	list_num = list_file_get_item_num(plist_file);
	struct srcitem *pitem = reinterpret_cast(struct srcitem *, list_file_get_list(plist_file));
	for (i=0; i<list_num; i++) {
		const char *dns_type = pitem[i].dns_type;
		char *dns_name = pitem[i].dns_name;
		HX_strlower(dns_name);
		const char *dns_ips = pitem[i].dns_ip_addrs;
		if (0 == strcasecmp(dns_type, "MX")) {
			ptable = g_MX_table;
			plock = &g_MX_lock;
		} else if (0 == strcasecmp(dns_type, "A")) {
			ptable = g_A_table;
			plock = &g_A_lock;
		} else {
			printf("[dns_adaptor]: dns type %s of item %d cannot be "
				"recognized\n", dns_type, i + 1);
			continue;
		}
		single_list_init(&temp_entry.ip_list);
		pbegin = dns_ips;
		while (NULL != (pcomma = strchr(pbegin, ':'))) {
			ip_len = pcomma - pbegin;
			if (ip_len > 15) {
				printf("[dns_adaptor]: ip format is illegal in item %d\n", i+1);
				pbegin = pcomma + 1;
				continue;
			}
			memcpy(tmp_ip, pbegin, ip_len);
			tmp_ip[ip_len] = '\0';
			if (NULL == extract_ip(pbegin, ip_buff) ||
				0 != strcmp(tmp_ip, ip_buff)) {
				printf("[dns_adaptor]: %s is illegal in item %d\n",tmp_ip, i+1);
				pbegin = pcomma + 1;
				continue;
			}
			p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			if (NULL == p_ip) {
				pthread_mutex_lock(plock);
				dns_adaptor_collect_garbage(ptable);
				pthread_mutex_unlock(plock);
				p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			}
			if (NULL == p_ip) {
				while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
					lib_buffer_put(g_ip_pool, pnode->pdata);
				break;
			}
			p_ip->node.pdata = p_ip;
			strcpy(p_ip->ip, tmp_ip);
			single_list_append_as_tail(&temp_entry.ip_list, &p_ip->node);
			pbegin = pcomma + 1;
		}
		if (0 == single_list_get_nodes_num(&temp_entry.ip_list)) {
			single_list_free(&temp_entry.ip_list);
			continue;
		}
		temp_entry.created_time = 0;
		temp_entry.access_times = 0;
		normal_exist = FALSE;
		pthread_mutex_lock(plock);
		/* first query the normal dns item, if same item exists, remove it */ 
		pentry = str_hash_query(ptable, dns_name);
		if (NULL != pentry) {
			normal_exist = TRUE;
			removed_entry = *pentry;
			str_hash_remove(ptable, dns_name);
		}
		if (1 != str_hash_add(ptable, dns_name, &temp_entry)) {
			printf("[dns_adaptor]: fail to add item %d into hash table\n", i);
		}
		pthread_mutex_unlock(plock);
		if (TRUE == normal_exist) {
			while ((pnode = single_list_get_from_head(&removed_entry.ip_list)) != NULL)
				lib_buffer_put(g_ip_pool, pnode->pdata);
			single_list_free(&removed_entry.ip_list);
		}
	}
	list_file_free(plist_file);
	return TRUE;
}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int dns_adaptor_stop()
{
	if (NULL != g_MX_table) {
		str_hash_free(g_MX_table);
		g_MX_table = NULL;
	}
	if (NULL != g_A_table) {
		str_hash_free(g_A_table);
		g_A_table = NULL;
	}
	if (NULL != g_ip_pool) {
		lib_buffer_free(g_ip_pool);
		g_ip_pool = NULL;
	}
    return 0;
}

/*
 *	query MX record
 *	@param
 *		mx_name [in]		domain name
 *		pstack [out]		stack for saving result
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL dns_adaptor_query_MX(char* mx_name, VSTACK* pstack)
{
	DNS_ENTRY temp_entry;
	SINGLE_LIST_NODE *pnode;
	int result;
	char tmp_name[256];

	strncpy(tmp_name, mx_name, 256);
	HX_strlower(tmp_name);
	if (TRUE == dns_adaptor_query_table(tmp_name, pstack, g_MX_table,
		&g_MX_lock)) {
		return TRUE;
	}
	/* query the DNS and add ip list into hash table */
	single_list_init(&temp_entry.ip_list);
	time(&temp_entry.created_time);
	temp_entry.access_times = 0;

	if (FALSE == dns_adaptor_get_MX_into_list(tmp_name, &temp_entry.ip_list)) {
		while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&temp_entry.ip_list);
		return FALSE;
	}
	
	for (pnode=single_list_get_head(&temp_entry.ip_list); NULL!=pnode;
		pnode=single_list_get_after(&temp_entry.ip_list, pnode)) {
		vstack_push(pstack, ((IP_NODE*)(pnode->pdata))->ip);
	}
	result = dns_adaptor_add_table(tmp_name, &temp_entry, g_MX_table,&g_MX_lock);
	if (DNS_ENTRY_ADD_FAIL == result || DNS_ENTRY_ADD_EXIST == result) {
		while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&temp_entry.ip_list);
	}
	return TRUE;
}

/*
 *	query A record
 *	@param
 *		a_name [in]		domain name
 *		pstack [out]		stack for saving result
 *	@return
 *		TRUE				OK
 *		FALSE				fail
 */
BOOL dns_adaptor_query_A(char* a_name, VSTACK* pstack)
{
	DNS_ENTRY temp_entry;
	SINGLE_LIST_NODE *pnode;
	int result;
	char tmp_name[256];

	strncpy(tmp_name, a_name, 256);
	HX_strlower(tmp_name);
	if (TRUE == dns_adaptor_query_table(tmp_name, pstack, g_A_table, &g_A_lock)) {
		return TRUE;
	}
	/* query the DNS and add ip list into hash table */
	single_list_init(&temp_entry.ip_list);
	time(&temp_entry.created_time);
	temp_entry.access_times = 0;

	if (FALSE == dns_adaptor_get_A_into_list(tmp_name, &temp_entry.ip_list)) {
		while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&temp_entry.ip_list);
		return FALSE;
	}
	
	for (pnode=single_list_get_head(&temp_entry.ip_list); NULL!=pnode;
		pnode=single_list_get_after(&temp_entry.ip_list, pnode)) {
		vstack_push(pstack, ((IP_NODE*)(pnode->pdata))->ip);
	}
	result = dns_adaptor_add_table(tmp_name, &temp_entry, g_A_table, &g_A_lock);
	if (DNS_ENTRY_ADD_FAIL == result || DNS_ENTRY_ADD_EXIST == result) {
		while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
			lib_buffer_put(g_ip_pool, pnode->pdata);
		single_list_free(&temp_entry.ip_list);
	}
	return TRUE;
}

static BOOL dns_adaptor_query_table(char *name, VSTACK *pstack,
	STR_HASH_TABLE *ptable, pthread_mutex_t *plock)
{
	DNS_ENTRY temp_entry, *pentry;
	SINGLE_LIST_NODE *pnode;
	time_t current_time;
	
	vstack_clear(pstack);
	pthread_mutex_lock(plock);
	pentry = (DNS_ENTRY*)str_hash_query(ptable, name);
	if (NULL != pentry) {
		if (pentry->created_time != 0) {
			time(&current_time);
			if (current_time - pentry->created_time > g_valid_interval) {
				temp_entry = *pentry;
				str_hash_remove(ptable, name);
				pthread_mutex_unlock(plock);
				while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
					lib_buffer_put(g_ip_pool, pnode->pdata);
				single_list_free(&temp_entry.ip_list);
				return FALSE;
			}
		}
		for (pnode=single_list_get_head(&pentry->ip_list); NULL!=pnode;
			pnode=single_list_get_after(&pentry->ip_list, pnode)) {
			vstack_push(pstack, ((IP_NODE*)(pnode->pdata))->ip);
		}
		pentry->access_times ++;
		pthread_mutex_unlock(plock);
		return TRUE;
	}
	pthread_mutex_unlock(plock);
	return FALSE;
}

static BOOL dns_adaptor_query_A_table_into_list(char *name, SINGLE_LIST *plist)
{
	IP_NODE *p_ip;
	SINGLE_LIST_NODE *pnode;
	time_t current_time;
	DNS_ENTRY temp_entry, *pentry;
	
	pthread_mutex_lock(&g_A_lock);
	pentry = (DNS_ENTRY*)str_hash_query(g_A_table, name);
	if (NULL != pentry) {
		if (pentry->created_time != 0) {
			time(&current_time);
			if (current_time - pentry->created_time > g_valid_interval) {
				temp_entry = *pentry;
				str_hash_remove(g_A_table, name);
				pthread_mutex_unlock(&g_A_lock);
				while ((pnode = single_list_get_from_head(&temp_entry.ip_list)) != NULL)
					lib_buffer_put(g_ip_pool, pnode->pdata);
				single_list_free(&temp_entry.ip_list);
				return FALSE;
			}
		}
		for (pnode=single_list_get_head(&pentry->ip_list); NULL!=pnode;
			pnode=single_list_get_after(&pentry->ip_list, pnode)) {
			p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			if (NULL == p_ip) {
				dns_adaptor_collect_garbage(g_A_table);
				p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			}
			if (NULL == p_ip) {
				pthread_mutex_unlock(&g_A_lock);
				return FALSE;
			}
			p_ip->node.pdata = p_ip;
			strcpy(p_ip->ip, ((IP_NODE*)pnode->pdata)->ip);
			single_list_append_as_tail(plist, &p_ip->node);
		}
		pentry->access_times ++;
		pthread_mutex_unlock(&g_A_lock);
		return TRUE;
	}
	pthread_mutex_unlock(&g_A_lock);
	return FALSE;
}


static int dns_adaptor_add_table(char *name, DNS_ENTRY *pentry,
	STR_HASH_TABLE *ptable, pthread_mutex_t *plock)
{
	DNS_ENTRY *psearch;
	
	pthread_mutex_lock(plock);
	psearch = (DNS_ENTRY*)str_hash_query(ptable, name);
	if (NULL == psearch) {
		if (1 != str_hash_add(ptable, name, pentry)) {
			dns_adaptor_collect_garbage(ptable);
			if (1 != str_hash_add(ptable, name, pentry)) {
				pthread_mutex_unlock(plock);
				return DNS_ENTRY_ADD_FAIL;
			}
		}
	} else {
		pthread_mutex_unlock(plock);
		return DNS_ENTRY_ADD_EXIST;
	}
	pthread_mutex_unlock(plock);
	return DNS_ENTRY_ADD_OK;
}

static BOOL dns_adaptor_get_A_into_list(char *a_name, SINGLE_LIST *plist)
{
	IP_NODE *p_ip;
	struct in_addr ip_addr;
	char **p_addr;
	char buf[2046];
	struct hostent hostinfo, *phost;
	int ret;
	
	if (0 != gethostbyname_r(a_name, &hostinfo, buf, sizeof(buf),
		&phost, &ret) || NULL == phost) {
	    return FALSE;
	}
	p_addr = phost->h_addr_list;
	for (; NULL != (*p_addr); p_addr++) {
		p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
		if (NULL == p_ip) {
			pthread_mutex_lock(&g_A_lock);
			dns_adaptor_collect_garbage(g_A_table);
			pthread_mutex_unlock(&g_A_lock);
			p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
		}
		if (NULL == p_ip) {
			return FALSE;
		}
		p_ip->node.pdata = p_ip;
		ip_addr.s_addr = *((unsigned int *)*p_addr);
		strcpy(p_ip->ip, inet_ntoa(ip_addr));
		single_list_append_as_tail(plist, &p_ip->node);
	}
	return TRUE;
}

static BOOL dns_adaptor_get_MX_into_list(char *mx_name, SINGLE_LIST *plist)
{
	IP_NODE *p_ip;
	char **mxhosts = NULL;
	char temp_ip[16];
	int i, num;
	BOOL ret_val;
	
	num = gx_getmxbyname(mx_name, &mxhosts);
	if (num <= 0) {
		if (mxhosts != NULL)
			HX_zvecfree(mxhosts);
	    return FALSE;
	}
	ret_val = FALSE;
	
	for (i=0; i<num; i++) {
		if (extract_ip(mxhosts[i], temp_ip) == NULL) {
			HX_strlower(mxhosts[i]);
			if (TRUE == dns_adaptor_query_A_table_into_list(mxhosts[i], plist)||
				TRUE == dns_adaptor_get_A_into_list(mxhosts[i], plist)) {
				ret_val = TRUE;
			} 
		} else {
			p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			if (NULL == p_ip) {
				pthread_mutex_lock(&g_MX_lock);
				dns_adaptor_collect_garbage(g_MX_table);
				pthread_mutex_unlock(&g_MX_lock);
				p_ip = (IP_NODE*)lib_buffer_get(g_ip_pool);
			}
			if (NULL == p_ip) {
				if (mxhosts != NULL)
					HX_zvecfree(mxhosts);
				return FALSE;
			}
			p_ip->node.pdata = p_ip;
			strcpy(p_ip->ip, temp_ip);
			single_list_append_as_tail(plist, &p_ip->node);
			ret_val = TRUE;
		}
	}
	if (mxhosts != NULL)
		HX_zvecfree(mxhosts);
	return ret_val;
}

static void dns_adaptor_collect_garbage(STR_HASH_TABLE *ptable)
{
	STR_HASH_ITER *iter;
	DNS_ENTRY *pentry;
	int collected_num;
	time_t current_time;
	SINGLE_LIST_NODE *pnode;
	
	collected_num = 0;
	iter = str_hash_iter_init(ptable);
	time(&current_time);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pentry = (DNS_ENTRY*)str_hash_iter_get_value(iter, NULL);
		if (0 == pentry->created_time) {
			continue;
		}
		if (current_time - pentry->created_time >= g_valid_interval) {
			while ((pnode = single_list_get_from_head(&pentry->ip_list)) != NULL)
				lib_buffer_put(g_ip_pool, pnode->pdata);
			single_list_free(&pentry->ip_list);
			str_hash_iter_remove(iter);
			collected_num++;
		}
	}
	if (collected_num >= g_capacity/2) {
		str_hash_iter_free(iter);
		return;
	}
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pentry = (DNS_ENTRY*)str_hash_iter_get_value(iter, NULL);
		if (0 == pentry->created_time) {
			continue;
		}
		if (1 == pentry->access_times &&
			current_time - pentry->created_time >= g_valid_interval/10) {
			while ((pnode = single_list_get_from_head(&pentry->ip_list)) != NULL)
				lib_buffer_put(g_ip_pool, pnode->pdata);
			single_list_free(&pentry->ip_list);
			str_hash_iter_remove(iter);
		}
	}
	str_hash_iter_free(iter);
}

void dns_adaptor_console_talk(int argc, char **argv, char *result, int length)
{
	int interval, len;
	char help_string[] = "250 dns adaptor help information:\r\n"
						 "\t%s info\r\n"
						 "\t    --print dns adaptor information\r\n"
						 "\t%s reload fixed\r\n"
						 "\t    --reload the fixed dns table\r\n"
						 "\t%s reload inbound-ips\r\n"
						 "\t    --reload the inbound-ips table\r\n"
						 "\t%s set valid-interval <interval>\r\n"
						 "\t    --set valid interval of dns item in adaptor";
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
	if (2 == argc && 0 == strcmp("info", argv[1])) {
		 len = snprintf(result, length,
				    "250 dns adaptor information:\r\n"
					"\tcapacity          %d\r\n"
					"\tvalid interval    ",
					g_capacity);
		 itvltoa(g_valid_interval, result + len);
		 return;
	}
	if (3 == argc && 0 == strcmp("reload", argv[1]) &&
		0 == strcmp("fixed", argv[2])) {
		if (TRUE == dns_adaptor_refresh()) {
			strncpy(result, "250 fixed dns table reload OK", length);
		} else {
			strncpy(result, "550 fixed dns table reload fail", length);
		}
		return;
	}
	if (3 == argc && 0 == strcmp("reload", argv[1]) &&
		0 == strcmp("inbound-ips", argv[2])) {
		if (TRUE == inbound_ips_refresh()) {
			strncpy(result, "250 inbound-ips table reload OK", length);
		} else {
			strncpy(result, "550 inbound-ips table reload fail", length);
		}
		return;
	}
	if (4 == argc && 0 == strcmp("set", argv[1]) &&
		0 == strcmp("valid-interval", argv[2])) {
		interval = atoitvl(argv[3]);
		if (interval <= 0) {
			strncpy(result, "<interval> should be larger than 0", length);
			return;
		}
		g_valid_interval = interval;
		strncpy(result, "250 valid interval set OK", length);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;

}

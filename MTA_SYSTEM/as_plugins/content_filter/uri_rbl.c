#include "uri_rbl.h"
#include "uri_cache.h"
#include "str_hash.h"
#include "list_file.h"
#include "mail_func.h"
#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <stdint.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <assert.h>
#include <pthread.h>



/* CCTLD: Country Code Top Level Domains */

static char g_cctld_path[256];
static char g_surbl_dns[256];
static char g_uribl_dns[256];
static STR_HASH_TABLE *g_cctld_hash;
static pthread_rwlock_t g_table_lock;


/* extract a rr from an answer,
 * need the sizeof the rr_name buffer in rr_name_len
 * return the exact size of the string rr_name in rr_name_len
 * other rr_* arguments are output only.
 *
 * rr_data will cary a pointer to the data of the rr in buffer
 * (not dynamicaly allocated).
 *
 */
static char *dns_explode_answer(char *buffer, int len, char *ptr,
	int *rr_name_len, char *rr_name, int  *rr_type, int *rr_class,
	int *rr_ttl, int *rr_data_len, char **rr_data)
{
	*rr_name_len = dn_expand(buffer, buffer + len, ptr, rr_name, *rr_name_len); 

	if (*rr_name_len < 0) {
		debug_info("[uri_rbl]: dns_explode_answers(): decoding error: "
			"rr_name_len = %d\n", *rr_name_len);
		return NULL;
    }
	ptr += *rr_name_len;
	NS_GET16(*rr_type, ptr);
	NS_GET16(*rr_class, ptr);
	NS_GET32(*rr_ttl, ptr);
	NS_GET16(*rr_data_len, ptr);
	*rr_data = ptr;
	ptr += *rr_data_len;
	return ptr;
}

/* in a answer section,
 * search A or TXT records matching the request
 */
static char* dns_process_answers(char *buffer, int len, int count, char *ptr,
	const char *req, int *bl, char *answer_buff, int answer_len)
{
	int rr_name_len;
	char rr_name[NS_MAXDNAME];
	int rr_type;
	int rr_class;
	int rr_ttl;
	char * rr_data;
	int rr_data_len;

	for(; count>0; count--) {
		rr_name_len = sizeof(rr_name);
		ptr = dns_explode_answer(buffer, len, ptr, &rr_name_len, rr_name,
				&rr_type, &rr_class, &rr_ttl, &rr_data_len, &rr_data);
		if (ptr == NULL) {
			return NULL;
		}
		if (rr_class == C_IN && rr_data_len > 0 && 
			strcasecmp(rr_name, req) == 0) {
			switch(rr_type) {
			case T_TXT:
				{
					/* string in TXT RDATA can't be more than that */
					char str[256]; 
					int str_len;
					char *strs = rr_data;
				
					/* extract all strings for the TXT RDATA */
					do {
						str_len = * (unsigned char *) strs; /* read len */
						strs ++;
						assert(str_len >= 0);
						if (str_len > rr_data_len || (strs + str_len) > ptr) {
							debug_info("[uri_rbl]: string overflow\n");
							return NULL;
						}
						/* empty string */
						if (str_len == 0) {
							continue;
						}
						memcpy(str, strs, str_len);
						*(str + str_len) = '\0';
						strncpy(answer_buff, str, answer_len);
						strs += str_len;
					} while (strs < ptr);
				}
				break;
			case T_A:
				if (rr_data_len != sizeof(struct in_addr)) {
					debug_info("[uri_rbl]: data size mismatch\n");
					return NULL;
				}
				if (0 != strncmp("127.0.0.", inet_ntoa(
					*(struct in_addr*)rr_data), 8)) {
					/* DNS is kidnapped */
					return NULL;
				}
#ifdef _DEBUG_UMTA	  
				debug_info("[uri_rbl]: %s\n", 
					inet_ntoa(*(struct in_addr*)rr_data));
#endif
				(*bl) ++;
				break;
			default: /* skip others */
				break;
			}
		}
	}
	return ptr;
}

/* read RR, but discard the values */
static char* dns_skip_answers(char *buffer, int len, int count, char *ptr)
{
	int rr_name_len;
	char rr_name[NS_MAXDNAME];
	int rr_type;
	int rr_class;
	int rr_ttl;
	char *rr_data;
	int rr_data_len;
	
	for(; count>0; count--) {
		rr_name_len = sizeof(rr_name);
		ptr = dns_explode_answer(buffer, len, ptr, &rr_name_len, rr_name,
				&rr_type, &rr_class, &rr_ttl, &rr_data_len, &rr_data);
		if (ptr == NULL) {
			return NULL;
		}
    }
	return ptr;
}

static char* dns_skip_questions(char *buffer, int len, int count, char *ptr)
{
	int rr_name_len;
	char rr_name[NS_MAXDNAME];
	int rr_type;
	int rr_class;

	for(; count>0; count--) {
		rr_name_len = sizeof(rr_name);
		rr_name_len = dn_expand(buffer, buffer + len, ptr, rr_name, 
						rr_name_len);
		if (rr_name_len < 0) {
			debug_info("[uri_rbl]: dns_skip_questions(): decoding error: "
				"rr_name_len = %d\n", rr_name_len);
			return NULL;
		}
		ptr += rr_name_len;
		NS_GET16(rr_type, ptr);
		NS_GET16(rr_class, ptr);
	}
	return ptr;
}

static int dnsrbl_check_query(const char * req, int type, char *answer_buff,
	int answer_len)
{
	char *buffer;
	char tmp_buf[16*NS_PACKETSZ];
	int buffer_size = 16*NS_PACKETSZ;
	int i, len;
	char *ptr;
	HEADER *h;
	int question_count;
	int answer_count;
	int ns_count;
	int ar_count;
	int remaining;
	int bl = 0;

	buffer = tmp_buf;
	for(i=0; ; i++) {
		len = res_query(req, C_IN, type, buffer, buffer_size);
		if (len < 0) { /* could be not found */
			switch(h_errno) {
			case TRY_AGAIN:
				if (i < 3) {
					continue;
				} else {
					debug_info("[uri_rbl]: res_query failed: %s\n",
						hstrerror(h_errno));
					return -1;
				}
			case HOST_NOT_FOUND:
				return 0; /* not listed */
			default:
				debug_info("[uri_rbl]: res_query failed: %s\n",
					hstrerror(h_errno));
				return -1;
			}
		}
		if (len >= (int)sizeof(HEADER)) {
			h = (HEADER *)buffer;
			if (!h->tc) /* truncated ? */ {
				/* really not truncated ? */
				if (len < buffer_size) {
					break;
				} else {
					debug_info("[uri_rbl]: buffer too short\n");
					goto ret_err;
				}
			}
		}
#ifdef _DEBUG_UMTA
		debug_info("[uri_rbl]: DEBUG: len = %d\n", len);
#endif
		if (i > 3) {
			debug_info("[uri_rbl]: can't find correct buffer size for query\n");
			goto ret_err;
		}
	}
	if (!h->qr) {
		debug_info("[uri_rbl]: packet is not an answer!\n");
		goto ret_err;
	}
	if (h->rcode != NOERROR) {
		debug_info("[uri_rbl]: error returned in answer\n");
		goto ret_err;
	}
	/* skip header */
	ptr = buffer + sizeof(HEADER);
	answer_count = ntohs(h->ancount);
	if (answer_count <= 0) {
#ifdef _DEBUG_UMTA
		debug_info("[uri_rbl]: no answer: assuming blacklisted\n");
#endif
		goto ret_notbl;
	}
	/* skip questions */
	question_count = ntohs(h->qdcount);
	ptr = dns_skip_questions(buffer, len, question_count, ptr);
	if (ptr == NULL) {
		goto ret_err;
	}
	/* process answer */
	ptr = dns_process_answers(buffer, len, answer_count, ptr, req, &bl,
			answer_buff, answer_len);
	if (ptr == NULL) {
		goto ret_err;
	}
	/* skip ns (authority section) */
	ns_count = ntohs(h->nscount);
	ptr = dns_skip_answers(buffer, len, ns_count, ptr);
	if (ptr == NULL) {
		goto ret_err;
	}
	/* process additionnal answer */
	ar_count = ntohs(h->arcount);
	ptr = dns_process_answers(buffer, len, ar_count, ptr, req, &bl,
			answer_buff, answer_len);
	if (ptr == NULL) {
		goto ret_err;
	}
	/* check the end of the answer
	 * paranoid check
	 * or kind of debug
	 */
	remaining = (buffer + len) - ptr;
	if (remaining < 0) {
		debug_info("[uri_rbl]: too many bytes read from buffer: %d/%d\n",
			len + remaining, len);
	}
	if (remaining < 0) {
		debug_info("[uri_rbl]: remaining data from buffer: %d/%d\n",
			remaining, len);
	}
	if (bl == 0) {
		goto ret_notbl;
	}
ret_bl:
	return 1;
ret_err:
	return -1;
ret_notbl:
	return 0;
}

static BOOL dnsrbl_check(const char *uri, const char *dnsrbl,
	char *answer_buff, int answer_len)
{
	int ret, uri_len;
	char *d0, *d1, *d2, *d3;
	char req[1024], temp_ip[16];
	
	memset(req, 0, 256);
	if (uri == extract_ip((char*)uri, temp_ip)) {
		d0 = temp_ip;
		d1 = strchr(d0, '.');
		*d1 = '\0';
		d1 ++;
		d2 = strchr(d1, '.');
		*d2 = '\0';
		d2 ++;
		d3 = strchr(d2, '.');
		*d3 = '\0';
		d3 ++;
		snprintf(req, 1023, "%s.%s.%s.%s.%s", d3, d2, d1, d0, dnsrbl);
	} else {
		snprintf(req, 1023, "%s.%s", uri, dnsrbl);
	}
	req[1023] = '\0';
	
	res_init();
#ifdef _DEBUG_UMTA
	debug_info("[uri_rbl]: DEBUG: req = '%s'\n", req);
#endif
	ret = dnsrbl_check_query(req, T_A, answer_buff, answer_len);
	if (ret) {
		dnsrbl_check_query(req, T_TXT, answer_buff, answer_len);
	}
	if (ret > 0 && strlen(answer_buff) > 8) {
		return FALSE;
	} else {
		return TRUE;
	}
}

void uri_rbl_init(const char *cctld_path, const char *surbl_dns,
	const char *uribl_dns)
{
	g_cctld_hash = NULL;
	strcpy(g_cctld_path, cctld_path);
	if (NULL == surbl_dns || '\0' == surbl_dns[0]) {
		g_surbl_dns[0] = '\0';
	} else {
		strncpy(g_surbl_dns, surbl_dns, 255);
		g_surbl_dns[255] = '\0';
	}
	if (NULL == uribl_dns || '\0' == uribl_dns[0]) {
		g_uribl_dns[0] = '\0';
	} else {
		strncpy(g_uribl_dns, uribl_dns, 255);
		g_uribl_dns[255] = '\0';
	}
	pthread_rwlock_init(&g_table_lock, NULL);
}

void uri_rbl_free()
{
	g_cctld_path[0] = '\0';
	g_surbl_dns[0] = '\0';
	g_uribl_dns[0] = '\0';
	pthread_rwlock_destroy(&g_table_lock);
}

int uri_rbl_run()
{
	if (FALSE == uri_rbl_refresh()) {
		return -1;
	}
	return 0;
}

int uri_rbl_stop()
{
	if (NULL != g_cctld_hash) {
		str_hash_free(g_cctld_hash);
		g_cctld_hash = NULL;
	}
	return 0;
}

BOOL uri_rbl_check_cctld(const char *domain)
{
	char temp_string[256];
	
	strncpy(temp_string, domain, 255);
	temp_string[255] = '\0';
	lower_string(temp_string);
	
	pthread_rwlock_rdlock(&g_table_lock);
	if (NULL != str_hash_query(g_cctld_hash, temp_string)) {
		pthread_rwlock_unlock(&g_table_lock);
		return TRUE;
	} else {
		pthread_rwlock_unlock(&g_table_lock);
		return FALSE;
	}
}

BOOL uri_rbl_judge(const char *uri, char *answer_buff, int answer_len)
{
	int uri_len, ret;
	char buf[2046];
	char temp_ip[16];
	char temp_buff[256];
	char query_string[256];
	char *d0, *d1, *d2, *d3;
	struct hostent hostinfo, *phost;

	if (TRUE == uri_cache_query(uri, answer_buff, answer_len)) {
		return FALSE;
	}
	
	if (0 != g_surbl_dns[0]) {
		if (FALSE == dnsrbl_check(uri, g_surbl_dns, answer_buff, answer_len)) {
			uri_cache_add(uri, answer_buff);
			return FALSE;
		}
	}
	if (0 != g_uribl_dns[0]) {
		if (FALSE == dnsrbl_check(uri, g_uribl_dns, answer_buff, answer_len)) {
			uri_cache_add(uri, answer_buff);
			return FALSE;
		}
	}
	return TRUE;
}

BOOL uri_rbl_refresh()
{
	char *pitem;
	int i, count;
	LIST_FILE *plist;
	STR_HASH_TABLE *phash;

	plist = list_file_init(g_cctld_path, "%s:256"); 
	if (NULL == plist) {
		printf("[uri_rbl]: fail to load %s\n", g_cctld_path);
		return FALSE;
	}
	count = list_file_get_item_num(plist);
	pitem = list_file_get_list(plist);
	phash = str_hash_init(count + 1, sizeof(int), NULL);
	if (NULL == phash) {
		list_file_free(plist);
		printf("[uri_rbl]: fail to init hash table\n");
		return FALSE;
	}
	for (i=0; i<count; i++) {
		lower_string(pitem + 256*i);
		str_hash_add(phash, pitem + 256*i, &i);
	}
	list_file_free(plist);
	pthread_rwlock_wrlock(&g_table_lock);
	if (NULL != g_cctld_hash) {
		str_hash_free(g_cctld_hash);
	}
	g_cctld_hash = phash;
	pthread_rwlock_unlock(&g_table_lock);
	return TRUE;
}

const char* uri_rbl_get_dns(int param)
{
	if (URI_RBL_SURBL == param) {
		return g_surbl_dns;
	} else {
		return g_uribl_dns;
	}
}



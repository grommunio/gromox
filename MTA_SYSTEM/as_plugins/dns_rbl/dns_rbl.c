/* dnsrblscore.c - check DNS RBL
 *
 * Copyright (C) 2004 Yann Droneaud <ydroneaud@meuh.org>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
#include "dns_rbl.h"
#include "util.h"
#include "list_file.h"
#include <pthread.h>
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


#define MAX_DNSRBL			256
#define MAX_LISTITEM		32

struct dnsrbl
{
  unsigned int errors; /* number of errors since last reset */
  time_t timestamp;    /* last query */
  char name[NS_MAXDNAME + 1];
};

static char g_path[256];
static int g_dnsrbl_count;
static pthread_rwlock_t g_list_lock;
static struct dnsrbl g_list[MAX_LISTITEM];


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
		debug_info("[dns_rbl]: dns_explode_answers(): decoding error: "
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
							debug_info("[dns_rbl]: string overflow\n");
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
					debug_info("[dns_rbl]: data size mismatch\n");
					return NULL;
				}
				if (0 != strncmp("127.0.0.", inet_ntoa(
					*(struct in_addr*)rr_data), 8)) {
					/* DNS is kidnapped */
					return NULL;
				}
#ifdef _DEBUG_UMTA	  
				debug_info("[dns_rbl]: %s\n", 
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

	for(; count>0; count--) {
		rr_name_len = sizeof(rr_name);
		rr_name_len = dn_expand(buffer, buffer + len, ptr, rr_name, 
						rr_name_len);
		if (rr_name_len < 0) {
			debug_info("[dns_rbl]: dns_skip_questions(): decoding error: "
				"rr_name_len = %d\n", rr_name_len);
			return NULL;
		}
		ptr += rr_name_len;
		ptr += NS_INT16SZ; /* rr_type */
		ptr += NS_INT16SZ; /* rr_class */
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
					debug_info("[dns_rbl]: res_query failed: %s\n",
						hstrerror(h_errno));
					return -1;
				}
			case HOST_NOT_FOUND:
				return 0; /* not listed */
			default:
				debug_info("[dns_rbl]: res_query failed: %s\n",
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
					debug_info("[dns_rbl]: buffer too short\n");
					goto ret_err;
				}
			}
		}
#ifdef _DEBUG_UMTA
		debug_info("[dns_rbl]: DEBUG: len = %d\n", len);
#endif
		if (i > 3) {
			debug_info("[dns_rbl]: can't find correct buffer size for query\n");
			goto ret_err;
		}
	}
	if (!h->qr) {
		debug_info("[dns_rbl]: packet is not an answer!\n");
		goto ret_err;
	}
	if (h->rcode != NOERROR) {
		debug_info("[dns_rbl]: error returned in answer\n");
		goto ret_err;
	}
	/* skip header */
	ptr = buffer + sizeof(HEADER);
	answer_count = ntohs(h->ancount);
	if (answer_count <= 0) {
#ifdef _DEBUG_UMTA
		debug_info("[dns_rbl]: no answer: assuming blacklisted\n");
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
		debug_info("[dns_rbl]: too many bytes read from buffer: %d/%d\n",
			len + remaining, len);
	}
	if (remaining < 0) {
		debug_info("[dns_rbl]: remaining data from buffer: %d/%d\n",
			remaining, len);
	}
	if (bl == 0) {
		goto ret_notbl;
	}
	return 1;
ret_err:
	return -1;
ret_notbl:
	return 0;
}

static int dnsrbl_check(const struct in_addr *addr, const char *dnsrbl,
	char *answer_buff, int answer_len)
{
	char req[1024];
	int ret;
	
	sprintf(req, "%u.%u.%u.%u.%s",
	  ((uint8_t *)addr)[3],
	  ((uint8_t *)addr)[2],
	  ((uint8_t *)addr)[1],
	  ((uint8_t *)addr)[0],
	  dnsrbl);
	
	res_init();
#ifdef _DEBUG_UMTA
	debug_info("[dns_rbl]: DEBUG: req = '%s'\n", req);
#endif
	ret = dnsrbl_check_query(req, T_A, answer_buff, answer_len);
	if (ret) {
		dnsrbl_check_query(req, T_TXT, answer_buff, answer_len);
	}
	return ret;
}

BOOL dns_rbl_judge(const char *ip, char *answer_buff, int answer_len)
{
	struct in_addr addr;
	struct dnsrbl *r;
	int s, i;

	if (inet_pton(AF_INET, ip, &addr) <= 0) {
		return TRUE;
	}
	pthread_rwlock_rdlock(&g_list_lock);
	for(i=0; i!=g_dnsrbl_count; i++) {
		r = &g_list[i];
		memset(answer_buff, 0, answer_len);
		s = dnsrbl_check(&addr, r->name, answer_buff, answer_len);
		if (s > 0 && strlen(answer_buff) > 8) {
			pthread_rwlock_unlock(&g_list_lock);
			return FALSE;
		}
	}
	pthread_rwlock_unlock(&g_list_lock);
	return TRUE;
}

void dns_rbl_init(const char *path)
{
	g_dnsrbl_count = 0;
	strcpy(g_path, path);
	pthread_rwlock_init(&g_list_lock, NULL);
}

void dns_rbl_free()
{
	pthread_rwlock_destroy(&g_list_lock);
}

int dns_rbl_stop()
{
	g_dnsrbl_count = 0;
	return 0;
}

int dns_rbl_run()
{
	if (FALSE == dns_rbl_refresh()) {
		return -1;
	}
	return 0;
}

BOOL dns_rbl_refresh()
{
	int i, count;
	const char *pitem;
	LIST_FILE *plist_file;

	plist_file = list_file_init(g_path, "%s:256");
	if (NULL == plist_file) {
		printf("[dns_rbl]: fail to load %s\n", g_path);
		return FALSE;
	}
	count = list_file_get_item_num(plist_file);
	if (count > MAX_LISTITEM) {
		count = MAX_LISTITEM;
	}
	pitem = list_file_get_list(plist_file);
	pthread_rwlock_wrlock(&g_list_lock);
	for (i=0; i<count; i++) {
		strcpy(g_list[i].name, pitem + 256*i);
		g_list[i].timestamp = 0;
		g_list[i].errors = 0;
	}
	g_dnsrbl_count = i;
	pthread_rwlock_unlock(&g_list_lock);
	list_file_free(plist_file);
	return TRUE;
}



#include <ctype.h>
#include <time.h>
#include <gromox/acl_control.h>
#include "system_log.h"
#include "list_file.h"
#include "util.h"
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ACL_CAPACITY			1024
#define MAX_ITEMS_PER_IP		64
#define TOKEN_SESSION           1

static char g_token_path[256];
static char g_acl_path[256];
static int g_timeout;
static LIST_FILE *g_acl_list;
static char *g_shm_begin;

void acl_control_init(const char *token_path, const char *acl_path, int timeout)
{
	strcpy(g_token_path, token_path);
	strcpy(g_acl_path, acl_path);
	g_timeout = timeout;
	g_shm_begin = NULL;
	g_acl_list = NULL;
}

int acl_control_run()
{
	int shm_id;
	key_t k_shm;
	
	g_acl_list = list_file_init(g_acl_path, "%s:256%s:256%s:256");
	if (NULL == g_acl_list) {
		system_log_info("[acl_control]: fail to init acl list %s", g_acl_path);
		return -1;
	}
	
	k_shm = ftok(g_token_path, TOKEN_SESSION);

	if (-1 == k_shm) {
		system_log_info("[acl_control]: fail to get share memory token %s",
			g_token_path);
		list_file_free(g_acl_list);
		g_acl_list = NULL;
		return -2;
	}
	
	shm_id = shmget(k_shm, ACL_CAPACITY*(32+sizeof(time_t)+16+256), 0666);
	
	if (-1 == shm_id) {
		shm_id = shmget(k_shm, ACL_CAPACITY*(32+sizeof(time_t)+16+256),
					0666|IPC_CREAT);
	}
	if (-1 == shm_id) {
	    system_log_info("[acl_control]: fail to get share memory %s for "
			"caching sessions", g_token_path);
		list_file_free(g_acl_list);
		g_acl_list = NULL;
		return -3;
	}

	g_shm_begin = shmat(shm_id, NULL, 0);
	if (NULL == g_shm_begin) {
		system_log_info("[acl_control]: fail to attach share memory");
		list_file_free(g_acl_list);
		g_acl_list = NULL;
		return -4;
	}
	return 0;
}

BOOL acl_control_auth(const char *username, const char *password)
{
	char temp_buff[256];
	char *pitem, temp_char;
	int i, j, len, item_num;

	item_num = list_file_get_item_num(g_acl_list);
	pitem = list_file_get_list(g_acl_list);

	if (0 == item_num && 0 == strcasecmp(username, "administrator") &&
		0 == strlen(password)) {
		return TRUE;
	}
	
	for (i=0; i<item_num; i++) {
		if (0 == strcasecmp(pitem + 3*256*i , username)) {
			memset(temp_buff, 0, 256);
			encode64(password, strlen(password), temp_buff, 256, &len);
			for (j=0; j<len/2; j++) {
				temp_char = temp_buff[j];
				temp_buff[j] = temp_buff[len - 1 - j];
				temp_buff[len - 1 - j] = temp_char;
			}
			if (0 == strcmp(temp_buff, pitem + 3*256*i + 256)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL acl_control_produce(const char *username, const char *ip, char *session)
{
	int ip_num;
	int i, pos, mod;
	char *pitem;
	char temp_addr[16];
	char temp_time[16];
	char temp_name[16];
	time_t cur_time;
	in_addr_t ip_addr;
	
	time(&cur_time);
	ip_addr = inet_addr(ip);
	sprintf(temp_addr, "%x", ip_addr);
	/* fill 'g' if length is too short */
	pos = strlen(temp_addr);
	if (pos < 8) {
		for (; pos<8; pos++) {
			temp_addr[pos] = 'g';
		}
	}
	temp_addr[8] = '\0';
	sprintf(temp_time, "%x", cur_time);
	if (strlen(username) >= 16) {
		memcpy(temp_name, username, 16);
	} else {
		memset(temp_name, '0', 16);
		memcpy(temp_name, username, strlen(username));
	}
	for (i=0; i<16; i++) {
		if ('@' == temp_name[i]) {
			temp_name[i] = '0';
		} else {
			temp_name[i] = tolower(temp_name[i]);
		}
	}
	for (i=0; i<32; i++) {
		mod = i%4;
		pos = i/4;
		if (0 == mod || 1 == mod) {
			session[i] = temp_name[pos*2 + mod];
		} else if (2 == mod) {
			session[i] = temp_addr[pos];
		} else {
			session[i] = temp_time[pos];
		}
	}
	session[32] = '\0';

	ip_num = 0;
	for (i=0; i<ACL_CAPACITY; i++) {
		pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
		if ('\0' != *pitem && cur_time - *(time_t*)(pitem + 32) <= g_timeout &&
			0 == strcmp(pitem+32+sizeof(time_t), ip)) {
			ip_num ++;
		}
	}
	if (ip_num >= MAX_ITEMS_PER_IP) {
		system_log_info("[acl_control]: session too many for %s", ip);
		return FALSE;
	}
	for (i=0; i<ACL_CAPACITY; i++) {
		pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
		if ('\0' == *pitem) {
			break;		
		}
	}
	if (i == ACL_CAPACITY) {
		for (i=0; i<ACL_CAPACITY; i++) {
			pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
			if ('\0' != *pitem && cur_time-*(time_t*)(pitem + 32) > g_timeout) {
				*pitem = '\0';
				break;
			}
		}
	}

	if (i < ACL_CAPACITY) {
		memcpy(pitem, session, 32);
		time((time_t*)(pitem + 32));
		strcpy(pitem + 32 + sizeof(time_t), ip);
		strcpy(pitem + 32 + sizeof(time_t) + 16, username);
		return TRUE;
	} else {
		system_log_info("[acl_control]: session limitation is reached, you can "
			"restart service athena to clean session cache!");
		return FALSE;
	}
}

int acl_control_check(const char *session, const char *ip, int m_id)
{
	int i, j;
	int item_num;
	time_t cur_time;
	char *pitem, *pacl;

	if (strlen(session) != 32) {
		return ACL_SESSION_ERROR;
	}
	item_num = list_file_get_item_num(g_acl_list);
	pacl = list_file_get_list(g_acl_list);
	time(&cur_time);
	for (i=0; i<ACL_CAPACITY; i++) {
		pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
		if (0 == strncmp(pitem, session, 32)) {
			if (cur_time - *(time_t*)(pitem + 32) > g_timeout) {
				*pitem = '\0';
				return ACL_SESSION_TIMEOUT;
			}
			if (0 != strcmp(ip, pitem + 32 + sizeof(time_t))) {
				return ACL_SESSION_ERROR;
			}
			if (0 != strcasecmp(pitem + 32 + sizeof(time_t) + 16,
				"administrator") && ACL_PRIVILEGE_IGNORE != m_id) {
				for (j=0; j<item_num; j++) {
					if (0 == strcasecmp(pacl + 3*256*j,
						pitem + 32 + sizeof(time_t) + 16)) {
						break;
					}	
				}
				if (j == item_num) {
					return ACL_SESSION_ERROR;
				}
				if (*(pacl + 3*256*j + 512 + m_id) != '1') {
					return ACL_SESSION_PRIVILEGE;
				}
			}
			time((time_t*)(pitem + 32));
			return ACL_SESSION_OK;
		}
	}
	return ACL_SESSION_ERROR;
}

BOOL acl_control_naming(const char *session, char *username)
{
	int i;
	char *pitem;

	if (strlen(session) != 32) {
		return FALSE;
	}
	for (i=0; i<ACL_CAPACITY; i++) {
		pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
		if (0 == strncmp(pitem, session, 32)) {
			strcpy(username, pitem + 32 + sizeof(time_t) + 16);
			return TRUE;
		}
	}
	return FALSE;
}

void acl_control_remove(const char *session)
{
	int i;
	char *pitem;
	
	if (strlen(session) != 32) {
		return;
	}

	for (i=0; i<ACL_CAPACITY; i++) {
		pitem = g_shm_begin + i * (32 + sizeof(time_t) + 16 + 256);
		if (0 == strncmp(pitem, session, 32)) {
			*pitem = '\0';
		}
	}
}

int acl_control_stop()
{
	if (NULL != g_shm_begin) {
		shmdt(g_shm_begin);
		g_shm_begin = NULL;
	}
	if (NULL != g_acl_list) {
		list_file_free(g_acl_list);
		g_acl_list = NULL;
	}
	return 0;
}

void acl_control_free()
{
	/* do nothing */
}



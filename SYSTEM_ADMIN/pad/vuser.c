#include "vuser.h"
#include "pop3.h"
#include "uid_db.h"
#include "midb_client.h"
#include "data_source.h"
#include "list_file.h"
#include "mail_func.h"
#include "mail.h"
#include "sensor_client.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


typedef struct _POP3_ACCOUNT {
	char hostname[256];
	int port;
	char username[256];
	char password[256];
	int b_undelete;
} POP3_ACCOUNT;


void vuser_init(VUSER *puser, const char *username)
{
	strcpy(puser->username, username);
}

int vuser_work(VUSER *puser)
{
	char temp_path[256];
	char mailbox_path[256];
	POP3_SESSION session;
	LIST_FILE *pfile;
	UID_DB uid_db;
	UID_ITEM *puid;
	struct in_addr ip_addr;
	char **p_addr;
	char buf[2046];
	char temp_ip[16];
	char mid_string[128];
	struct hostent hostinfo, *phost;
	POP3_ACCOUNT *paccount;
	POP3_ACCOUNT *accounts;
	int ret, i, num, count;
	struct stat node_stat;


	if (FALSE == data_source_get_maildir(puser->username, mailbox_path)) {
		return VUSER_FAIL;
	}

	if ('\0' == mailbox_path[0]) {
		return VUSER_NONE;
	}

	if (FALSE == midb_client_ckfl(mailbox_path)) {
		return VUSER_FAIL;
	}
	
	snprintf(temp_path, 255, "%s/config/pop.cfg", mailbox_path);

	if (0 != stat(temp_path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return VUSER_NONE;
	}

	pfile = list_file_init(temp_path, "%s:256%d%s:256%s:256%d");
	if (NULL == pfile) {
		return VUSER_FAIL;
	}

	num = list_file_get_item_num(pfile);
	accounts = (POP3_ACCOUNT*)list_file_get_list(pfile);

	for (i=0; i<num; i++) {
		paccount = accounts + i;
		if (0 == strcasecmp(paccount->username, puser->username)) {
			continue;
		}
		if (extract_ip(paccount->hostname, temp_ip) == NULL) {
			if (0 != gethostbyname_r(paccount->hostname, &hostinfo, buf,
				sizeof(buf), &phost, &ret) || NULL == phost) {
				continue;
			}
	        p_addr = phost->h_addr_list;
			if (NULL == p_addr) {
				continue;
			}
			ip_addr.s_addr = *((unsigned int *)*p_addr);
			strcpy(temp_ip, inet_ntoa(ip_addr));
		}

		uid_db_init(&uid_db, mailbox_path, paccount->username);
		if (FALSE == uid_db_open(&uid_db)) {
			uid_db_free(&uid_db);
			continue;
		}

		pop3_init(&session, temp_ip, paccount->port, paccount->username,
			paccount->password);
		if (FALSE == pop3_login(&session) || FALSE == pop3_uidl(&session)) {
			pop3_free(&session);
			uid_db_close(&uid_db);
			uid_db_free(&uid_db);
			continue;
		}

		if (FALSE == uid_db_check(&uid_db, &session)) {
			pop3_free(&session);
			uid_db_close(&uid_db);
			uid_db_free(&uid_db);
			continue;
		}
		count = 0;
		for (puid=pop3_uidl_head(&session); NULL!=puid;
			puid=pop3_uidl_next(&session)) {
			snprintf(mid_string, 127, "%d.%d.pad.%d.%u", time(NULL),
				puid->id, i + 1, pthread_self());
			sprintf(temp_path, "%s/eml/%s", mailbox_path, mid_string);
			if (TRUE == pop3_retr(&session, puid, temp_path)) {
				if (TRUE == midb_client_insert(
					mailbox_path, "inbox", mid_string)) {
					count ++;
					if (0 != paccount->b_undelete) {
						pop3_mark(&session, puid);
					} else {
						pop3_delete(&session, puid);
					}
				} else {
					remove(temp_path);
				}
			}
		}

		pop3_update(&session);
		uid_db_update(&uid_db, &session);
		pop3_free(&session);
		uid_db_close(&uid_db);
		uid_db_free(&uid_db);
		if (count > 0) {
			sensor_client_add(puser->username, count);
		}
	}

	list_file_free(pfile);
	return VUSER_OK;

}

void vuser_free(VUSER *puser)
{
	puser->username[0] = '\0';
}


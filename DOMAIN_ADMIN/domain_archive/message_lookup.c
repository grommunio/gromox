#include "message_lookup.h"
#include "list_file.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>


#define SOCKET_TIMEOUT		60


typedef struct _CIDB_HOST {
	char prefix[128];
	char ip[16];
	int port;
} CIDB_HOST;

static char g_cidb_path[256];

void message_lookup_init(const char *cidb_path)
{
	strcpy(g_cidb_path, cidb_path);
}

int message_lookup_run()
{
	/* do nothing */
	return 0;
}

void message_lookup_stop(void)
{
	/* do nothing */
}

void message_lookup_free()
{
	/* do nothing */
}

LOOKUP_COLLECT* message_lookup_collect_init()
{
	LOOKUP_COLLECT *pcollect;

	pcollect = (LOOKUP_COLLECT*)malloc(sizeof(LOOKUP_COLLECT));
	if (NULL == pcollect) {
		return NULL;
	}
	
	double_list_init(&pcollect->message_list);
	pcollect->pnode = NULL;
	return pcollect;
}

void message_lookup_collect_free(LOOKUP_COLLECT *pcollect)
{
	DOUBLE_LIST_NODE *pnode;
	
	while (pnode=double_list_get_from_head(&pcollect->message_list)) {
		free(pnode->pdata);
	}
	double_list_free(&pcollect->message_list);
	
	
	free(pcollect);
}

int message_lookup_collect_total(LOOKUP_COLLECT *pcollect)
{
	return double_list_get_nodes_num(&pcollect->message_list);
}

void message_lookup_collect_begin(LOOKUP_COLLECT *pcollect)
{
	 pcollect->pnode = double_list_get_head(&pcollect->message_list);
}

int message_lookup_collect_done(LOOKUP_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
        return 1;
    }
    return 0;
}

MESSAGE_ITEM* message_lookup_collect_get_value(LOOKUP_COLLECT *pcollect)
{
	if (NULL == pcollect || NULL == pcollect->pnode) {
        return NULL;
    }
    return (MESSAGE_ITEM*)(pcollect->pnode->pdata);
}

int message_lookup_collect_forward(LOOKUP_COLLECT *pcollect)
{
    DOUBLE_LIST_NODE *pnode;
	
	if (NULL == pcollect->pnode) {
		return -1;
	}
    pnode = double_list_get_after(&pcollect->message_list, pcollect->pnode);
    if (NULL == pnode) {
        pcollect->pnode = NULL;
        return -1;
    }
    pcollect->pnode = pnode;
    return 1;
}

static int message_lookup_connect_cidb(const char *ip_addr, int port)
{
    int sockd;
    int offset;
    int read_len;
	fd_set myset;
	struct timeval tv;
    char temp_buff[1024];
    struct sockaddr_in servaddr;
	
	
    sockd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
    if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        close(sockd);
        return -1;
    }
	tv.tv_usec = 0;
	tv.tv_sec = SOCKET_TIMEOUT;
	FD_ZERO(&myset);
	FD_SET(sockd, &myset);
	if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		close(sockd);
		return -1;
	}
	read_len = read(sockd, temp_buff, 1024);
	if (read_len <= 0) {
        close(sockd);
        return -1;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static BOOL message_lookup_search_mail(int server_id, CIDB_HOST *pserver,
	const char *cmd_string, int cmd_len, DOUBLE_LIST *plist_result)
{
	int i;
	int sockd;
	int lines;
	int count;
	int offset;
	int length;
	int last_pos;
	int read_len;
	int line_pos;
	fd_set myset;
	struct timeval tv;
	char num_buff[32];
	char temp_line[512];
	char buff[256*1025];
	MESSAGE_ITEM *pmessage;


	sockd = message_lookup_connect_cidb(pserver->ip, pserver->port);
	if (-1 == sockd) {
		return FALSE;
	}

	if (cmd_len != write(sockd, cmd_string, cmd_len)) {
		close(sockd);
		return FALSE;
	}

	count = 0;
	offset = 0;
	lines = -1;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			close(sockd);
			return FALSE;
		}
		read_len = read(sockd, buff + offset, 256*1024 - offset);
		if (read_len <= 0) {
			close(sockd);
			return FALSE;
		}
		offset += read_len;
		buff[offset] = '\0';
		
		if (-1 == lines) {
			for (i=0; i<offset-1&&i<36; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					if (0 == strncmp(buff, "TRUE ", 5)) {
						memcpy(num_buff, buff + 5, i - 5);
						num_buff[i - 5] = '\0';
						lines = atoi(num_buff);
						if (lines < 0) {
							close(sockd);
							return FALSE;
						}
						last_pos = i + 2;
						line_pos = 0;
						break;
					} else if (0 == strncmp(buff, "FALSE ", 6)) {
						close(sockd);
						return FALSE;
					}
				}
			}
			if (-1 == lines) {
				if (offset > 1024) {
					close(sockd);
					return FALSE;
				}
				continue;
			}
		}

		for (i=last_pos; i<offset; i++) {
			if ('\r' == buff[i] && i < offset - 1 && '\n' == buff[i + 1]) {
				count ++;
			} else if ('\n' == buff[i] && '\r' == buff[i - 1]) {
				temp_line[line_pos] = '\0';
				pmessage = (MESSAGE_ITEM*)malloc(sizeof(MESSAGE_ITEM));
				if (NULL == pmessage) {
					close(sockd);
					return FALSE;
				}
				pmessage->node.pdata = pmessage;
				pmessage->mail_id = atoll(temp_line);
				pmessage->server_id = server_id;
				double_list_append_as_tail(plist_result, &pmessage->node);
				line_pos = 0;
			} else {
				if ('\r' != buff[i] || i != offset - 1) {
					temp_line[line_pos] = buff[i];
					line_pos ++;
					if (line_pos >= 32) {
						close(sockd);
						return FALSE;
					}
				}
			}
		}

		if (count >= lines) {
			close(sockd);
			return TRUE;
		}

		if ('\r' == buff[offset - 1]) {
			last_pos = offset - 1;
		} else {
			last_pos = offset;
		}

		if (256*1024 == offset) {
			if ('\r' != buff[offset - 1]) {
				offset = 0;
			} else {
				buff[0] = '\r';
				offset = 1;
			}
			last_pos = 0;
		}
	}

}


BOOL message_lookup_search(int server_id, const char *charset,
	const char *unit, const char *sender, const char *rcpt,
	const char *from, const char *to, const char *cc,
	const char *subject, const char *content, const char *filename,
	BOOL *attached, int *priority, VAL_SCOPE *atime, VAL_SCOPE *rtime,
	VAL_SCOPE *ctime, VAL_SCOPE *size, uint64_t *reference,
	VAL_SCOPE *id, HEADER_VAL *header, LOOKUP_COLLECT *pcollect)
{
	int i;
	int length;
	int item_num;
	size_t encode_len;
	CIDB_HOST *pitem;
	LIST_FILE *pfile;
	char cmd_buff[64*1024];
	DOUBLE_LIST_NODE *pnode;
	
	
	length = snprintf(cmd_buff, sizeof(cmd_buff), "A-SRCH %s", charset);
	
	if (NULL != unit) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" UNIT ");
		encode64(unit, strlen(unit), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != sender) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" SENDER ");
		encode64(sender, strlen(sender), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != rcpt) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" RCPT ");
		encode64(rcpt, strlen(rcpt), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != from) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" FROM ");
		encode64(from, strlen(from), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != to) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" TO ");
		encode64(to, strlen(to), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != cc) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" CC ");
		encode64(cc, strlen(cc), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != subject) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" SUBJECT ");
		encode64(subject, strlen(subject), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != content) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" CONTENT ");
		encode64(content, strlen(content), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != filename) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" FILENAME ");
		encode64(filename, strlen(filename), cmd_buff + length,
			sizeof(cmd_buff) - length, &encode_len);
		length += encode_len;
	}
	
	if (NULL != attached) {
		if (FALSE == *attached) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" ATTACHED NO");
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" ATTACHED YES");
		}
	}
	
	if (NULL != priority) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" PRIORITY %d", *priority);
	}
	
	if (NULL != atime) {
		if (0 == atime->begin) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ATIME LE %lld", atime->end);
		} else if (-1 == atime->end) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ATIME GE %lld", atime->begin);
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ATIME %lld %lld", atime->begin, atime->end);
		}
	}
	
	if (NULL != rtime) {
		if (0 == rtime->begin) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" RTIME LE %lld", rtime->end);
		} else if (-1 == rtime->end) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" RTIME GE %lld", rtime->begin);
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" RTIME %lld %lld", rtime->begin, rtime->end);
		}
	}
	
	if (NULL != ctime) {
		if (0 == ctime->begin) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" CTIME LE %lld", ctime->end);
		} else if (-1 == ctime->end) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" CTIME GE %lld", ctime->begin);
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" CTIME %lld %lld", ctime->begin, ctime->end);
		}
	}
	
	if (NULL != size) {
		if (0 == size->begin) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" SIZE LE %lld", size->end);
		} else if (-1 == size->end) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" SIZE GE %lld", size->begin);
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" SIZE %lld %lld", size->begin, size->end);
		}
	}
	
	if (NULL != id) {
		if (0 == id->begin) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ID LE %lld", id->end);
		} else if (-1 == id->end) {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ID GE %lld", id->begin);
		} else {
			length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
						" ID %lld %lld", id->begin, id->end);
		}
	}
	
	if (NULL != reference) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" REFERENCE %lld", *reference);
	}
	
	if (NULL != header) {
		length += snprintf(cmd_buff + length, sizeof(cmd_buff) - length,
					" HEADER %s %s", header->field, header->value);
	}
	
	cmd_buff[length]='\r';
	length ++;
	cmd_buff[length] ='\n';
	length ++;
	
	pfile = list_file_init(g_cidb_path, "%s:128%s:16%d");
	if (NULL == pfile) {
		return FALSE;
	}
	
	item_num = list_file_get_item_num(pfile);
	pitem = (CIDB_HOST*)list_file_get_list(pfile);
	if (-1 == server_id) {
		for (i=0; i<item_num; i++) {
			if (FALSE == message_lookup_search_mail(i, &pitem[i], cmd_buff,
				length, &pcollect->message_list)) {
				list_file_free(pfile);
				return FALSE;
			}
		}
	} else {
		if (server_id < 0 || server_id >= item_num) {
			list_file_free(pfile);
			return FALSE;
		}
		if (FALSE == message_lookup_search_mail(server_id, &pitem[server_id],
			cmd_buff, length, &pcollect->message_list)) {
			list_file_free(pfile);
			return FALSE;
		}
	}
	list_file_free(pfile);
	
	return TRUE;
	
}

BOOL message_lookup_match(int server_id, uint64_t mail_id,
	char *path, char *digest)
{
	int sockd;
	int length;
	int read_len;
	fd_set myset;
	char *pspace;
	CIDB_HOST *pitem;
	LIST_FILE *pfile;
	struct timeval tv;
	char cmd_buff[1024];
	char tmp_buff[256*1025];
	
	
	pfile = list_file_init(g_cidb_path, "%s:128%s:16%d");
	if (NULL == pfile) {
		return FALSE;
	}
	
	if (server_id >= list_file_get_item_num(pfile)) {
		list_file_free(pfile);
		return FALSE;
	}
	
	pitem = (CIDB_HOST*)list_file_get_list(pfile);
	
	length = snprintf(cmd_buff, 1024, "A-MTCH %lld\r\n", mail_id);
	sockd = message_lookup_connect_cidb(pitem[server_id].ip,
				pitem[server_id].port);
	strcpy(path, pitem[server_id].prefix);
	list_file_free(pfile);
	if (-1 == sockd) {
		return FALSE;
	}
	
	if (length != write(sockd, cmd_buff, length)) {
		close(sockd);
		return FALSE;
	}
	
	length = 0;
	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(sockd, &myset);
		if (select(sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			close(sockd);
			return FALSE;
		}
		read_len = read(sockd, tmp_buff + length, 256*1025 - length);
		if (read_len <= 0) {
			close(sockd);
			return FALSE;
		}
		
		length += read_len;
		if ('\r' == tmp_buff[length - 2] && '\n' == tmp_buff[length - 1]) {
			close(sockd);
			tmp_buff[length - 2] = '\0';
			if (0 == strncasecmp(tmp_buff, "TRUE ", 5)) {
				pspace = strchr(tmp_buff + 5, ' ');
				if (NULL == pspace) {
					return FALSE;
				}
				*pspace = '\0';
				strcat(path, tmp_buff + 5);
				strncpy(digest, pspace + 1, 256*1024);
				return TRUE;
			}
			return FALSE;
		}
		
	}
	
}



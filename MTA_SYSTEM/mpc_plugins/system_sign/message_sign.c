#include <unistd.h>
#include "message_sign.h"
#include "single_list.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>

#define MAX_SIGN_SIZE		4096

enum {
	TYPE_PLAIN,
	TYPE_HTML
};


typedef struct _SIGN_NODE {
	SINGLE_LIST_NODE node;
	int type;
	char charset[32];
	char *sign_content;
	int sign_length;
} SIGN_NODE;

static SINGLE_LIST *g_sign_list;
static char g_sign_path[256];
static pthread_rwlock_t g_list_lock;

static void message_sign_free_list(SINGLE_LIST *plist);

static void message_sign_mime(MIME *pmime);

void message_sign_init(const char *path)
{
	g_sign_list = NULL;
	strcpy(g_sign_path, path);
	pthread_rwlock_init(&g_list_lock, NULL);
}

int message_sign_run()
{
	if (FALSE == message_sign_refresh()) {
		return -1;
	}
	return 0;
}

void message_sign_mark(MAIL *pmail)
{
	MIME *pmime;
	MIME *phtml;
	MIME *pplain;
	char temp_buff[1024];
	
	pmime = mail_get_head(pmail);
	/* for Encryption mail, do not sign the message body */
	if (0 == strcasecmp("multipart/signed", mime_get_content_type(pmime)) ||
		TRUE == mime_get_content_param(pmime, "smime-type", temp_buff, 1024)) {
		return;
	}
	pplain = NULL;
	phtml = NULL;
	/* try to get script text in the mail */
	if (0 == strcasecmp("text/plain", mime_get_content_type(pmime))) {
		pplain = pmime;
	} else if (0 == strcasecmp("text/html", mime_get_content_type(pmime))) {
		phtml = pmime;
	} else {
		pmime = mail_get_mime_horizontal(pmail, pmime, 1, 0);
		if (NULL == pmime || 0 == strcasecmp("multipart/signed",
			mime_get_content_type(pmime))) {
			return;
		}
		if (0 == strcasecmp("text/plain", mime_get_content_type(pmime))) {
			pplain = pmime;
			pmime =  mail_get_mime_vertical(pmail, pmime, 0, 1);
			if (NULL != pmime && 0 == strcasecmp("text/html",
				mime_get_content_type(pmime))) {
				phtml = pmime;
			}
		} else if (0 == strcasecmp("text/html", mime_get_content_type(pmime))) {
			phtml = pmime;
		} else {
			pmime = mail_get_mime_horizontal(pmail, pmime, 1, 0);
			if (NULL == pmime || 0 == strcasecmp("multipart/signed",
				mime_get_content_type(pmime))) {
				return;
			}
			if (0 == strcasecmp("text/plain", mime_get_content_type(pmime))) {
				pplain = pmime;
				pmime =  mail_get_mime_vertical(pmail, pmime, 0, 1);
				if (NULL != pmime && 0 == strcasecmp("text/html",
					mime_get_content_type(pmime))) {
					phtml = pmime;
				}
			} else if (0 == strcasecmp("text/html",
				mime_get_content_type(pmime))) {
				phtml = pmime;
			} else {
				pmime = mail_get_mime_horizontal(pmail, pmime, 1, 0);
				if (NULL == pmime || 0 == strcasecmp("multipart/signed",
					mime_get_content_type(pmime))) {
					return;
				}
				if (0 == strcasecmp("text/plain",
					mime_get_content_type(pmime))) {
					pplain = pmime;
					pmime =  mail_get_mime_vertical(pmail, pmime, 0, 1);
					if (NULL != pmime && 0 == strcasecmp("text/html",
						mime_get_content_type(pmime))) {
						phtml = pmime;
					}
				} else if (0 == strcasecmp("text/html",
					mime_get_content_type(pmime))) {
					phtml = pmime;
				} else {
					return;
				}
			}
		}
	}
	if (NULL != pplain) {
		message_sign_mime(pplain);
	}
	if (NULL != phtml) {
		message_sign_mime(phtml);
	}
}
	
static void message_sign_mime(MIME *pmime)
{
	size_t length;
	int temp_len;
	int text_type;
	int encoding_type;
	char charset[32];
	char encoding[256];
	SINGLE_LIST_NODE *pnode;
	SIGN_NODE *pitem;
	SIGN_NODE *pus_ascii;
	char *begin, *end;
	char temp_charset[32];
	char temp_buff[64*1024];

	if (0 == strcasecmp("text/plain", mime_get_content_type(pmime))) {
		text_type = TYPE_PLAIN;
	} else if (0 == strcasecmp("text/html", mime_get_content_type(pmime))) {
		text_type = TYPE_HTML;
	} else {
		return;
	}
	if (FALSE == mime_get_field(pmime, "Content-Transfer-Encoding",
		encoding, 256)) {
		encoding_type = MIME_ENCODING_NONE;
	} else {
		if (0 == strcasecmp("base64", encoding)) {
			encoding_type = MIME_ENCODING_BASE64;
		} else if (0 == strcasecmp("quoted-printable", encoding)) {
			encoding_type = MIME_ENCODING_QP;
		} else {
			encoding_type = MIME_ENCODING_NONE;
		}
	}
	length = sizeof(temp_buff) - MAX_SIGN_SIZE;
	if (FALSE == mime_read_content(pmime, temp_buff, &length)) {
		return;
	}
	if (TRUE == mime_get_content_param(pmime, "charset", temp_charset, 32)) {
		temp_len = strlen(temp_charset);
		if (temp_len <= 2) {
			return;
		}
		begin = strchr(temp_charset, '"');
		if (NULL != begin) {
			end = strchr(begin + 1, '"');
			if (NULL == end) {
				return;
			}
			temp_len = end - begin - 1;
			memcpy(charset, begin + 1, temp_len);
			charset[temp_len] = '\0';
		} else {
			strcpy(charset, temp_charset);
		}
	} else {
		strcpy(charset, "us-ascii");
	}
	pus_ascii = NULL;
	pthread_rwlock_rdlock(&g_list_lock);
	for (pnode=single_list_get_head(g_sign_list); pnode!=NULL;
		pnode=single_list_get_after(g_sign_list, pnode)) {
		pitem = (SIGN_NODE*)pnode->pdata;
		if (text_type != pitem->type) {
			continue;
		}
		if (0 == strcasecmp(pitem->charset, charset)) {
			break;
		}
		if (0 == strcasecmp(pitem->charset, "us-ascii")) {
			pus_ascii = pitem;
		}
	}
	if (NULL == pnode) {
		if (NULL != pus_ascii) {
			memcpy(temp_buff + length, pus_ascii->sign_content,
				pus_ascii->sign_length);
			mime_write_content(pmime, temp_buff,
				length + pus_ascii->sign_length, encoding_type);
		}
	} else {
		memcpy(temp_buff + length, pitem->sign_content, pitem->sign_length);
		mime_write_content(pmime, temp_buff, length + pitem->sign_length,
			encoding_type);
	}
	pthread_rwlock_unlock(&g_list_lock);
}

int message_sign_stop()
{
	if (NULL != g_sign_list) {
		message_sign_free_list(g_sign_list);
		g_sign_list = NULL;
	}
	return 0;
}

void message_sign_free()
{
	pthread_rwlock_destroy(&g_list_lock);

}

static void message_sign_free_list(SINGLE_LIST *plist)
{
	SINGLE_LIST_NODE *pnode;
	SIGN_NODE *pitem;
	
	while (pnode = single_list_get_from_head(plist)) {
		pitem = (SIGN_NODE*)pnode->pdata;
		free(pitem->sign_content);
		free(pitem);
	}
	single_list_free(plist);
	free(plist);
}

BOOL message_sign_refresh()
{
	DIR *dirp;
	int fd, type;
	SIGN_NODE *pitem;
	char *ptype, *pbuff;
	char temp_name[256];
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	SINGLE_LIST *plist, *ptemp_list;

	plist = malloc(sizeof(SINGLE_LIST));
	if (NULL == plist) {
		return FALSE;
	}
	dirp = opendir(g_sign_path);
	if (NULL == dirp) {
		free(plist);
		return FALSE;
	}
	single_list_init(plist);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", g_sign_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat) ||
			0 == S_ISREG(node_stat.st_mode) ||
			node_stat.st_size > MAX_SIGN_SIZE) {
			continue;
		}
		strcpy(temp_name, direntp->d_name);
		ptype = strrchr(temp_name, '.');
		if (NULL == ptype) {
			continue;
		}
		*ptype = '\0';
		ptype ++;
		if (0 == strcasecmp(ptype, "plain")) {
			type = TYPE_PLAIN;
		} else if (0 == strcasecmp(ptype, "html")) {
			type = TYPE_HTML;
		} else {
			continue;
		}
		pbuff = malloc(node_stat.st_size);
		if (NULL == pbuff) {
			continue;
		}
		fd = open(temp_path, O_RDONLY);
		if (-1 == fd) {
			free(pbuff);
			continue;
		}
		if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
			free(pbuff);
			close(fd);
			continue;
		}
		close(fd);
		pitem = (SIGN_NODE*)malloc(sizeof(SIGN_NODE));
		if (NULL == pitem) {
			free(pbuff);
			continue;
		}
		pitem->node.pdata = pitem;
		pitem->type = type;
		strncpy(pitem->charset, temp_name, sizeof(pitem->charset));
		pitem->sign_content = pbuff;
		pitem->sign_length = node_stat.st_size;
		single_list_append_as_tail(plist, &pitem->node);
	}
	closedir(dirp);
	pthread_rwlock_wrlock(&g_list_lock);
	ptemp_list = g_sign_list;
	g_sign_list = plist;
	pthread_rwlock_unlock(&g_list_lock);
	if (NULL != ptemp_list) {
		message_sign_free_list(ptemp_list);
	}
	return TRUE;
}


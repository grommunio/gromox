#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/string.h>
#include "domain_sign.h"
#include "single_list.h"
#include "str_hash.h"
#include "util.h"
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#define MAX_SIGN_SIZE		4096

#define GROWING_NUM			100

enum {
	TYPE_PLAIN,
	TYPE_HTML
};

enum{
	DOMAIN_LOAD_OK = 0,
	DOMAIN_LOAD_MEM_FAIL,
	DOMAIN_LOAD_DIR_ERROR,
	DOMAIN_LOAD_HASH_FAIL
};



typedef struct _SIGN_NODE {
	SINGLE_LIST_NODE node;
	int type;
	char charset[32];
	char *sign_content;
	int sign_length;
} SIGN_NODE;

static int g_hash_cap;
static char g_root_path[256];
static STR_HASH_TABLE *g_sign_hash;
static pthread_rwlock_t g_hash_lock;

static int domain_sign_add_domain(const char *domain);

static void domain_sign_remove_domain(const char *domain);

static void domain_sign_free_hash(STR_HASH_TABLE *phash);

static void domain_sign_free_list(SINGLE_LIST *plist);

static void domain_sign_mime(SINGLE_LIST *psign_list, MIME *pmime);

void domain_sign_init(const char *path)
{
	g_sign_hash = NULL;
	strcpy(g_root_path, path);
	pthread_rwlock_init(&g_hash_lock, NULL);
}

int domain_sign_run()
{
	DIR *dirp;
	int domain_num;
	int i, temp_len;
	char temp_domain[256];
	struct dirent *direntp;

	dirp = opendir(g_root_path);
	if (NULL == dirp) {
		printf("[domain_sign]: failed to open directory %s: %s\n",
			g_root_path, strerror(errno));
		return -1;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		domain_num ++;
	}
	g_hash_cap = domain_num + GROWING_NUM;
	g_sign_hash = str_hash_init(g_hash_cap, sizeof(SINGLE_LIST*), NULL);
	if (NULL == g_sign_hash) {
		printf("[domain_monitor]: fail to init domain hash table\n");
		return -2;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		for (i=0; i<temp_len; i++) {
			if (HX_isupper(temp_domain[i]))
				break;
		}
		if (i == temp_len) {
			domain_sign_add_domain(temp_domain);
		}
	}
	closedir(dirp);
	return 0;
}

void domain_sign_mark(const char *domain, MAIL *pmail)
{
	MIME *pmime;
	MIME *phtml;
	MIME *pplain;
	SINGLE_LIST **pplist;
	char temp_buff[1024];
	char temp_domain[256];

	
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

	strncpy(temp_domain, domain, 255);
	HX_strlower(temp_domain);
	pthread_rwlock_rdlock(&g_hash_lock);
	pplist = str_hash_query(g_sign_hash, temp_domain);
	if (NULL == pplist) {
		pthread_rwlock_unlock(&g_hash_lock);
		return;
	}
	
	if (NULL != pplain) {
		domain_sign_mime(*pplist, pplain);
	}
	if (NULL != phtml) {
		domain_sign_mime(*pplist, phtml);
	}
	pthread_rwlock_unlock(&g_hash_lock);
}
	
static void domain_sign_mime(SINGLE_LIST *psign_list, MIME *pmime)
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
	for (pnode=single_list_get_head(psign_list); pnode!=NULL;
		pnode=single_list_get_after(psign_list, pnode)) {
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
}

int domain_sign_stop()
{
	if (NULL != g_sign_hash) {
		domain_sign_free_hash(g_sign_hash);
		g_sign_hash = NULL;
	}
	return 0;
}

void domain_sign_free()
{
	pthread_rwlock_destroy(&g_hash_lock);

}

static void domain_sign_free_hash(STR_HASH_TABLE *phash)
{
	SINGLE_LIST **pplist;
	STR_HASH_ITER *iter;

	iter = str_hash_iter_init(phash);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		pplist = (SINGLE_LIST**)str_hash_iter_get_value(iter, NULL);
		domain_sign_free_list(*pplist);
	}
	str_hash_iter_free(iter);
	str_hash_free(phash);
}


static void domain_sign_free_list(SINGLE_LIST *plist)
{
	SINGLE_LIST_NODE *pnode;
	SIGN_NODE *pitem;
	
	while ((pnode = single_list_get_from_head(plist)) != NULL) {
		pitem = (SIGN_NODE*)pnode->pdata;
		free(pitem->sign_content);
		free(pitem);
	}
	single_list_free(plist);
	free(plist);
}

static int domain_sign_add_domain(const char *domain)
{
	DIR *dirp;
	int fd, type;
	SIGN_NODE *pitem;
	char *ptype, *pbuff;
	char temp_domain[256];
	char temp_name[256];
	char temp_path[256];
	struct stat node_stat;
	struct dirent *direntp;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	SINGLE_LIST *plist, **pptemp_list;

	strncpy(temp_domain, domain, 255);
	HX_strlower(temp_domain);
	snprintf(temp_path, 255, "%s/%s", g_root_path, temp_domain);

	plist = malloc(sizeof(SINGLE_LIST));
	if (NULL == plist) {
		return DOMAIN_LOAD_MEM_FAIL;
	}
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		free(plist);
		return DOMAIN_LOAD_DIR_ERROR;
	}
	single_list_init(plist);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s/%s", g_root_path,
			temp_domain, direntp->d_name);
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
	pthread_rwlock_wrlock(&g_hash_lock);
	pptemp_list = (SINGLE_LIST**)str_hash_query(g_sign_hash, temp_domain);
	if (NULL != pptemp_list) {
		domain_sign_free_list(*pptemp_list);
		str_hash_remove(g_sign_hash, temp_domain);
	}
	if (1 != str_hash_add(g_sign_hash, temp_domain, &plist)) {
		phash = str_hash_init(g_hash_cap + GROWING_NUM, sizeof(SINGLE_LIST*), NULL);
		if (NULL == phash) {
			pthread_rwlock_unlock(&g_hash_lock);
			domain_sign_free_list(plist);
			return DOMAIN_LOAD_HASH_FAIL;
		}
		iter = str_hash_iter_init(g_sign_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pptemp_list = (SINGLE_LIST**)str_hash_iter_get_value(iter, temp_domain);
			str_hash_add(phash, temp_domain, pptemp_list);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_sign_hash);
		g_sign_hash = phash;
		if (1 != str_hash_add(g_sign_hash, temp_domain, &plist)) {
			pthread_rwlock_unlock(&g_hash_lock);
			domain_sign_free_list(plist);
			return DOMAIN_LOAD_HASH_FAIL;
		}
	}
	pthread_rwlock_unlock(&g_hash_lock);
	return DOMAIN_LOAD_OK;
}

static void domain_sign_remove_domain(const char *domain)
{
	DIR *dirp;
	SINGLE_LIST **pplist, *plist;
	char temp_path[256];
	char temp_domain[256];
	struct dirent *direntp;

	plist = NULL;
	strncpy(temp_domain, domain, 255);
	HX_strlower(temp_domain);
	pthread_rwlock_wrlock(&g_hash_lock);
	pplist = (SINGLE_LIST**)str_hash_query(g_sign_hash, temp_domain);
	if (NULL != pplist) {
		plist = *pplist;
		str_hash_remove(g_sign_hash, temp_domain);
	}
	pthread_rwlock_unlock(&g_hash_lock);
	if (NULL != plist) {
		domain_sign_free_list(plist);
	}
	
	snprintf(temp_path, 255, "%s/%s", g_root_path, temp_domain);
	dirp = opendir(temp_path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s/%s", g_root_path,
			temp_domain, direntp->d_name);
		remove(temp_path);
	}
	closedir(dirp);
	snprintf(temp_path, 255, "%s/%s", g_root_path, temp_domain);
	remove(temp_path);
	
}

void domain_sign_console_talk(int argc, char **argv, char *result,
	int length)
{
	char help_string[] = "250 domain sign help information:\r\n"
				         "\t%s add <domain>\r\n"
						 "\t    --add domain sign list into system\r\n"
						 "\t%s remove <domain>\r\n"
						 "\t    --remove domain sign list from system";
	
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}

	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] = '\0';
		return;
	}

	if (3 == argc && 0 == strcmp("add", argv[1])) {
		switch (domain_sign_add_domain(argv[2])) {
		case DOMAIN_LOAD_OK:
			snprintf(result, length, "250 domain %s's sign list added OK",
				argv[2]);
			break;
		case DOMAIN_LOAD_MEM_FAIL:
			snprintf(result, length, "550 fail to allocate memory for domain",
				argv[2]);
			break;
		case DOMAIN_LOAD_DIR_ERROR:
			snprintf(result, length, "550 fail to open domain %s's sign ",
				"directory", argv[2]);
			break;
		case DOMAIN_LOAD_HASH_FAIL:
			snprintf(result, length, "550 fail to add domain %s's sign "
				"list into hash table", argv[2]);
			break;
		}
		return;
	}
	
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		domain_sign_remove_domain(argv[2]);
		snprintf(result, length, "250 domain %s's monitor list removed OK",
			argv[2]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


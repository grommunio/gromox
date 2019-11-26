#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <stdbool.h>
#include <libHX/ctype_helper.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <gromox/paths.h>
#include "util.h"
#include "list_file.h"
#include "mail_func.h"
#include "config_file.h"
#include "double_list.h"
#include <zlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#define SOCKET_TIMEOUT      300

enum {
	D_TYPE_DIR,
	D_TYPE_REG,
	D_TYPE_LNK
};

enum {
	SUCCESS = 0,
	ERROR_SOCKET,
	ERROR_EXECUTE,
};

typedef struct _AREA_ITEM {
	char type[12];
	char master[256];
	char slave[256];
	int space;
	int files;
} AREA_ITEM;

typedef struct _THREAD_NODE {
	DOUBLE_LIST_NODE node;
	pthread_t thr_id;
} THREAD_NODE;

typedef struct _CONNECTION {
	int sockd;
	SSL *ssl;
} CONNECTION;

typedef struct _DIRENT_NODE {
	DOUBLE_LIST_NODE node;
	int d_type;
	char d_name[256];
} DIRENT_NODE;

static int g_host_port;
static int g_notify_stop;
static char g_host_ip[16];
static SSL_CTX *g_ssl_ctx;
static DOUBLE_LIST g_thread_list;
static pthread_mutex_t *g_ssl_mutex_buf;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static BOOL unzip_file(const char *src_path, const char *dst_path)
{
	int fd;
	gzFile gz_fd;
	int read_len;
	char buff[256*1024];
	
	gz_fd = gzopen(src_path, "r");
	if (Z_NULL == gz_fd) {
		remove(src_path);
		return FALSE;
	}

	fd = open(dst_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		gzclose(gz_fd);
		remove(src_path);
		return FALSE;
	}

	while ((read_len = gzread(gz_fd, buff, sizeof(buff))) > 0) {
		write(fd, buff, read_len);
    }
	close(fd);
	gzclose(gz_fd);
	remove(src_path);
	return true;
}

static BOOL md5_file(const char *path, char *digest)
{
	char *pbuff;
	MD5_CTX ctx;
	int i, fd;
	struct stat node_stat;
	unsigned char md[MD5_DIGEST_LENGTH];


	if (0 != stat(path, &node_stat) ||
		0 == S_ISREG(node_stat.st_mode)) {
		return FALSE;
	}
	
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}
	
	pbuff = malloc(node_stat.st_size);
	if (NULL == pbuff) {
		return FALSE;
	}

	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		return FALSE;
	}

	close(fd);


	MD5_Init(&ctx);
	MD5_Update(&ctx, (void *)pbuff, node_stat.st_size);
	MD5_Final(md, &ctx);

	free(pbuff);
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		sprintf(digest + 2*i, "%02x", md[i]);
	}

	return TRUE;

}

static CONNECTION connect_rsyncd(const char *ip_addr, int port)
{
    int read_len;
	fd_set myset;
    CONNECTION conn;
	struct timeval tv;
    char temp_buff[1024];
	struct timeval timeout_val;
    struct sockaddr_in servaddr;


    conn.sockd = socket(AF_INET, SOCK_STREAM, 0);
	timeout_val.tv_sec = SOCKET_TIMEOUT;
	timeout_val.tv_usec = 0;
	setsockopt(conn.sockd, SOL_SOCKET, SO_RCVTIMEO, &timeout_val,
		sizeof(struct timeval));
	memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, ip_addr, &servaddr.sin_addr);
    if (0 != connect(conn.sockd, (struct sockaddr*)&servaddr,
		sizeof(servaddr))) {
        close(conn.sockd);
		conn.sockd = -1;
		conn.ssl = NULL;
        return conn;
    }

	conn.ssl = SSL_new(g_ssl_ctx);
	if (NULL == conn.ssl) {
		close(conn.sockd);
		conn.sockd = -1;
		return conn;
	}

	SSL_set_fd(conn.ssl, conn.sockd);

	if (1 != SSL_connect(conn.ssl)) {
		printf("[system]: fail to establish SSL connection with "
			"rsync server, client certificate may be error!\n");
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		return conn;
	}

	tv.tv_usec = 0;
	tv.tv_sec = SOCKET_TIMEOUT;
	FD_ZERO(&myset);
	FD_SET(conn.sockd, &myset);
	if (select(conn.sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		return conn;
	}
	

	read_len = SSL_read(conn.ssl, temp_buff, 1024);
	if (read_len <= 0) {
		SSL_free(conn.ssl);
		conn.ssl = NULL;
        close(conn.sockd);
		conn.sockd = -1;
        return conn;
	}
	temp_buff[read_len] = '\0';
	if (0 != strcasecmp(temp_buff, "OK\r\n")) {
		SSL_free(conn.ssl);
		conn.ssl = NULL;
        close(conn.sockd);
		conn.sockd = -1;
        return conn;
	}
	return conn;
}

static BOOL read_line(CONNECTION conn, char *buff, int length)
{
	int offset;
    fd_set myset;
    int read_len;
    struct timeval tv;

	offset = 0;
    while (TRUE) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(conn.sockd, &myset);
        if (select(conn.sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
            return FALSE;
        }
        read_len = SSL_read(conn.ssl, buff + offset, length - offset);
        if (read_len <= 0) {
            return FALSE;
        }
        offset += read_len;
		if ('\r' == buff[offset - 2] && '\n' == buff[offset - 1]) {
			buff[offset - 2] = '\0';
			return TRUE;
        }
		if (offset == length) {
			return FALSE;
		}
    }
}

static int remote_list(CONNECTION conn, DOUBLE_LIST *plist)
{
	int i;
	int offset;
	int last_pos;
    fd_set myset;
    int read_len;
	BOOL b_first;
    struct timeval tv;
	char buff[64*1024];
	DIRENT_NODE *pdirent;
	DOUBLE_LIST_NODE *pnode;


	if (6 != SSL_write(conn.ssl, "LIST\r\n", 6)) {
		return ERROR_SOCKET;
	}

	offset = 0;
	b_first = FALSE;
    while (TRUE) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(conn.sockd, &myset);
        if (select(conn.sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			while ((pnode = double_list_get_from_head(plist)) != NULL) {
				pdirent = (DIRENT_NODE*)pnode->pdata;
				free(pdirent);
			}
            return ERROR_SOCKET;
        }
        read_len = SSL_read(conn.ssl, buff + offset, sizeof(buff) - offset);
        if (read_len <= 0) {
			while ((pnode = double_list_get_from_head(plist)) != NULL) {
				pdirent = (DIRENT_NODE*)pnode->pdata;
				free(pdirent);
			}
            return ERROR_SOCKET;
        }
        offset += read_len;
		if (FALSE == b_first) {
			for (i=0; i<offset; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					buff[i] = '\0';
					if (0 == strcasecmp(buff, "TRUE")) {
						last_pos = i + 2;
						b_first = TRUE;
					} else if (0 == strcasecmp(buff, "FALSE")) {
						return ERROR_EXECUTE;
					} else {
						return ERROR_SOCKET;
					}
				}
			}
			if (FALSE == b_first) {
				continue;
			}
		}

		for (i=last_pos; i<offset-1; i++) {
			if ('\r' == buff[i] && '\n' == buff[i + 1]) {
				buff[i] = '\0';
			
				if (0 == strcasecmp(buff + last_pos, "END-OF-DIR")) {
					return SUCCESS;
				}
				pdirent = (DIRENT_NODE*)malloc(sizeof(DIRENT_NODE));
				if (NULL == pdirent) {
					continue;
				}
				pdirent->node.pdata = pdirent;
				if ('D' == buff[last_pos]) {
					pdirent->d_type = D_TYPE_DIR;
				} else if ('R' == buff[last_pos]) {
					pdirent->d_type = D_TYPE_REG;
				} else if ('L' == buff[last_pos]) {
					pdirent->d_type = D_TYPE_LNK;
				} else {
					free(pdirent);
					while ((pnode = double_list_get_from_head(plist)) != NULL) {
						pdirent = (DIRENT_NODE*)pnode->pdata;
						free(pdirent);
					}
					return ERROR_SOCKET;
				}

				strncpy(pdirent->d_name, buff + last_pos + 2, 256);
				double_list_append_as_tail(plist, &pdirent->node);
				last_pos = i + 2;
				i ++;
			}
		}

		memmove(buff, buff + last_pos, offset - last_pos);
		offset -= last_pos;
		last_pos = 0;
	}

}

static int remote_get(CONNECTION conn,
	const char *remote_file, const char *local_path)
{
	int i, fd;
	int offset;
	size_t length;
    fd_set myset;
    int read_len;
	BOOL b_first;
	size_t tmp_len;
    struct timeval tv;
	char buff[64*1024];
	char temp_path[256];
	char temp_path1[256];

	
	offset = snprintf(buff, 1024, "GET %s\r\n", remote_file);
	if (offset != SSL_write(conn.ssl, buff, offset)) {
		return ERROR_SOCKET;
	}

	offset = 0;
	fd = -1;
	b_first = FALSE;
    while (TRUE) {
        tv.tv_usec = 0;
        tv.tv_sec = SOCKET_TIMEOUT;
        FD_ZERO(&myset);
        FD_SET(conn.sockd, &myset);
        if (select(conn.sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			if (-1 != fd) {
				close(fd);
			}
            return ERROR_SOCKET;
        }
        read_len = SSL_read(conn.ssl, buff + offset, sizeof(buff) - offset);
        if (read_len <= 0) {
			if (-1 != fd) {
				close(fd);
			}
            return ERROR_SOCKET;
        }
        offset += read_len;

		if (FALSE == b_first) {
			for (i=0; i<offset; i++) {
				if ('\r' == buff[i] && '\n' == buff[i + 1]) {
					buff[i] = '\0';
					if (0 == strcasecmp(buff, "FALSE")) {
						return ERROR_EXECUTE;
					} else if (0 == strncasecmp(buff, "TRUE gzip ", 10)) {

						snprintf(temp_path, 256, "%s/%s.gz", local_path,
							remote_file);
						snprintf(temp_path1, 256, "%s/%s", local_path,
							remote_file);
						fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
						if (-1 == fd) {
							return ERROR_SOCKET;
						}
						b_first = TRUE;
						length = atol(buff + 10);
						tmp_len = offset - (i + 2);
						write(fd, buff + i + 2, tmp_len);
						if (tmp_len >= length) {
							close(fd);
							unzip_file(temp_path, temp_path1);
							return SUCCESS;
						}
						offset = 0;
						break;
					} else {
						return ERROR_SOCKET;
					}
				}
			}
		} else {
			write(fd, buff, offset);
			tmp_len += offset;
			offset = 0;
			if (tmp_len >= length) {
				close(fd);
				unzip_file(temp_path, temp_path1);
				return SUCCESS;
			}
		}
	}
	
}

static int remote_link(CONNECTION conn,
	const char *remote_link, char *link_buff)
{
	int offset;
    char temp_buff[1024];
	
	
	offset = snprintf(temp_buff, 1024, "LINK %s\r\n", remote_link);
	if (offset != SSL_write(conn.ssl, temp_buff, offset)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(conn, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		strncpy(link_buff, temp_buff + 5, 256);
		return SUCCESS;
	} else {
		return ERROR_EXECUTE;
	}

}

static int remote_md5(CONNECTION conn,
	const char *remote_file, char *md5_buff)
{
	int offset;
    char temp_buff[1024];
	
	
	offset = snprintf(temp_buff, 1024, "MD5 %s\r\n", remote_file);
	if (offset != SSL_write(conn.ssl, temp_buff, offset)) {
		return ERROR_SOCKET;
	}

	if (FALSE == read_line(conn, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}

	if (0 == strncasecmp(temp_buff, "TRUE ", 5)) {
		strncpy(md5_buff, temp_buff + 5, 2*MD5_DIGEST_LENGTH + 1);
		return SUCCESS;
	} else {
		return ERROR_EXECUTE;
	}

}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ssl_locking(int mode, int n, const char * file, int line)
{
	if (mode&CRYPTO_LOCK) {
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	} else {
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
	}
}

static unsigned long ssl_id()
{
	return (unsigned long)pthread_self();
}
#endif

static void remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != lstat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
		remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}



static BOOL check_format(const char *filename)
{
	char *pdot;
	const char *ptr;

	pdot = strchr(filename, '.');
	if (pdot - filename > 10 || pdot - filename < 1) {
		return FALSE;
	}
	for (ptr=filename; ptr<pdot; ptr++) {
		if (!HX_isdigit(*ptr))
			return FALSE;
	}
	ptr = pdot + 1;
	pdot = strchr(ptr, '.');
	if (pdot - ptr > 10 || pdot - ptr < 1) {
		return FALSE;
	}
	for (; ptr<pdot; ptr++) {
		if (!HX_isdigit(*ptr))
			return FALSE;
	}
	return TRUE;
}

static int remote_dir(CONNECTION conn, const char *remote_path)
{
	int offset;
    char temp_buff[1024];
	
	offset = snprintf(temp_buff, 1024, "DIR %s\r\n", remote_path);
	if (offset != SSL_write(conn.ssl, temp_buff, offset)) {
		return ERROR_SOCKET;
	}
	if (FALSE == read_line(conn, temp_buff, 1024)) {
		return ERROR_SOCKET;
	}
	if (0 == strcasecmp(temp_buff, "TRUE")) {
		return SUCCESS;
	} else {
		return ERROR_EXECUTE;
	}
}

static CONNECTION connect_dir(const char *ip_addr, int port, const char* dir)
{
	CONNECTION conn;

CONNECT_RSYNCD:
	conn = connect_rsyncd(ip_addr, port);
	if (-1 != conn.sockd) {
		switch (remote_dir(conn, dir)) {
		case SUCCESS:
			return conn;
		case ERROR_SOCKET:
			SSL_free(conn.ssl);
			close(conn.sockd);
			sleep(60);
			goto CONNECT_RSYNCD;
		case ERROR_EXECUTE:
			SSL_free(conn.ssl);
			conn.ssl = NULL;
			close(conn.sockd);
			conn.sockd = -1;
			return conn;
		}
	}
	goto CONNECT_RSYNCD;
}

static CONNECTION backup_subdir(CONNECTION conn, char *path)
{
	int len;
	DIR *dirp;
	int result;
	BOOL b_cid;
	CONNECTION conn2;
	char temp_path[256];
	char link_buff[256];
	char link_buff1[256];
	DOUBLE_LIST dir_list;
	DIRENT_NODE *pdirent;
	struct stat node_stat;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	char digest[2*MD5_DIGEST_LENGTH + 1];
	char digest1[2*MD5_DIGEST_LENGTH + 1];


	conn2 = conn;
	len = strlen(path);
	if (0 == strcmp(path + len - 4, "/cid")) {
		b_cid = TRUE;
	} else {
		b_cid = FALSE;
	}
	if (0 != stat(path, &node_stat)) {
		mkdir(path, 0777);
	} else {
		if (0 == S_ISDIR(node_stat.st_mode)) {
			remove_inode(path);
			mkdir(path, 0777);
		}
	}

	result = remote_dir(conn2, path);
	switch (result) {
	case ERROR_SOCKET:
	case ERROR_EXECUTE:
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		conn2 = connect_dir(g_host_ip, g_host_port, path);
		break;
	}

	double_list_init(&dir_list);
	result = remote_list(conn2, &dir_list);
	switch (result) {
	case ERROR_SOCKET:
	case ERROR_EXECUTE:
		SSL_free(conn2.ssl);
		conn2.ssl = NULL;
		close(conn2.sockd);
		conn2.sockd = -1;
		double_list_free(&dir_list);
		conn2 = connect_dir(g_host_ip, g_host_port, path);
		return conn2;
	}

	for (pnode=double_list_get_head(&dir_list); NULL!=pnode;
		pnode=double_list_get_after(&dir_list, pnode)) {
		pdirent = (DIRENT_NODE*)pnode->pdata;
		snprintf(temp_path, 256, "%s/%s", path, pdirent->d_name);
		switch (pdirent->d_type) {
		case D_TYPE_DIR:
			conn2 = backup_subdir(conn2, temp_path);
			if (ERROR_SOCKET == remote_dir(conn2, path)) {
				SSL_free(conn2.ssl);
				conn2.ssl = NULL;
				close(conn2.sockd);
				conn2.sockd = -1;
				conn2 = connect_dir(g_host_ip, g_host_port, path);
			}
			break;
		case D_TYPE_REG:
			if (0 == lstat(temp_path, &node_stat)) {
				if (TRUE == b_cid || TRUE == check_format(pdirent->d_name)) {
					break;
				} else {
					switch (remote_md5(conn2, pdirent->d_name, digest)) {
					case ERROR_SOCKET:
						SSL_free(conn2.ssl);
						conn2.ssl = NULL;
						close(conn2.sockd);
						conn2.sockd = -1;
						conn2 = connect_dir(g_host_ip, g_host_port, path);
						break;
					case SUCCESS:
						md5_file(temp_path, digest1);
						if (0 != strcmp(digest, digest1)) {
							remove(temp_path);
							if (ERROR_SOCKET == remote_get(conn2,
								pdirent->d_name, path)) {
								SSL_free(conn2.ssl);
								conn2.ssl = NULL;
								close(conn2.sockd);
								conn2.sockd = -1;
								conn2 = connect_dir(g_host_ip,
											g_host_port, path);
								break;

							}
						}
					}
				}
			} else {
				if (ERROR_SOCKET == remote_get(conn2, pdirent->d_name, path)) {
					SSL_free(conn2.ssl);
					conn2.ssl = NULL;
					close(conn2.sockd);
					conn2.sockd = -1;
					conn2 = connect_dir(g_host_ip, g_host_port, path);
				}
			}
			break;
		case D_TYPE_LNK:
			switch (remote_link(conn2, pdirent->d_name, link_buff)) {
			case SUCCESS:
				snprintf(temp_path, 255, "%s/%s", path, pdirent->d_name);
				if (0 != lstat(temp_path, &node_stat)) {
					symlink(link_buff, temp_path);
				} else {
					if (0 != S_ISLNK(node_stat.st_mode)) {
						memset(link_buff1, 0, 256);
						readlink(temp_path, link_buff1, 256);
						if (0 != strcmp(link_buff, link_buff1)) {
							remove(temp_path);
							symlink(link_buff, temp_path);
						}
					} else {
						remove_inode(temp_path);
						symlink(link_buff, temp_path);
					}

				}
				break;
			case ERROR_SOCKET:
				SSL_free(conn2.ssl);
				conn2.ssl = NULL;
				close(conn2.sockd);
				conn2.sockd = -1;
				conn2 = connect_dir(g_host_ip, g_host_port, path);
				break;
			}
		}
	}

	dirp = opendir(path);
	if (NULL == dirp) {
		return conn2;
	}

	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		for (pnode=double_list_get_head(&dir_list); NULL!=pnode;
			pnode=double_list_get_after(&dir_list, pnode)) {
			pdirent = (DIRENT_NODE*)pnode->pdata;
			if (0 == strcmp(pdirent->d_name, direntp->d_name)) {
				break;
			}
		}
		if (NULL == pnode) {
			snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
			remove_inode(temp_path);
		}
	}
	closedir(dirp);
	while ((pnode = double_list_get_from_head(&dir_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&dir_list);
	return conn2;
}

static void backup_dir(char *path)
{
	DIR *dirp;
	int result;
	CONNECTION conn;
	char temp_path[256];
	char link_buff[256];
	char link_buff1[256];
	DOUBLE_LIST dir_list;
	DIRENT_NODE *pdirent;
	struct stat node_stat;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	char digest[2*MD5_DIGEST_LENGTH + 1];
	char digest1[2*MD5_DIGEST_LENGTH + 1];
	
	
	if (0 != stat(path, &node_stat)) {
		mkdir(path, 0777);
	} else {
		if (0 == S_ISDIR(node_stat.st_mode)) {
			remove_inode(path);
			mkdir(path, 0777);
		}
	}

BEGIN_BACKUP:
	conn = connect_rsyncd(g_host_ip, g_host_port);

	if  (-1 == conn.sockd) {
		sleep(60);
		goto BEGIN_BACKUP;
	}

	result = remote_dir(conn, path);
	switch (result) {
	case ERROR_SOCKET:
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		goto BEGIN_BACKUP;
	case ERROR_EXECUTE:
		printf("[system]: fail to open directory %s in remote host\n", path);
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		return;
	}

	double_list_init(&dir_list);
	result = remote_list(conn, &dir_list);
	switch (result) {
	case ERROR_SOCKET:
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		double_list_free(&dir_list);
		goto BEGIN_BACKUP;
	case ERROR_EXECUTE:
		printf("[system]: fail to list directory %s in remote host\n", path);
		SSL_free(conn.ssl);
		conn.ssl = NULL;
		close(conn.sockd);
		conn.sockd = -1;
		double_list_free(&dir_list);
		return;
	}

	for (pnode=double_list_get_head(&dir_list); NULL!=pnode;
		pnode=double_list_get_after(&dir_list, pnode)) {
		pdirent = (DIRENT_NODE*)pnode->pdata;
		snprintf(temp_path, 256, "%s/%s", path, pdirent->d_name);
		
		switch (pdirent->d_type) {
		case D_TYPE_DIR:
			conn = backup_subdir(conn, temp_path);
			if (ERROR_SOCKET == remote_dir(conn, path)) {
				SSL_free(conn.ssl);
				conn.ssl = NULL;
				close(conn.sockd);
				conn.sockd = -1;
				conn = connect_dir(g_host_ip, g_host_port, path);
			}
			break;
		case D_TYPE_REG:
			if (0 == lstat(temp_path, &node_stat)) {
				switch (remote_md5(conn, pdirent->d_name, digest)) {
				case ERROR_SOCKET:
					SSL_free(conn.ssl);
					conn.ssl = NULL;
					close(conn.sockd);
					conn.sockd = -1;
					conn = connect_dir(g_host_ip, g_host_port, path);
					break;
				case SUCCESS:
					md5_file(temp_path, digest1);
					if (0 != strcmp(digest, digest1)) {
						remove(temp_path);
						if (ERROR_SOCKET == remote_get(conn,
							pdirent->d_name, path)) {
							SSL_free(conn.ssl);
							conn.ssl = NULL;
							close(conn.sockd);
							conn.sockd = -1;
							conn = connect_dir(g_host_ip, g_host_port, path);
							break;

						}
					}
				}
			} else {
				if (ERROR_SOCKET == remote_get(conn, pdirent->d_name, path)) {
					SSL_free(conn.ssl);
					conn.ssl = NULL;
					close(conn.sockd);
					conn.sockd = -1;
					conn = connect_dir(g_host_ip, g_host_port, path);
				}
			}
			break;
		case D_TYPE_LNK:
			switch(remote_link(conn, pdirent->d_name, link_buff)) {
			case SUCCESS:
				snprintf(temp_path, 255, "%s/%s", path, pdirent->d_name);
				if (0 != lstat(temp_path, &node_stat)) {
					symlink(link_buff, temp_path);
				} else {
					if (0 != S_ISLNK(node_stat.st_mode)) {
						memset(link_buff1, 0, 256);
						readlink(temp_path, link_buff1, 256);
						if (0 != strcmp(link_buff, link_buff1)) {
							remove(temp_path);
							symlink(link_buff, temp_path);
						}
					} else {
						remove_inode(temp_path);
						symlink(link_buff, temp_path);
					}

				}
				break;
			case ERROR_SOCKET:
				SSL_free(conn.ssl);
				conn.ssl = NULL;
				close(conn.sockd);
				conn.sockd = -1;
				conn = connect_dir(g_host_ip, g_host_port, path);
				break;
			}

		}
	}

	SSL_free(conn.ssl);
	conn.ssl = NULL;
	close(conn.sockd);
	conn.sockd = -1;

	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}

	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		for (pnode=double_list_get_head(&dir_list); NULL!=pnode;
			pnode=double_list_get_after(&dir_list, pnode)) {
			pdirent = (DIRENT_NODE*)pnode->pdata;
			if (0 == strcmp(pdirent->d_name, direntp->d_name)) {
				break;
			}
		}
		if (NULL == pnode) {
			snprintf(temp_path, 255, "%s/%s", path, direntp->d_name);
			remove_inode(temp_path);
		}
	}
	closedir(dirp);
	while ((pnode = double_list_get_from_head(&dir_list)) != NULL)
		free(pnode->pdata);
	double_list_free(&dir_list);
}

static void* thread_work_func(void *param)
{
	char *path;
	BOOL b_done;
	struct tm *ptm;
	time_t cur_time;
	struct tm tmp_tm;
	
	path = (char*)param;
	b_done = FALSE;
	while (FALSE == g_notify_stop) {
		time(&cur_time);
		ptm = localtime_r(&cur_time, &tmp_tm);
		if (ptm->tm_hour >= 19 || ptm->tm_hour <= 7) {
			if (FALSE == b_done) {
				backup_dir(path);
				b_done = TRUE;
			}
		} else {
			b_done = FALSE;
		}
		sleep(60);
	}
	return NULL;
}

int main(int argc, const char **argv)
{
	int i, num;
	char *str_value;
	AREA_ITEM *pitem;
	LIST_FILE *pfile;
	char ca_path[256];
	char list_path[256];
	char mysql_path[256];
	CONFIG_FILE *pconfig;
	THREAD_NODE *pthread;
	DOUBLE_LIST_NODE *pnode;
	char certificate_path[256];
	char private_key_path[256];
	char certificate_passwd[1024];

	umask(0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s role: client\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	pconfig = config_file_init2(opt_config_file, config_default_path("rsyncer.cfg"));
	if (opt_config_file != NULL && pconfig != NULL) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}
	
	str_value = config_file_get_value(pconfig, "DATA_FILE_PATH");
	if (NULL == str_value) {
		HX_strlcpy(list_path, PKGDATASADIR "/area_list.txt", sizeof(list_path));
    } else {
        snprintf(list_path, 255, "%s/area_list.txt", str_value);
    }
    printf("[system]: area list path is %s\n", list_path);

	str_value = config_file_get_value(pconfig, "MYSQL_BACKUP_PATH");
	if (NULL == str_value) {
		printf("[system]: value empty of \"MYSQL_BACKUP_PATH\"\n");
		config_file_free(pconfig);
		return 3;
	}
	strncpy(mysql_path, str_value, 256);

	str_value = config_file_get_value(pconfig, "RSYNC_HOST_IP");
	if (NULL == str_value) {
		printf("[system]: value empty of \"RSYNC_HOST_IP\"!\n");
		config_file_free(pconfig);
		return 4;
	}
	strncpy(g_host_ip, str_value, 16);
	printf("[system]: remote synchronization server host is %s\n", g_host_ip);

    str_value = config_file_get_value(pconfig, "RSYNC_HOST_PORT");
    if (NULL == str_value) {
		printf("[system]: value empty of \"RSYNC_HOST_PORT\"!\n");
		config_file_free(pconfig);
		return 5;
    }
	g_host_port = atoi(str_value);
	if (g_host_port <= 0) {
		printf("[system]: value of \"RSYNCER_HOST_PORT\" error!\n");
		config_file_free(pconfig);
		return 5;
	}

	str_value = config_file_get_value(pconfig, "CA_PATH");
	if (NULL == str_value) {
		printf("[system]: missing CA_PATH in config file\n");
		config_file_free(pconfig);
		return 5;
	}
	strncpy(ca_path, str_value, 256);
	
	str_value = config_file_get_value(pconfig, "CERTIFICATE_PATH");
	if (NULL == str_value) {
		printf("[system]: missing CERTIFICATE_PATH in config file\n");
		config_file_free(pconfig);
		return 5;
	}
	strncpy(certificate_path, str_value, 256);

	str_value = config_file_get_value(pconfig, "CERTIFICATE_PASSWD");
	if (NULL == str_value) {
		certificate_passwd[0] = '\0';
	} else {
		strncpy(certificate_passwd, str_value, 1024);
	}

	str_value = config_file_get_value(pconfig, "PRIVATE_KEY_PATH");
	if (NULL == str_value) {
		printf("[system]: missing PRIVATE_KEY_PATH in config file\n");
		config_file_free(pconfig);
		return 5;
	}
	strncpy(private_key_path, str_value, 256);
	
	config_file_free(pconfig);

	pfile = list_file_init(list_path, "%s:12%s:256%s:256%d%d");
	if (NULL == pfile) {
		printf("[system]: Failed to read area list from %s: %s\n",
			list_path, strerror(errno));
		return 5;
	}
	
	SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    g_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (NULL == g_ssl_ctx) {
        printf("[system]: fail to init ssl context\n");
		return 6;
    }

    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);

	SSL_CTX_load_verify_locations(g_ssl_ctx, ca_path, NULL);

    if ('\0' != certificate_passwd[0]) {
        SSL_CTX_set_default_passwd_cb_userdata(g_ssl_ctx, certificate_passwd);
    }

    if (SSL_CTX_use_certificate_chain_file(g_ssl_ctx, certificate_path) <= 0) {
        printf("[system]: fail to use certificate file:");
        ERR_print_errors_fp(stdout);
		SSL_CTX_free(g_ssl_ctx);
		return 6;
    }

    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, private_key_path,
        SSL_FILETYPE_PEM) <= 0) {
        printf("[system]: fail to use private key file:");
        ERR_print_errors_fp(stdout);
		SSL_CTX_free(g_ssl_ctx);
		return 6;
    }

    if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
        printf("[system]: private key does not match certificate:");
        ERR_print_errors_fp(stdout);
		SSL_CTX_free(g_ssl_ctx);
		return 6;
    }

    g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
    if (NULL == g_ssl_mutex_buf) {
        printf("[system]: fail to allocate ssl locking buffer\n");
		SSL_CTX_free(g_ssl_ctx);
		return 6;
    }

    for (i=0; i<CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
    }

    CRYPTO_set_id_callback(ssl_id);
    CRYPTO_set_locking_callback(ssl_locking);

	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);

	double_list_init(&g_thread_list);
	num = list_file_get_item_num(pfile);
	pitem = (AREA_ITEM*)list_file_get_list(pfile);
	for (i=0; i<num; i++) {
		pthread = (THREAD_NODE*)malloc(sizeof(THREAD_NODE));
		if (NULL == pthread) {
			printf("[system]: fail to allocate memory for %s\n",
				pitem[i].slave);
			continue;
		}
		pthread->node.pdata = pthread;
		if (0 != pthread_create(&pthread->thr_id, NULL, thread_work_func,
			(void*)pitem[i].slave)) {
			free(pthread);
			printf("[system]: fail to create thread for %s\n",
				pitem[i].slave);
			continue;
		}
		double_list_append_as_tail(&g_thread_list, &pthread->node);
	}

	pthread = (THREAD_NODE*)malloc(sizeof(THREAD_NODE));
	if (NULL == pthread) {
		printf("[system]: fail to allocate memory for %s\n", mysql_path);	
	} else {
		pthread->node.pdata = pthread;
		if (0 != pthread_create(&pthread->thr_id, NULL, thread_work_func,
			(void*)mysql_path)) {
			free(pthread);
			printf("[system]: fail to create thread for %s\n", mysql_path);
		} else {
			double_list_append_as_tail(&g_thread_list, &pthread->node);
		}
	}
	
	while (FALSE == g_notify_stop) {
		sleep(1);
	}
	while ((pnode = double_list_get_from_head(&g_thread_list)) != NULL) {
		pthread = (THREAD_NODE*)pnode->pdata;
		pthread_cancel(pthread->thr_id);
		free(pthread);
	}
	
	double_list_free(&g_thread_list);
	list_file_free(pfile);
	SSL_CTX_free(g_ssl_ctx);
	
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
	}
	free(g_ssl_mutex_buf);
	
	return 0;
}

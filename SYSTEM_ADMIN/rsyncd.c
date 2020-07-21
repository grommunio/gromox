#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <errno.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <gromox/defs.h>
#include "util.h"
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
#define SOCKET_TIMEOUT		300

typedef struct _CONNECTION_NODE {
	pthread_t thr_id;
	DOUBLE_LIST_NODE node;
	int sockd;
	SSL *ssl;
	int offset;
	char path[256];
	char domain[256];
	char buffer[1024];
	char line[1024];
} CONNECTION_NODE;


static BOOL g_notify_stop;
static SSL_CTX *g_ssl_ctx;
static DOUBLE_LIST g_connection_list;
static pthread_mutex_t *g_ssl_mutex_buf;
static pthread_mutex_t g_connection_lock;
static char *opt_config_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{.sh = 'c', .type = HXTYPE_STRING, .ptr = &opt_config_file, .help = "Config file to read", .htyp = "FILE"},
	{.ln = "version", .type = HXTYPE_NONE, .ptr = &opt_show_version, .help = "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void *accept_work_func(void *param);

static void *thread_work_func(void *param);

static void term_handler(int signo);

static BOOL read_mark(CONNECTION_NODE *pconnection);

static BOOL md5_file(const char *path, BOOL b_msg, char *digest);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void ssl_locking(int mode, int n, const char * file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&g_ssl_mutex_buf[n]);
	else
		pthread_mutex_unlock(&g_ssl_mutex_buf[n]);
}

static unsigned long ssl_id()
{
	return (unsigned long)pthread_self();
}
#endif

int main(int argc, const char **argv)
{
	int i;
	int optval;
	int listen_port;
	int sockd, status;
	pthread_t thr_id;
	char ca_path[256];
	CONFIG_FILE *pconfig;
	char *str_value;
	DOUBLE_LIST_NODE *pnode;
	struct sockaddr_in my_name;
	char certificate_path[256];
	char private_key_path[256];
	char certificate_passwd[1024];
	CONNECTION_NODE *pconnection;

	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s role: server\n", PROJECT_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	pconfig = config_file_init2(opt_config_file, config_default_path("rsyncd.cfg"));
	if (opt_config_file != nullptr && pconfig == nullptr) {
		printf("[system]: config_file_init %s: %s\n", opt_config_file, strerror(errno));
		return 2;
	}

	str_value = config_file_get_value(pconfig, "RSYNC_LISTEN_PORT");
	if (NULL == str_value) {
		listen_port = 44444;
		config_file_set_value(pconfig, "RSYNC_LISTEN_PORT", "44444");
	} else {
		listen_port = atoi(str_value);
		if (listen_port <= 0) {
			listen_port = 44444;
			config_file_set_value(pconfig, "RSYNC_LISTEN_PORT", "44444");
		}
	}
	printf("[system]: listen port is %d\n", listen_port);

	str_value = config_file_get_value(pconfig, "CA_PATH");
	if (NULL == str_value) {
		printf("[system]: missing CA_PATH in config file\n");
		config_file_free(pconfig);
		return 2;
	}
	strncpy(ca_path, str_value, 256);

	str_value = config_file_get_value(pconfig, "CERTIFICATE_PATH");
	if (NULL == str_value) {
		printf("[system]: missing CERTIFICATE_PATH in config file\n");
		config_file_free(pconfig);
		return 2;
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
		return 2;
	}
	strncpy(private_key_path, str_value, 256);
	config_file_free(pconfig);
	
	/* create a socket */
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) {
		printf("[system]: failed to create listen socket: %s\n", strerror(errno));
		return 3;
	}
	optval = -1;
	/* eliminates "Address already in use" error from bind */
	setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
		sizeof(int));
	
	/* socket binding */
	memset(&my_name, 0, sizeof(my_name));
	my_name.sin_family = AF_INET;
	my_name.sin_addr.s_addr = INADDR_ANY;   
	my_name.sin_port = htons(listen_port);
	
	status = bind(sockd, (struct sockaddr*)&my_name, sizeof(my_name));
	if (-1 == status) {
		printf("[system]: bind *:%u: %s\n", listen_port, strerror(errno));
        close(sockd);
		return 4;
    }
	
	status = listen(sockd, 5);

	if (-1 == status) {
		printf("[system]: fail to listen socket\n");
		close(sockd);
		return 5;
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	g_ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (NULL == g_ssl_ctx) {
		printf("[system]: fail to init ssl context\n");
		close(sockd);
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
		close(sockd);
		return 6;
	}

	if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, private_key_path,
		SSL_FILETYPE_PEM) <= 0) {
		printf("[system]: fail to use private key file:");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(g_ssl_ctx);
		close(sockd);
		return 6;
	}

	if (1 != SSL_CTX_check_private_key(g_ssl_ctx)) {
		printf("[system]: private key does not match certificate:");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(g_ssl_ctx);
		close(sockd);
		return 6;
	}
	
	g_ssl_mutex_buf = malloc(CRYPTO_num_locks()*sizeof(pthread_mutex_t));
	if (NULL == g_ssl_mutex_buf) {
		printf("[system]: fail to allocate ssl locking buffer\n");
		SSL_CTX_free(g_ssl_ctx);
		close(sockd);
		return 6;
	}

	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&g_ssl_mutex_buf[i], NULL);
	}
	
	CRYPTO_set_id_callback(ssl_id);
	CRYPTO_set_locking_callback(ssl_locking);


	pthread_mutex_init(&g_connection_lock, NULL);
	
	double_list_init(&g_connection_list);
	int ret = pthread_create(&thr_id, nullptr, accept_work_func,
	          reinterpret_cast(void *, static_cast(intptr_t, sockd)));
	if (ret != 0) {
		printf("[system]: failed to create accept thread: %s\n", strerror(ret));
		close(sockd);
		SSL_CTX_free(g_ssl_ctx);
		
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
		for (i=0; i<CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
		}
		free(g_ssl_mutex_buf);

		double_list_free(&g_connection_list);

		pthread_mutex_destroy(&g_connection_lock);
		SSL_CTX_free(g_ssl_ctx);
		close(sockd);
		return 7;
	}
	
	pthread_setname_np(thr_id, "accept");	
	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: RSYNC is now running\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}

	close(sockd);
	while ((pnode = double_list_get_from_head(&g_connection_list)) != NULL) {
		pconnection = (CONNECTION_NODE*)pnode->pdata;
		pthread_cancel(pconnection->thr_id);
		close(pconnection->sockd);
		free(pconnection);
	}

	double_list_free(&g_connection_list);

	pthread_mutex_destroy(&g_connection_lock);

	SSL_CTX_free(g_ssl_ctx);
	
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&g_ssl_mutex_buf[i]);
	}
	free(g_ssl_mutex_buf);

	return 0;
}



static void *accept_work_func(void *param)
{
	int sockd, sockd2;
	socklen_t addrlen;
	X509 *client_cert;
	X509_NAME *subjectName; 
	struct sockaddr_storage peer_name;
	CONNECTION_NODE *pconnection;	


	sockd = (int)(long)param;
	while (FALSE == g_notify_stop) {
		/* wait for an incoming connection */
        addrlen = sizeof(peer_name);
        sockd2 = accept(sockd, (struct sockaddr*)&peer_name, &addrlen);
		if (-1 == sockd2) {
			continue;
		}

		pconnection = (CONNECTION_NODE*)malloc(sizeof(CONNECTION_NODE));
		if (NULL == pconnection) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			continue;
		}

		pconnection->node.pdata = pconnection;
		pconnection->offset = 0;
		pconnection->path[0] = '\0';
		pconnection->sockd = sockd2;
		pconnection->ssl = SSL_new(g_ssl_ctx);
		if (NULL == pconnection->ssl) {
			write(sockd2, "Internal Error!\r\n", 17);
			close(sockd2);
			free(pconnection);
			continue;
		}
		SSL_set_fd(pconnection->ssl, sockd2);
		if (1 != SSL_accept(pconnection->ssl)) {
			SSL_free(pconnection->ssl);
			close(sockd2);
			free(pconnection);
			continue;
		}

		client_cert = SSL_get_peer_certificate(pconnection->ssl);
		if (NULL == client_cert) {
			SSL_free(pconnection->ssl);
			close(sockd2);
			free(pconnection);
			continue;
		}
		subjectName = X509_get_subject_name(client_cert); 
		X509_NAME_get_text_by_NID(subjectName, NID_commonName,
			pconnection->domain, sizeof(pconnection->domain));
		
		if (0 != pthread_create(&pconnection->thr_id, NULL,
			thread_work_func, (void*)pconnection)) {
			SSL_write(pconnection->ssl, "Internal Error!\r\n", 17);
			SSL_free(pconnection->ssl);
			close(sockd2);
			free(pconnection);
			continue;
		}
		pthread_setname_np(pconnection->thr_id, "client");
		pthread_mutex_lock(&g_connection_lock);
		double_list_append_as_tail(&g_connection_list, &pconnection->node);
		pthread_mutex_unlock(&g_connection_lock);

	}
	
	pthread_exit(0);

}


static void *thread_work_func(void *param)
{
	int fd;
	DIR *dirp;
	int offset;
	char *pbuff;
	gzFile gz_fd;
	char buff[256*1024];
	char temp_path[260];
	struct stat node_stat;
	struct dirent *direntp;
	CONNECTION_NODE *pconnection;


	pconnection = (CONNECTION_NODE*)param;

	SSL_write(pconnection->ssl, "OK\r\n", 4);


	while (TRUE) {
		if (FALSE == read_mark(pconnection)) {
			SSL_free(pconnection->ssl);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			pthread_detach(pthread_self());
			pthread_exit(0);
		}

		if (0 == strncasecmp(pconnection->line, "DIR ", 4) &&
			strlen(pconnection->line) > 4) {
			if (0 != stat(pconnection->line + 4, &node_stat) ||
				0 == S_ISDIR(node_stat.st_mode)) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			strcpy(pconnection->path, pconnection->line + 4);
			SSL_write(pconnection->ssl, "TRUE\r\n", 6);

		} else if (0 == strcasecmp(pconnection->line, "LIST")) {
			if ('\0' == pconnection->path[0]) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			dirp = opendir(pconnection->path);
			if (NULL == dirp) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}	
			SSL_write(pconnection->ssl, "TRUE\r\n", 6);
			offset = 0;
			while ((direntp = readdir(dirp)) != NULL) {
				if (0 == strcmp(direntp->d_name, ".") ||
					0 == strcmp(direntp->d_name, "..")) {
					continue;
				}
				snprintf(temp_path, 256, "%s/%s", pconnection->path,
					direntp->d_name);
				if (0 != lstat(temp_path, &node_stat)) {
					continue;
				}
				if (0 != S_ISDIR(node_stat.st_mode)) {
					offset += snprintf(buff + offset, sizeof(buff) - offset,
								"D %s\r\n", direntp->d_name);
				} else if (0 != S_ISREG(node_stat.st_mode)) {
					offset += snprintf(buff + offset, sizeof(buff) - offset,
								"R %s\r\n", direntp->d_name);
				} else if (0 != S_ISLNK(node_stat.st_mode)) {
					offset += snprintf(buff + offset, sizeof(buff) - offset,
								"L %s\r\n", direntp->d_name);
				}

				if (offset > sizeof(buff) - 1024) {
					SSL_write(pconnection->ssl, buff, offset);
					offset = 0;
				}
			}
			closedir(dirp);
			strcpy(buff + offset, "END-OF-DIR\r\n");
			offset += 12;
			SSL_write(pconnection->ssl, buff, offset);
		} else if (0 == strncasecmp(pconnection->line, "MD5 ", 4)) {
			snprintf(temp_path, 256, "%s/%s", pconnection->path,
				pconnection->line + 4);

			strcpy(buff, "TRUE ");
			if (FALSE == md5_file(temp_path, FALSE, buff + 5)) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
			} else {
				offset = strlen(buff);
				buff[offset] = '\r';
				offset ++;
				buff[offset] = '\n';
				offset ++;
				SSL_write(pconnection->ssl, buff, offset);
			}
		} else if(0 == strncasecmp(pconnection->line, "MD5-MSG ",8)) {
			snprintf(temp_path, 256, "%s/%s", pconnection->path,
				pconnection->line + 8);

			strcpy(buff, "TRUE ");
			if (FALSE == md5_file(temp_path, TRUE, buff + 5)) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
			} else {
				offset = strlen(buff);
				buff[offset] = '\r';
				offset ++;
				buff[offset] = '\n';
				offset ++;
				SSL_write(pconnection->ssl, buff, offset);
			}
		} else if (0 == strncasecmp(pconnection->line, "LINK ", 5)) {
			snprintf(temp_path, 256, "%s/%s", pconnection->path,
				pconnection->line + 5);
			if (0 != lstat(temp_path, &node_stat) ||
				0 == S_ISLNK(node_stat.st_mode)) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			memset(buff, 0, sizeof(buff));
			strcpy(buff, "TRUE ");
			if (readlink(temp_path, buff + 5, 256) <= 0) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
			} else {
				offset = strlen(buff);
				buff[offset] = '\r';
				offset ++;
				buff[offset] = '\n';
				offset ++;
				SSL_write(pconnection->ssl, buff, offset);
			}
		} else if (0 == strncasecmp(pconnection->line, "GET ", 4)) {
			snprintf(temp_path, 256, "%s/%s", pconnection->path,
				pconnection->line + 4);
			if (0 != stat(temp_path, &node_stat) ||
				0 == S_ISREG(node_stat.st_mode)) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size > sizeof(buff)) {
				pbuff = malloc(node_stat.st_size);
				if (NULL == pbuff) {
					close(fd);
					SSL_write(pconnection->ssl, "FALSE\r\n", 7);
					continue;
				}
			} else {
				pbuff = buff;
			}

			if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
				close(fd);
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			close(fd);
			
			strcat(temp_path, ".gz");
			gz_fd = gzopen(temp_path, "wb");
			if (Z_NULL == gz_fd) {
				close(fd);
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size != gzwrite(gz_fd, pbuff,
				node_stat.st_size)) {
				if (node_stat.st_size > sizeof(buff)) {
					free(pbuff);
				}
				gzclose(gz_fd);
				remove(temp_path);
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			if (node_stat.st_size > sizeof(buff)) {
				free(pbuff);
			}
			gzclose(gz_fd);

			if (0 != stat(temp_path, &node_stat)) {
				remove(temp_path);
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}

			if (node_stat.st_size + 128 > sizeof(buff)) {
				pbuff = malloc(node_stat.st_size + 128);
				if (NULL == pbuff) {
					remove(temp_path);
					SSL_write(pconnection->ssl, "FALSE\r\n", 7);
					continue;
				}
			} else {
				pbuff = buff;
			}

			fd = open(temp_path, O_RDONLY);
			if (-1 == fd) {
				remove(temp_path);
				if (node_stat.st_size + 128 > sizeof(buff)) {
					free(pbuff);
				}
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}

			offset = sprintf(pbuff, "TRUE gzip %llu\r\n",
			         static_cast(unsigned long long, node_stat.st_size));
			if (node_stat.st_size != read(fd, pbuff + offset,
				node_stat.st_size)) {
				close(fd);
				remove(temp_path);
				if (node_stat.st_size + 128 > sizeof(buff)) {
					free(pbuff);
				}
				SSL_write(pconnection->ssl, "FALSE\r\n", 7);
				continue;
			}
			offset += node_stat.st_size;
			close(fd);
			remove(temp_path);
			SSL_write(pconnection->ssl, pbuff, offset);
			if (node_stat.st_size + 128 > sizeof(buff)) {
				free(pbuff);
			}
			continue;
		} else if (0 == strcasecmp(pconnection->line, "PING")) {
			SSL_write(pconnection->ssl, "TRUE\r\n", 6);
		} else if (0 == strcasecmp(pconnection->line, "QUIT")) {
			SSL_write(pconnection->ssl, "BYE\r\n", 5);
			SSL_free(pconnection->ssl);
			close(pconnection->sockd);
			pthread_mutex_lock(&g_connection_lock);
			double_list_remove(&g_connection_list, &pconnection->node);
			pthread_mutex_unlock(&g_connection_lock);
			free(pconnection);
			pthread_detach(pthread_self());
			pthread_exit(0);
		} else {
			SSL_write(pconnection->ssl, "FALSE\r\n", 7);
		}

	}

	pthread_detach(pthread_self());
	pthread_exit(0);
}


static BOOL read_mark(CONNECTION_NODE *pconnection)
{
	fd_set myset;
	int i, read_len;
	struct timeval tv;

	while (TRUE) {
		tv.tv_usec = 0;
		tv.tv_sec = SOCKET_TIMEOUT;
		FD_ZERO(&myset);
		FD_SET(pconnection->sockd, &myset);
		if (select(pconnection->sockd + 1, &myset, NULL, NULL, &tv) <= 0) {
			return FALSE;
		}
		read_len = SSL_read(pconnection->ssl, pconnection->buffer +
					pconnection->offset, 1024 - pconnection->offset);
		if (read_len <= 0) {
			return FALSE;
		}
		pconnection->offset += read_len;
		for (i=0; i<pconnection->offset-1; i++) {
			if ('\r' == pconnection->buffer[i] &&
				'\n' == pconnection->buffer[i + 1]) {
				memcpy(pconnection->line, pconnection->buffer, i);
				pconnection->line[i] = '\0';
				pconnection->offset -= i + 2;
				memmove(pconnection->buffer, pconnection->buffer + i + 2,
					pconnection->offset);
				return TRUE;
			}
		}
		if (1024 == pconnection->offset) {
			return FALSE;
		}
		
	}
}

static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static BOOL md5_file(const char *path, BOOL b_msg, char *digest)
{
	int offset;
	char *pbuff;
	MD5_CTX ctx;
	int i, len, fd;
	MIME_FIELD mime_field;
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

	if (TRUE == b_msg) {
		offset = 0;
		while ((len = parse_mime_field(pbuff + offset,
		       node_stat.st_size - offset, &mime_field)) != 0) {
			if ((8 == mime_field.field_name_len &&
				0 == strncasecmp("Received", mime_field.field_name, 8)) ||
				(9 == mime_field.field_name_len &&
				0 == strncasecmp("X-Lasthop", mime_field.field_name, 9)) ||
				(18 ==mime_field.field_name_len &&
				 0 == strncasecmp("X-Penetrate-Bounce",
					mime_field.field_name, 18))) {
				offset += len;
				continue;
			}
			break;
		}

	}

	MD5_Init(&ctx);
	if (TRUE == b_msg) {
		MD5_Update(&ctx, (void*)pbuff + offset,
			node_stat.st_size - offset);
	} else {
		MD5_Update(&ctx, (void *)pbuff, node_stat.st_size);
	}
	MD5_Final(md, &ctx);

	free(pbuff);
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		sprintf(digest + 2*i, "%02x", md[i]);
	}

	return TRUE;

}

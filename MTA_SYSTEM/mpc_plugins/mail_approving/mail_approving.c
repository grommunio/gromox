#include "mail_approving.h"
#include "bounce_producer.h"
#include "mail_func.h"
#include "list_file.h"
#include "str_hash.h"
#include "double_list.h"
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <stdarg.h>


enum{
	DOMAIN_LOAD_OK = 0,
	DOMAIN_LOAD_FILE_ERROR,
	DOMAIN_LOAD_HASH_FAIL
};

typedef struct _APPROVING_DATA{
	DOUBLE_LIST_NODE	node;
	char				forward_to[256];
	char                language[32];
} APPROVING_DATA;

static char				g_root_path[256];
static int				g_growing_num;
static char             g_dm_host[256];
static int				g_hash_cap;
static STR_HASH_TABLE	*g_domain_hash;
static pthread_mutex_t  g_sequence_lock;
static pthread_rwlock_t g_table_lock;

static BOOL (*mail_approving_get_homedir)(const char*, char*);

static BOOL mail_approving_add_table(STR_HASH_TABLE *ptable,
	const char *obj, const char *dst, const char *lang);

static BOOL mail_approving_free_table(STR_HASH_TABLE *ptable);

static int mail_approving_add_domain(const char *domain);

static void mail_approving_remove_domain(const char *domain);

static int mail_approving_sequence_ID();

static void mail_approving_produce_session(const char *tag, char *session);

static BOOL mail_approving_serialize(MESSAGE_CONTEXT *pcontext,
	char *homedir, char *mess_id);

static BOOL mail_approving_activate(const char *file_name);

static void mail_approving_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...);

void mail_approving_init(const char *root_path, int growing_num,
	const char *dm_host)
{
	strcpy(g_root_path, root_path);
	g_growing_num = growing_num;
	strcpy(g_dm_host, dm_host);
	g_hash_cap = 0;
	pthread_rwlock_init(&g_table_lock, NULL);
	pthread_mutex_init(&g_sequence_lock, NULL);
	g_domain_hash = NULL;
}

/*
 *	run the module
 *	@return
 *		 0			OK
 *		<>0			fail 
 */
int mail_approving_run()
{
	DIR *dirp;
	int domain_num;
	int i, temp_len;
	char temp_domain[256];
	struct dirent *direntp;

	
	mail_approving_get_homedir = query_service("get_domain_homedir");
	if (NULL == mail_approving_get_homedir) {
		printf("[mail_approving]: fail to get "
			"\"get_domain_homedir\" service\n");
		return -1;
	}


	dirp = opendir(g_root_path);
	if (NULL == dirp) {
		printf("[mail_approving]: fail to open %s\n", g_root_path);
		return -2;
	}
	domain_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		domain_num ++;
	}
	g_hash_cap = domain_num + g_growing_num;
	g_domain_hash = str_hash_init(g_hash_cap, sizeof(STR_HASH_TABLE), NULL);
	if (NULL == g_domain_hash) {
		closedir(dirp);
		printf("[mail_approving]: fail to init domain hash table\n");
		return -3;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_domain, direntp->d_name);
		temp_len = strlen(temp_domain);
		if (temp_len <= 4 || 0 != strcasecmp(
			temp_domain + temp_len - 4, ".txt")) {
			continue;
		}
		temp_domain[temp_len - 4] = '\0';
		for (i=0; i<temp_len-4; i++) {
			if (0 != isupper(temp_domain[i])) {
				break;
			}
		}
		if (i < temp_len - 4) {
			continue;
		}
		mail_approving_add_domain(temp_domain);
	}
	closedir(dirp);
	return 0;
}

/*
 *	mail approving's hook function
 *	@param
 *		pcontext [in]			message context object pointer
 *	@return
 *		TRUE					message context is processed
 *		FALSE					message context isn't processed
 */
BOOL mail_approving_process(MESSAGE_CONTEXT *pcontext)
{
	int fd, len;
	MIME *pmime;
	BOOL b_found;
	char key[256];
	char *pdomain;
	char path[256];
	time_t cur_time;
	char mess_id[256];
	char rcpt_to[256];
	char homedir[256];
	char session[32 + 1];
	char temp_from[256];
	char temp_domain[256];
	DOUBLE_LIST *plist;
	MEM_FILE temp_file;
	APPROVING_DATA *pdata;
	struct stat node_stat;
	DOUBLE_LIST_NODE *pnode;
	STR_HASH_TABLE **pphash;
	MESSAGE_CONTEXT *pforward_context;



	if (pcontext->pcontrol->bound_type != BOUND_OUT &&
		pcontext->pcontrol->bound_type != BOUND_RELAY) {
		return FALSE;
	}

	pmime = mail_get_head(pcontext->pmail);
	if (NULL == pmime || TRUE == mime_get_field(pmime,
		"X-Approving-Mail", key, 256)) {
		return FALSE;
	}

	
	strcpy(temp_from, pcontext->pcontrol->from);
	lower_string(temp_from);
	pdomain = strchr(temp_from, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	
	pdomain ++;
	

	pforward_context = NULL;

	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	pthread_rwlock_rdlock(&g_table_lock);
	pphash = (STR_HASH_TABLE**)str_hash_query(g_domain_hash, pdomain);
	if (NULL == pphash) {
		pthread_rwlock_unlock(&g_table_lock);
		mem_file_free(&temp_file);
		return FALSE;
	}

	plist = (DOUBLE_LIST*)str_hash_query(*pphash, temp_from);
	if (NULL == plist) {
		pthread_rwlock_unlock(&g_table_lock);
		mem_file_free(&temp_file);
		return FALSE;
	}

	for (pnode=double_list_get_head(plist); NULL!=pnode;
		pnode=double_list_get_after(plist, pnode)) {
		pdata = (APPROVING_DATA*)pnode->pdata;
		mem_file_writeline(&temp_file, pdata->forward_to);		
	}
	pthread_rwlock_unlock(&g_table_lock);

	if (0 == mem_file_get_total_length(&temp_file)) {
		mem_file_free(&temp_file);
		return FALSE;
	}

	b_found = FALSE;
	while (MEM_END_OF_FILE != mem_file_readline(&temp_file, rcpt_to, 256)) {
		pforward_context = get_context();
		if (NULL == pforward_context) {
			mem_file_free(&temp_file);
			return FALSE;
		}
			
		if (FALSE == b_found) {
			if (TRUE == mail_approving_get_homedir(pdomain, homedir)) { 
				snprintf(path, 256, "%s/_approving", homedir);
				if (0 != stat(path, &node_stat)) {
					mkdir(path, 0777);
					snprintf(path, 256, "%s/_approving/todo", homedir);
					mkdir(path, 0777);
					snprintf(path, 256, "%s/_approving/done", homedir);
					mkdir(path, 0777);
					snprintf(path, 256, "%s/_approving/pending", homedir);
					mkdir(path, 0777);
					snprintf(path, 256, "%s/_approving/allow", homedir);
					mkdir(path, 0777);
					snprintf(path, 256, "%s/_approving/deny", homedir);
					mkdir(path, 0777);
				}
				time(&cur_time);
				snprintf(mess_id, 50, "%ld.%d.%s", cur_time,
					mail_approving_sequence_ID(), get_host_ID());
				b_found = TRUE;
			} else {
				put_context(pforward_context);
				continue;
			}
		}
				
		mail_approving_produce_session(rcpt_to, session);
		snprintf(path, 256, "%s/_approving/pending/%s", homedir, session);
		fd = open(path, O_CREAT|O_WRONLY|O_APPEND, 0666);
		if (-1 != fd) {
			len = snprintf(key, 256, "%s\t%s", mess_id, rcpt_to);
			write(fd, key, len);
			close(fd);
		}

		snprintf(key, 256, "http://%s/cgi/domain_approve?domain=%s&session=%s",
			g_dm_host, pdomain, session);
		bounce_producer_make(pcontext, rcpt_to, pdata->language,
			key, pforward_context->pmail);
		pforward_context->pcontrol->need_bounce = FALSE;
		sprintf(pforward_context->pcontrol->from, "sys-admin@%s",
			get_default_domain());
		mem_file_writeline(&pforward_context->pcontrol->f_rcpt_to, rcpt_to);
		throw_context(pforward_context);
	}
	
	mem_file_free(&temp_file);

	if (TRUE == b_found) {
		if (TRUE == mail_approving_serialize(pcontext, homedir, mess_id)) {
			mail_approving_log_info(pcontext, 8,
				"message %s/_approving/todo/%s is put into approving queue",
				homedir, mess_id);
			return TRUE;
		} else {
			mail_approving_log_info(pcontext, 8,
				"fail to put message into approving queue");

		}
	}
	return FALSE;
}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int mail_approving_stop()
{
	STR_HASH_ITER *iter;
	STR_HASH_TABLE **pphash;
	
	if (NULL != g_domain_hash) {
		iter = str_hash_iter_init(g_domain_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pphash = (STR_HASH_TABLE**)str_hash_iter_get_value(iter, NULL);
			mail_approving_free_table(*pphash);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_domain_hash);
		g_domain_hash = NULL;
	}
	return 0;
}

/*
 *	mail approving's destruct function
 *
 */
void mail_approving_free()
{
	g_root_path[0] = '\0';
	pthread_rwlock_destroy(&g_table_lock);
	pthread_mutex_destroy(&g_sequence_lock);
}


static int mail_approving_add_domain(const char *domain)
{
	int i, list_len;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	LIST_FILE *plist_file;
	STR_HASH_TABLE **pphash;
	STR_HASH_TABLE *ptemp_hash;
	STR_HASH_TABLE **ppitem_hash;
	int domain_len, address_len;
	char *pitem, temp_path[256];
	char temp_domain[256], temp_buff[256];
	char *str_lang, *str_obj, *str_dst;

	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	domain_len = strlen(temp_domain);
	sprintf(temp_path, "%s/%s.txt", g_root_path, temp_domain);
	/* initialize the list filter */
	plist_file = list_file_init(temp_path, "%s:256%s:256%s:32");
	if (NULL == plist_file) {
		printf("[mail_approving]: fail to open list file %s\n", temp_path);
		return DOMAIN_LOAD_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	phash = str_hash_init(list_len + 1, sizeof(DOUBLE_LIST), NULL);
	if (NULL == phash) {
		printf("[mail_approving]: fail to allocate hash map for %s\n", domain);
		list_file_free(plist_file);
		return DOMAIN_LOAD_HASH_FAIL;
	}
	for (i=0; i<list_len; i++) {
		str_obj = pitem + 544*i;
		str_dst = str_obj + 256;
		str_lang = str_dst + 256;
		lower_string(str_obj);
		address_len = strlen(str_obj);
		if (address_len <= domain_len + 1 ||
			'@' != str_obj[address_len - domain_len - 1] ||
			0 != strcmp(str_obj + address_len - domain_len, temp_domain)) {
			printf("[mail_approving]: %s is not under domain %s\n",
					str_obj, temp_domain);
			continue;
		}
			
		if (FALSE == mail_approving_add_table(phash, str_obj,
			str_dst, str_lang)) {
			printf("[mail_approving]: fail to add %s into table, it may "
				"already exist!\n", str_obj);
		}
	}
	list_file_free(plist_file);
	pthread_rwlock_wrlock(&g_table_lock);
	pphash = (STR_HASH_TABLE**)str_hash_query(g_domain_hash, temp_domain);
	if (NULL != pphash) {
		mail_approving_free_table(*pphash);
		str_hash_remove(g_domain_hash, temp_domain);
	}
	if (1 != str_hash_add(g_domain_hash, temp_domain, &phash)) {
		ptemp_hash = str_hash_init(g_hash_cap + g_growing_num,
						sizeof(STR_HASH_TABLE), NULL);
		if (NULL == ptemp_hash) {
			pthread_rwlock_unlock(&g_table_lock);
			mail_approving_free_table(phash);
			return DOMAIN_LOAD_HASH_FAIL;
		}
		iter = str_hash_iter_init(g_domain_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem_hash = (STR_HASH_TABLE**)str_hash_iter_get_value(iter,
							temp_buff);
			str_hash_add(ptemp_hash, temp_buff, ppitem_hash);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_domain_hash);
		g_domain_hash = ptemp_hash;
		g_hash_cap += g_growing_num;
		if (1 != str_hash_add(g_domain_hash, temp_domain, &phash)) {
			pthread_rwlock_unlock(&g_table_lock);
			mail_approving_free_table(phash);
			return DOMAIN_LOAD_HASH_FAIL;
		}	
	}
	pthread_rwlock_unlock(&g_table_lock);
	return DOMAIN_LOAD_OK;
}

static void mail_approving_remove_domain(const char *domain)
{
	char temp_path[256];
	char temp_domain[256];
	STR_HASH_TABLE **pphash;
	STR_HASH_TABLE *phash = NULL;

	strcpy(temp_domain, domain);
	lower_string(temp_domain);
	
	pthread_rwlock_wrlock(&g_table_lock);
	pphash = (STR_HASH_TABLE**)str_hash_query(g_domain_hash, temp_domain);
	if (NULL != pphash) {
		phash = *pphash;
		str_hash_remove(g_domain_hash, temp_domain);
	}
	pthread_rwlock_unlock(&g_table_lock);
	if (NULL != phash) {
		mail_approving_free_table(phash);
	}
	sprintf(temp_path, "%s/%s.txt", g_root_path, temp_domain);
	remove(temp_path);
}

static BOOL mail_approving_add_table(STR_HASH_TABLE *ptable,
	const char *obj, const char *dst, const char *lang)
{
	DOUBLE_LIST *plist, temp_list;
	DOUBLE_LIST_NODE *pnode;
	APPROVING_DATA *pdata;
	
	plist = str_hash_query(ptable, (char*)obj);
	if (NULL == plist) {
		double_list_init(&temp_list);
		if (str_hash_add(ptable, (char*)obj, &temp_list) != 1) {
			double_list_free(&temp_list);
			return FALSE;
		}
		plist = str_hash_query(ptable, (char*)obj);
	}
	for(pnode=double_list_get_head(plist); pnode!=NULL;
		pnode=double_list_get_after(plist, pnode)) {
		if (0 == strcasecmp(((APPROVING_DATA*)(pnode->pdata))->forward_to,
			dst)) {
			return FALSE;
		}
	}
	pdata = (APPROVING_DATA*)malloc(sizeof(APPROVING_DATA));
	if (NULL == pdata) {
		return FALSE;
	}
	pdata->node.pdata = pdata;
	strcpy(pdata->forward_to, dst);
	strcpy(pdata->language, lang);
	double_list_append_as_tail(plist, &pdata->node);
	return TRUE;
}

/*
 *	free hash table
 *	@param
 *		ptable [in]				hash table pointer
 *	@return
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL mail_approving_free_table(STR_HASH_TABLE *ptable)
{
	STR_HASH_ITER *iter;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;

	iter = str_hash_iter_init(ptable);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = (DOUBLE_LIST*)str_hash_iter_get_value(iter, NULL);
		while (pnode = double_list_get_from_head(plist)) {
			free(pnode->pdata);
		}
		double_list_free(plist);
	}
	str_hash_iter_free(iter);
	str_hash_free(ptable);
	return NULL;
}


/*
 *	console talk function
 *	@param
 *		argc				argument number
 *		argv [in]			arguments array
 *		result [out]		result buffer
 *		length				buffer length
 */
void mail_approving_console_talk(int argc, char **argv, char *result,
	int length)
{
	char *ptr;
	int fd, len;
	time_t cur_time;
	char homedir[256];
	char temp_path[256];
	char temp_path1[256];
	char temp_buff[1024];
	char temp_buff1[1024];
	char session_path[256];
	struct stat node_stat;
	char help_string[] = "250 mail approving help information:\r\n"
						 "\t%s bounce reload\r\n"
						 "\t    --reload the bounce resource list\r\n"
						 "\t%s add <domain>\r\n"
						 "\t    --add domain approving table into system\r\n"
						 "\t%s remove <domain>\r\n"
						 "\t    --remove domain approving table from system\r\n"
						 "\t%s allow <domain> <session>\r\n"
						 "\t    --allow mail to be sent\r\n"
						 "\t%s deny <domain> <session>\r\n"
						 "\t    --deny mail to be sent\r\n"
						 "\t%s activate <path>\r\n"
						 "\t    --activate the processed mail to be sent";

	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0],
			argv[0], argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}

	if (3 == argc && 0 == strcmp("bounce", argv[1]) &&
		0 == strcmp("reload", argv[2])) {
		if (TRUE == bounce_producer_refresh()) {
			snprintf(result, length, "250 bounce resource list reload OK");	
		} else {
			snprintf(result, length, "550 bounce resource list reload error");
		}
		return;
	}

	if (4 == argc && (0 == strcmp("allow", argv[1])||
		0 == strcmp("deny", argv[1]))) {
		if (FALSE == mail_approving_get_homedir(argv[2], homedir)) {
			snprintf(result, length, "550 fail to get domain directory of %s",
				argv[2]);
			return;
		}
		snprintf(temp_path, 256, "%s/_approving", homedir);
		if (0 != stat(temp_path, &node_stat)) {
			snprintf(result, length, "550 approving table of domain %s "
				"is not set", argv[2]);
			return;
		}
		snprintf(session_path, 256, "%s/_approving/pending/%s",
			homedir, argv[3]);
		if (0 != stat(session_path, &node_stat)) {
			snprintf(temp_path, 256, "%s/_approving/allow/%s",
				homedir, argv[3]);
			if (0 != stat(temp_path, &node_stat)) {
				snprintf(temp_path, 256, "%s/_approving/deny/%s",
					homedir, argv[3]);
				if (0 != stat(temp_path, &node_stat)) {
					snprintf(result, length, "550 fail to verify session");
					return;
				} else {
					snprintf(result, length, "250 mail has already "
						"been denied");
					return;
				}
			} else {
				snprintf(result, length, "250 mail has already "
					"been allowed");
				return;
			}	
		} else {
			fd = open(session_path, O_RDONLY);
			if (-1 == fd) {
				snprintf(result, length, "550 fail to open session file");
				return;
			}
				
			len = read(fd, temp_buff, 1024);
			if (len <= 0) {
				snprintf(result, length, "550 fail to read session file");
				return;	
			}

			close(fd);
			
			temp_buff[len] = '\0';
			ptr = strchr(temp_buff, '\t');
			if (NULL == ptr) {
				snprintf(result, length, "550 session file format error");
				return;
			}
			*ptr = '\0';
			snprintf(temp_path, 256, "%s/_approving/todo/%s",
				homedir, temp_buff);
			if (0 != stat(temp_path, &node_stat)) {
				snprintf(result, length, "550 mail has been processed "
					"by another one");
				return;
			}
			if (0 == strcmp(argv[1], "allow")) {
				if (TRUE == mail_approving_activate(temp_path)) {
					snprintf(temp_path, 256, "%s/_approving/allow/%s",
						homedir, argv[3]);
					rename(session_path, temp_path);
					fd = open(temp_path, O_WRONLY|O_APPEND);
					if (-1 != fd) {
						time(&cur_time);
						len = snprintf(temp_buff1, 1024, "\t%d", cur_time);
						write(fd, temp_buff1, len);
						close(fd);
					}
					snprintf(temp_path, 256, "%s/_approving/todo/%s",
						homedir, temp_buff);
					snprintf(temp_path1, 256, "%s/_approving/done/%s",
						homedir, temp_buff);
					rename(temp_path, temp_path1);
					snprintf(result, length, "250 mail is allowed");
				} else {
					snprintf(result, length, "550 fail to activate mail");
				}
			} else {
				snprintf(temp_path, 256, "%s/_approving/deny/%s",
					homedir, argv[3]);
				rename(session_path, temp_path);
				fd = open(temp_path, O_WRONLY|O_APPEND);
				if (-1 != fd) {
					time(&cur_time);
					len = snprintf(temp_buff1, 1024, "\t%d", cur_time);
					write(fd, temp_buff1, len);
					close(fd);
				}
				snprintf(temp_path, 256, "%s/_approving/todo/%s",
					homedir, temp_buff);
				snprintf(temp_path1, 256, "%s/_approving/done/%s",
					homedir, temp_buff);
				rename(temp_path, temp_path1);
				snprintf(result, length, "250 mail is denyed");
			}
			return;
		}

	}

	if (3 == argc && 0 == strcmp("activate", argv[1])) {
		if (TRUE == mail_approving_activate(argv[2])) {
			snprintf(result, length, "250 mail is activated");
		} else {
			snprintf(result, length, "550 fail to activate mail");
		}
		return;
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		switch (mail_approving_add_domain(argv[2])) {
		case DOMAIN_LOAD_OK:
			snprintf(result, length, "250 domain %s's monitor list added OK",
				argv[2]);
			break;
		case DOMAIN_LOAD_FILE_ERROR:
			snprintf(result, length, "550 fail to open domain %s's monitor "
				"list file", argv[2]);
			break;
		case DOMAIN_LOAD_HASH_FAIL:
			snprintf(result, length, "550 fail to add domain %s's monitor "
				"list into hash table", argv[2]);
			break;
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		mail_approving_remove_domain(argv[2]);
		snprintf(result, length, "250 domain %s's monitor list removed OK",
			argv[2]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}

static BOOL mail_approving_serialize(MESSAGE_CONTEXT *pcontext,
	char *homedir, char *mess_id)
{
	int	fd, len;
	char temp_rcpt[256];
	char temp_path[256];
	char temp_buff[512];

	sprintf(temp_path, "%s/_approving/todo/%s", homedir, mess_id);
	fd = open(temp_path, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (-1 == fd) {
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Queue-Id: %d\r\n",
			pcontext->pcontrol->queue_ID);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Bound-Type: %d\r\n",
			pcontext->pcontrol->bound_type);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Approving-Mail: 1\r\n");
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	len = sprintf(temp_buff, "X-Envelop-From: %s\r\n",
			pcontext->pcontrol->from);
	if (len != write(fd, temp_buff, len)) {
		close(fd);
		remove(temp_path);
		return FALSE;
	}
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		temp_rcpt, 256)) {
		len = sprintf(temp_buff, "X-Envelop-Rcpt: %s\r\n", temp_rcpt);
		if (len != write(fd, temp_buff, len)) {
			close(fd);
			remove(temp_path);
			return FALSE;
		}
	}
	if (FALSE == mail_to_file(pcontext->pmail, fd)) {
        close(fd);
        remove(temp_path);
        return FALSE;
    }
	close(fd);
	return TRUE;
}


static BOOL mail_approving_activate(const char *file_name)
{
	int i, fd;
	int rcpt_num;
	MIME *pmime;
	char *pbuff;
	char queue_buff[32];
	char temp_rcpt[256];
	char bound_buff[32];
	struct stat node_stat;
	MESSAGE_CONTEXT *pcontext;
	
	if (0 != stat(file_name, &node_stat)) {
		return FALSE;
	}
	fd = open(file_name, O_RDONLY);
	if (-1 == fd) {
		return FALSE;
	}
	pbuff = malloc(((node_stat.st_size - 1)/(64 * 1024) + 1) * 64 * 1024);
	if (NULL == pbuff) {
		close(fd);
		return FALSE;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		free(pbuff);
		close(fd);
		return FALSE;
	}
	close(fd);
	pcontext = get_context();
	if (NULL == pcontext) {
		free(pbuff);
		return FALSE;
	}
	if (FALSE == mail_retrieve_ex(pcontext->pmail, pbuff, node_stat.st_size)) {
		free(pbuff);
		put_context(pcontext);
		return FALSE;
	}
	free(pbuff);
	pmime = mail_get_head(pcontext->pmail);
	if (FALSE == mime_get_field(pmime, "X-Queue-Id", queue_buff, 32)) {
		put_context(pcontext);
		return FALSE;
	}
	pcontext->pcontrol->queue_ID = atoi(queue_buff);
	if (FALSE == mime_get_field(pmime, "X-Bound-Type", bound_buff, 32)) {
		put_context(pcontext);
		return FALSE;
	}
	pcontext->pcontrol->bound_type = atoi(bound_buff);
	if (FALSE == mime_get_field(pmime, "X-Envelop-From",
		pcontext->pcontrol->from, 256)) {
		put_context(pcontext);
		return FALSE;
	}
	rcpt_num = mime_get_field_num(pmime, "X-Envelop-Rcpt");
	for (i=0; i<rcpt_num; i++) {
		if (FALSE == mime_search_field(pmime, "X-Envelop-Rcpt", i,
			temp_rcpt, 256)) {
			put_context(pcontext);
			return FALSE;
		}
		mem_file_writeline(&pcontext->pcontrol->f_rcpt_to, temp_rcpt);
	}
	pcontext->pcontrol->need_bounce = TRUE;
	enqueue_context(pcontext);
	mail_approving_log_info(pcontext, 8, "message is activated "
		"from approving queue");
	return TRUE;
}


static void mail_approving_produce_session(const char *tag, char *session)
{
	int i, pos, mod;
	char *pitem;
	char temp_time[16];
	char temp_name[16];
	time_t cur_time;
	
	time(&cur_time);
	/* fill 'g' if length is too short */
	sprintf(temp_time, "%x", cur_time);
	if (strlen(tag) >= 16) {
		memcpy(temp_name, tag, 16);
	} else {
		memset(temp_name, '0', 16);
		memcpy(temp_name, tag, strlen(tag));
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
			session[i] = 'a' + rand()%26;
		} else {
			session[i] = temp_time[pos];
		}
	}
	session[32] = '\0';
}


static int mail_approving_sequence_ID()
{
	int temp_ID;
	static int sequence_ID = 1;

	pthread_mutex_lock(&g_sequence_lock);
	if (sequence_ID >= 0X7FFFFFFF) {
		sequence_ID = 1;
	} else {
		sequence_ID ++;
	}
	temp_ID = sequence_ID;
	pthread_mutex_unlock(&g_sequence_lock);
	return temp_ID;
}


static void mail_approving_log_info(MESSAGE_CONTEXT *pcontext, int level,
	char *format, ...)
{
    char log_buf[2048], rcpt_buff[256];
    va_list ap;

    va_start(ap, format);
    vsnprintf(log_buf, sizeof(log_buf) - 1, format, ap);
    log_buf[sizeof(log_buf) - 1] = '\0';

    mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
    while (MEM_END_OF_FILE != mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_buff, 256)) {
		log_info(level, "SMTP message queue-ID: %d, FROM: %s, "
			"TO: %s  %s", pcontext->pcontrol->queue_ID,
			pcontext->pcontrol->from, rcpt_buff, log_buf);

    }
}


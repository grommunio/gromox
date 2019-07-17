#include "mail_forwarder.h"
#include "mail_func.h"
#include "list_file.h"
#include "str_hash.h"
#include "double_list.h"
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>

#define DEF_MODE            S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

enum{
	TABLE_REFRESH_OK,
	TABLE_REFRESH_FILE_ERROR,
	TABLE_REFRESH_HASH_FAIL
};

enum{
	FORWARD_IN,
	FORWARD_OUT,
	FORWARD_ALL,
	FORWARD_INTERNAL,
	FORWARD_EXTERNAL,
	FORWARD_TOTAL
};

enum{
	ADD_OK,
	ADD_EXIST,
	ADD_FAIL
};

typedef struct _FORWARD_DATA{
	DOUBLE_LIST_NODE	node;
	int					type;
	char				forward_to[256];
} FORWARD_DATA;

static char				g_path[256];
static char				g_subject[1024];
static char				g_domain[256];
static int				g_growing_num;
static int				g_hash_cap;
static STR_HASH_TABLE	*g_hash_table;
static pthread_rwlock_t g_refresh_lock;


static int mail_forwarder_refresh();

static BOOL mail_forwarder_add_table(STR_HASH_TABLE *ptable, int type,
	const char *tag, const char *address);

static BOOL mail_forwarder_free_table(STR_HASH_TABLE *ptable);

static BOOL mail_forwarder_flush();

static int mail_forwarder_add(int type, const char *tag, const char *address);

static BOOL mail_forwarder_remove(const char *tag, const char *address);

/*
 *	mail forwarder's init function
 *	@param
 *		path [in]			indicate the list file path
 *		subject [in]		subject for forward mail
 *		domain [in]			system default domain
 *		growing_num			growing number of hash table
 */
void mail_forwarder_init(const char *path, const char *subject,
	const char *domain, int growing_num)
{
	strcpy(g_path, path);
	strcpy(g_subject, subject);
	strcpy(g_domain, domain);
	g_growing_num = growing_num;
	g_hash_cap = 0;
	pthread_rwlock_init(&g_refresh_lock, NULL);
	g_hash_table = NULL;
}

/*
 *	run the module
 *	@return
 *		 0			OK
 *		<>0			fail 
 */
int mail_forwarder_run()
{
	if (TABLE_REFRESH_OK != mail_forwarder_refresh()) {
		return -1;
	}
	return 0;

}

/*
 *	mail forwarder's hook function
 *	@param
 *		pcontext [in]			message context object pointer
 *	@return
 *		TRUE					message context is processed
 *		FALSE					message context isn't processed
 */
BOOL mail_forwarder_process(MESSAGE_CONTEXT *pcontext)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	char rcpt_to[256], origin_rcpt[256];
	char rcpt_buf[1024], tmp_buff[256];
	char date_buf[1024];
	char *pdomain, *ptr, *pdomain1;
	int length, offset, f_type;
	time_t cur_time;
	struct tm time_buff;
	FORWARD_DATA *pdata;
	MEM_FILE file_forward;
	BOOL should_forward;
	BOOL b_internal, b_external;
	MESSAGE_CONTEXT *pforward_context;
	MIME *pmime;

	if (pcontext->pcontrol->bound_type >= BOUND_SELF) {
		return FALSE;
	}
	/* first search the "from" domain */
	strcpy(tmp_buff, pcontext->pcontrol->from);
	lower_string(tmp_buff);
	pdomain = strchr(tmp_buff, '@');
	if (NULL == pdomain) {
		return FALSE;
	}
	pdomain ++;
	mem_file_init(&file_forward, pcontext->pcontrol->f_rcpt_to.allocator);
	
	pthread_rwlock_rdlock(&g_refresh_lock);
	plist = str_hash_query(g_hash_table, pdomain);
	if (NULL != plist) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			pdata = (FORWARD_DATA*)pnode->pdata;
			if (FORWARD_IN == pdata->type) {
				continue;
			} else if (FORWARD_EXTERNAL == pdata->type ||
				FORWARD_INTERNAL == pdata->type) {
				b_internal = FALSE;
				b_external = FALSE;
				mem_file_seek(&pcontext->pcontrol->f_rcpt_to,
					MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
				while (MEM_END_OF_FILE != mem_file_readline(
					&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256)) {
					pdomain1 = strchr(rcpt_to, '@');
					if (NULL == pdomain1) {
						continue;
					}
					pdomain1 ++;
					if (0 != strcasecmp(pdomain1, pdomain)) {
						b_external = TRUE;
					} else {
						b_internal = TRUE;
					}
				}
				if ((TRUE == b_internal && FORWARD_INTERNAL == pdata->type) ||
					(TRUE == b_external && FORWARD_EXTERNAL == pdata->type)) {
					mem_file_writeline(&file_forward, pdata->forward_to);
				}
			} else {
				mem_file_writeline(&file_forward, pdata->forward_to);
			}
		}
	}
	plist = str_hash_query(g_hash_table, tmp_buff);
	if (NULL != plist) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			pdata = (FORWARD_DATA*)pnode->pdata;
			if (FORWARD_IN != pdata->type) {
				mem_file_writeline(&file_forward, pdata->forward_to);
			}
		}
	}
	pthread_rwlock_unlock(&g_refresh_lock);

	/* search every recipient and check if they have forwarder */
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		rcpt_to, 256)) {
		lower_string(rcpt_to);
		pdomain1 = strchr(rcpt_to, '@');
		if (NULL == pdomain1) {
			continue;
		}
		pdomain1 ++;
		pthread_rwlock_rdlock(&g_refresh_lock);
		plist = str_hash_query(g_hash_table, pdomain1);
		if (NULL != plist) {
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				pdata = (FORWARD_DATA*)pnode->pdata;
				if (FORWARD_ALL == pdata->type ||
					FORWARD_IN == pdata->type ||
					(FORWARD_EXTERNAL == pdata->type &&
					0 != strcasecmp(pdomain, pdomain1))) {
					mem_file_writeline(&file_forward, pdata->forward_to);
				}
			}
		}
		plist = str_hash_query(g_hash_table, rcpt_to);
		if (NULL != plist) {
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				pdata = (FORWARD_DATA*)pnode->pdata;
				if (FORWARD_OUT != pdata->type) {
					mem_file_writeline(&file_forward, pdata->forward_to);
				}
			}
		}
		pthread_rwlock_unlock(&g_refresh_lock);
	}
	/* if there's no forwarder, return immediately */
	if (mem_file_get_total_length(&file_forward) == 0) {
		mem_file_free(&file_forward);
		return FALSE;
	}
	pforward_context = get_context();
	if (NULL == pforward_context) {
		mem_file_free(&file_forward);
		return FALSE;
	}
	/* merge the replicate forwarder */
	while (MEM_END_OF_FILE != mem_file_readline(&file_forward, rcpt_to, 256)) {
		if (strcasecmp(rcpt_to, tmp_buff) == 0) {
			continue;
		}
		should_forward = TRUE;
		mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
			MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_readline(
			&pcontext->pcontrol->f_rcpt_to, origin_rcpt, 256)) {
			if (strcasecmp(origin_rcpt, rcpt_to) == 0) {
				should_forward = FALSE;
				break;
			}
		}
		if (FALSE == should_forward) {
			continue;
		}
		mem_file_seek(&pforward_context->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR,
			0, MEM_FILE_SEEK_BEGIN);
		while (MEM_END_OF_FILE != mem_file_readline(
			&pforward_context->pcontrol->f_rcpt_to, origin_rcpt, 256)) {
			if (strcasecmp(origin_rcpt, rcpt_to) == 0) {
				should_forward = FALSE;
				break;
			}
		}
		if (FALSE == should_forward) {
			continue;
		}
		mem_file_writeline(&pforward_context->pcontrol->f_rcpt_to, rcpt_to);
	}

	if (mem_file_get_total_length(&pforward_context->pcontrol->f_rcpt_to)==0) {
		mem_file_free(&file_forward);
		put_context(pforward_context);
		return FALSE;
	}
	/* make rcpts buffer */
	offset = 0;
	mem_file_seek(&pcontext->pcontrol->f_rcpt_to, MEM_FILE_READ_PTR, 0,
		MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != (length = mem_file_readline(
		&pcontext->pcontrol->f_rcpt_to, rcpt_to, 256))) {
		offset += snprintf(rcpt_buf + offset, 1024 - offset, "<%s>, ", rcpt_to);
		if (offset >= 1024) {
			offset = 1023;
			break;
		}
	}
	rcpt_buf[offset] = '\0';

	sprintf(pforward_context->pcontrol->from, "forward@%s", g_domain);
	pforward_context->pcontrol->need_bounce = FALSE;
	pmime = mail_add_head(pforward_context->pmail);
	if (NULL == pmime) {
		mem_file_free(&file_forward);
		put_context(pforward_context);
		return FALSE;
	}
	mime_set_content_type(pmime, "message/rfc822");
	mime_set_field(pmime, "Received", "from unknown (helo localhost) "
			        "(unkown@127.0.0.1)\r\n\tby herculiz with SMTP");
	mime_set_field(pmime, "From", pcontext->pcontrol->from);
	mime_set_field(pmime, "To", rcpt_buf);
	mime_set_field(pmime, "Subject", g_subject);
	time(&cur_time);
	strftime(date_buf, 128, "%a, %d %b %Y %H:%M:%S %z", 
		localtime_r(&cur_time, &time_buff));
	mime_set_field(pmime, "Date", date_buf);
	mime_write_mail(pmime, pcontext->pmail);
	throw_context(pforward_context);
	mem_file_free(&file_forward);
	return FALSE;
}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int mail_forwarder_stop()
{
	if (NULL != g_hash_table) {
		mail_forwarder_free(g_hash_table);
	}
	return 0;
}

/*
 *	mail forwarder's destruct function
 *
 */
void mail_forwarder_free()
{
	g_path[0] = '\0';
	g_subject[0] = '\0';
	g_domain[0] = '\0';
	pthread_rwlock_destroy(&g_refresh_lock);
}

/*
 *	reload the forward list table
 *	@retrun
 *		TABLE_REFRESH_FILE_ERROR		file error, can not be opened
 *		TABLE_REFRESH_HASH_FAIL			fail to create hash table
 *		TABLE_REFRESH_OK				OK
 */
static int mail_forwarder_refresh()
{
	STR_HASH_TABLE *phash = NULL;
	int i, list_len;
	int hash_cap, type;
	LIST_FILE *plist_file;
	char *pitem;
	char *str_type, *str_tag, *str_value;
	BOOL should_add;

	/* initialize the list filter */
	plist_file = list_file_init(g_path, "%s:16%s:256:%s:256");
	if (NULL == plist_file) {
		printf("[mail_forwarder]: fail to open list file\n");
		return TABLE_REFRESH_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	hash_cap = list_len + g_growing_num;
	phash = str_hash_init(hash_cap, sizeof(DOUBLE_LIST), NULL);
	if (NULL == phash) {
		printf("[mail_forwarder]: fail to allocate hash map");
		list_file_free(plist_file);
		return TABLE_REFRESH_HASH_FAIL;
	}
	for (i=0; i<list_len; i++) {
		str_type = pitem + 528*i;
		str_tag = str_type + 16;
		str_value = str_tag + 256;
		should_add = TRUE;
		if (0 == strcasecmp("F_IN", str_type)) {
			type = FORWARD_IN;
			should_add = TRUE;
		} else if (0 == strcasecmp("F_OUT", str_type)) {
			type = FORWARD_OUT;
			should_add = TRUE;
		} else if (0 == strcasecmp("F_ALL", str_type)) {
			type = FORWARD_ALL;
			should_add = TRUE;
		} else if (0 == strcasecmp("F_INTERNAL", str_type)) {
			if (NULL != strchr(str_tag, '@')) {
				printf("[mail_forwarder]: only domain can use F_INTERNAL in "
					"item %d\n", i + 1);
				should_add = FALSE;
			} else {
				type = FORWARD_INTERNAL;
				should_add = TRUE;
			}
		} else if (0 == strcasecmp("F_EXTERNAL", str_type)) {
			if (NULL != strchr(str_tag, '@')) {
				printf("[mail_forwarder]: only domain can use F_EXTERNAL in "
					"item %d\n", i + 1);
				should_add = FALSE;
			} else {
				type = FORWARD_EXTERNAL;
				should_add = TRUE;
			}
		} else {
			printf("[mail_forwarder]: type error in item %d, only can be one "
				"of \"F_IN\", \"F_OUT\", \"F_ALL\", \"F_INTERNAL\", "
				"\"F_EXTERNAL\"\n", i + 1);
			should_add = FALSE;
		}
		if (TRUE == should_add) {
			lower_string(str_tag);
			if (FALSE == mail_forwarder_add_table(phash, type, str_tag, 
				str_value)) {
				printf("[mail_forwarder]: fail to add %s into table, it may "
					"already exist!\n", str_tag);
			}
		}
	}
	list_file_free(plist_file);

	pthread_rwlock_wrlock(&g_refresh_lock);
	if (NULL != g_hash_table) {
		mail_forwarder_free_table(g_hash_table);
	}
	g_hash_table = phash;
	pthread_rwlock_unlock(&g_refresh_lock);

	return TABLE_REFRESH_OK;

}

/*
 *	add list into hash table
 *	@param
 *		ptable [in]				hash table object pointer
 *		tag [in]				tag string, can be domain or mail address
 *		plist [in]				list for forward-to address
 *	@return
 *		TRUE					OK
 *		FALSE					fail
 */
static BOOL mail_forwarder_add_table(STR_HASH_TABLE *ptable, int type,
	const char *tag, const char *address)
{
	DOUBLE_LIST *plist, temp_list;
	DOUBLE_LIST_NODE *pnode;
	FORWARD_DATA *pdata;
	
	plist = str_hash_query(ptable, (char*)tag);
	if (NULL == plist) {
		double_list_init(&temp_list);
		if (str_hash_add(ptable, (char*)tag, &temp_list) != 1) {
			double_list_free(&temp_list);
			return FALSE;
		}
		plist = str_hash_query(ptable, (char*)tag);
	}
	for(pnode=double_list_get_head(plist); pnode!=NULL;
		pnode=double_list_get_after(plist, pnode)) {
		if (0 == strcasecmp(((FORWARD_DATA*)(pnode->pdata))->forward_to,
			address)) {
			return FALSE;
		}
	}
	pdata = (FORWARD_DATA*)malloc(sizeof(FORWARD_DATA));
	if (NULL == pdata) {
		return FALSE;
	}
	pdata->node.pdata = pdata;
	pdata->type = type;
	strcpy(pdata->forward_to, address);
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
static BOOL mail_forwarder_free_table(STR_HASH_TABLE *ptable)
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
}

static int mail_forwarder_add(int type, const char *tag, const char *address)
{
	char tmp_buff[256];
	char tmp_line[1024];
	int fd, string_len, hash_cap;
	DOUBLE_LIST *plist, temp_list;
	DOUBLE_LIST_NODE *pnode;
	FORWARD_DATA *pdata;
	STR_HASH_ITER *iter;
	STR_HASH_TABLE *phash;
	
	strcpy(tmp_buff, tag);
	lower_string(tmp_buff);
	switch (type) {
	case FORWARD_IN:
		string_len = sprintf(tmp_line, "F_IN\t%s\t%s\n", tmp_buff, address);
		break;
	case FORWARD_OUT:
		string_len = sprintf(tmp_line, "F_OUT\t%s\t%s\n", tmp_buff, address);
		break;
	case FORWARD_ALL:
		string_len = sprintf(tmp_line, "F_ALL\t%s\t%s\n", tmp_buff, address);
		break;
	case FORWARD_INTERNAL:
		string_len = sprintf(tmp_line, "F_INTERNAL\t%s\t%s\n", tmp_buff,
			address);
		break;
	case FORWARD_EXTERNAL:
		string_len = sprintf(tmp_line, "F_EXTERNAL\t%s\t%s\n", tmp_buff,
			address);
		break;
	}
	pthread_rwlock_wrlock(&g_refresh_lock);
	plist = str_hash_query(g_hash_table, tmp_buff);
	if (NULL != plist) {
		for(pnode=double_list_get_head(plist); pnode!=NULL;
			pnode=double_list_get_after(plist, pnode)) {
			if (0 == strcasecmp(((FORWARD_DATA*)(pnode->pdata))->forward_to,
				address)) {
				pthread_rwlock_unlock(&g_refresh_lock);
				return ADD_EXIST;
			}
		}
	} else {
		double_list_init(&temp_list);
		if (str_hash_add(g_hash_table, tmp_buff, &temp_list) != 1) {
			hash_cap = g_hash_cap + g_growing_num;
			phash = str_hash_init(hash_cap, sizeof(DOUBLE_LIST), NULL);
			if (NULL == phash) {
				pthread_rwlock_unlock(&g_refresh_lock);
				double_list_free(&temp_list);
				return ADD_FAIL;
			}
			iter = str_hash_iter_init(g_hash_table);
			for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
				str_hash_iter_forward(iter)) {
				plist = str_hash_iter_get_value(iter, tmp_line);
				str_hash_add(phash, tmp_line, plist);
			}
			str_hash_iter_free(iter);
			str_hash_free(g_hash_table);
			g_hash_table = phash;
			g_hash_cap = hash_cap;
			if (str_hash_add(g_hash_table, tmp_buff, &temp_list) != 1) {
				pthread_rwlock_unlock(&g_refresh_lock);
				double_list_free(&temp_list);
				return ADD_FAIL;
			}
		}
		plist = str_hash_query(g_hash_table, tmp_buff);
	}
	fd = open(g_path, O_APPEND|O_WRONLY);
	if (-1 == fd) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return ADD_FAIL;
	}
	if (string_len != write(fd, tmp_line, string_len)) {
		pthread_rwlock_unlock(&g_refresh_lock);
		close(fd);
		return ADD_FAIL;
	}
	close(fd);
	pdata = (FORWARD_DATA*)malloc(sizeof(FORWARD_DATA));
	if (NULL == pdata) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return ADD_FAIL;
	}
	pdata->node.pdata = pdata;
	pdata->type = type;
	strcpy(pdata->forward_to, address);
	double_list_append_as_tail(plist, &pdata->node);
	pthread_rwlock_unlock(&g_refresh_lock);
	return ADD_OK;
}

static BOOL mail_forwarder_remove(const char *tag, const char *address)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	FORWARD_DATA *pdata;
	char tmp_buff[256];

	strcpy(tmp_buff, tag);
	lower_string(tmp_buff);
	/* check first if the string is in hash table */
	pthread_rwlock_wrlock(&g_refresh_lock);
	plist = str_hash_query(g_hash_table, tmp_buff);
	if (NULL == plist) {
		pthread_rwlock_unlock(&g_refresh_lock);
		return TRUE;
	}
	for (pnode=double_list_get_head(plist); pnode!=NULL;
		pnode=double_list_get_after(plist, pnode)) {
		if (0 == strcasecmp(((FORWARD_DATA*)(pnode->pdata))->forward_to,
			address)) {
			break;	
		}
	}
	if (NULL != pnode) {
		double_list_remove(plist, pnode);
		free(pnode->pdata);
		if (0 == double_list_get_nodes_num(plist)) {
			str_hash_remove(g_hash_table, tmp_buff);
			double_list_free(plist);
		}
	}
	mail_forwarder_flush();
	pthread_rwlock_unlock(&g_refresh_lock);
	return TRUE;
}

static BOOL mail_forwarder_flush()
{
	int i, j, fd;
	int string_len;
	char tmp_buff[256];
	char tmp_line[1024];
	FORWARD_DATA *pdata;
	STR_HASH_ITER *iter;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;

	fd = open(g_path, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
	if (-1 == fd) {
		return FALSE;
	}
	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); FALSE == str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = str_hash_iter_get_value(iter, tmp_buff);
		for (pnode=double_list_get_head(plist); pnode!=NULL;
			pnode=double_list_get_after(plist, pnode)) {
			pdata = (FORWARD_DATA*)pnode->pdata;
			switch (pdata->type) {
			case FORWARD_IN:
				string_len = sprintf(tmp_line, "F_IN\t%s\t%s\n", tmp_buff,
							pdata->forward_to);
				break;
			case FORWARD_OUT:
				string_len = sprintf(tmp_line, "F_OUT\t%s\t%s\n", tmp_buff,
							pdata->forward_to);
				break;
			case FORWARD_ALL:
				string_len = sprintf(tmp_line, "F_ALL\t%s\t%s\n", tmp_buff,
							pdata->forward_to);
				break;
			case FORWARD_INTERNAL:
				string_len = sprintf(tmp_line, "F_INTERNAL\t%s\t%s\n",
							tmp_buff, pdata->forward_to);
				break;
			case FORWARD_EXTERNAL:
				string_len = sprintf(tmp_line, "F_EXTERNAL\t%s\t%s\n",
							tmp_buff, pdata->forward_to);
				break;
			}
			write(fd, tmp_line, string_len);
		}
	}
	str_hash_iter_free(iter);
	close(fd);
	return TRUE;
}


/*
 *	console talk function
 *	@param
 *		argc				argument number
 *		argv [in]			arguments array
 *		result [out]		result buffer
 *		length				buffer length
 */
void mail_forwarder_console_talk(int argc, char **argv, char *result,
	int length)
{
	int type;
	char tmp_buff[16];
	char help_string[] = "250 mail forwarder help information:\r\n"
						 "\t%s reload\r\n"
						 "\t    --reload the forward table from file\r\n"
						 "\t%s add IN|OUT|ALL|INTERNAL|EXTERNAL <tag> <address>\r\n"
						 "\t    --add item into forward list\r\n"
						 "\t%s remove <tag> <address>\r\n"
						 "\t    --remove one item from forward list";
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (2 == argc && 0 == strcmp(argv[1], "reload")) {
		switch (mail_forwarder_refresh()) {
		case TABLE_REFRESH_OK:
			strncpy(result, "250 forward table reload OK", length);
			return;
		case TABLE_REFRESH_FILE_ERROR:
			strncpy(result, "550 can not open forward list file", length);
			return;
		case TABLE_REFRESH_HASH_FAIL:
			strncpy(result, "550 forward hash table fail", length);
			return;
		}
		return;
	}
	if (5 == argc && 0 == strcmp("add", argv[1])) {
		if (0 == strcasecmp("IN", argv[2])) {
			type = FORWARD_IN;
		} else if (0 == strcasecmp("OUT", argv[2])) {
			type = FORWARD_OUT;
		} else if (0 == strcasecmp("ALL", argv[2])) {
			type = FORWARD_ALL;
		} else if (0 == strcasecmp("INTERNAL", argv[2])) {
			type = FORWARD_INTERNAL;
		} else if (0 == strcasecmp("EXTERNAL", argv[2])) {
			type = FORWARD_EXTERNAL;
		} else {
			snprintf(result, length, "550 %s can only be one of IN, OUT, ALL, "
				"INTERNAL or EXTERNAL", argv[2]);
			return;
		}
		if (FORWARD_EXTERNAL == type || FORWARD_INTERNAL == type) {
			if (NULL != strchr(argv[3], '@')) {
				strncpy(result, "550 INTERNAL or EXTERNAL can only be added "
					"with domain", length);
				return;
			}
		}
		if (NULL == strchr(argv[4], '@')) {
			snprintf(result, length, "550 %s is not email address", argv[4]);
			return;
		}
		switch (mail_forwarder_add(type, argv[3], argv[4])) {
		case ADD_EXIST:
			snprintf(result, length, "550 %s already exists in forward table",
				argv[4]);
			return;
		case ADD_FAIL:
			strncpy(result, "550 fail to add item into table", length);
			return;
		case ADD_OK:
			strncpy(result, "250 add item OK", length);
			return;
		}
	}
	if (4 == argc && 0 == strcmp("remove", argv[1])) {
		if (FALSE == mail_forwarder_remove(argv[2], argv[3])) {
			strncpy(result, "550 fail to remove item", length);
		} else {
			strncpy(result, "250 remove item OK", length);
		}
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


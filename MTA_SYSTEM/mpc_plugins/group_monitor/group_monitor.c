#include "group_monitor.h"
#include "hook_common.h"
#include "mail_func.h"
#include "list_file.h"
#include "str_hash.h"
#include "util.h"
#include "double_list.h"
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>


enum{
	GROUP_LOAD_OK = 0,
	GROUP_LOAD_NAME_ERROR,
	GROUP_LOAD_FILE_ERROR,
	GROUP_LOAD_HASH_FAIL,
	GROUP_LOAD_DOMAIN_ERROR
};

enum{
	FORWARD_IN,
	FORWARD_OUT,
	FORWARD_ALL
};

typedef struct _FORWARD_DATA{
	DOUBLE_LIST_NODE	node;
	int					type;
	char				forward_to[256];
} FORWARD_DATA;

static char				g_root_path[256];
static char				g_subject[1024];
static int				g_growing_num;
static int				g_hash_cap;
static STR_HASH_TABLE	*g_group_hash;
static pthread_rwlock_t g_table_lock;

static BOOL (*monitor_domains_check)(const char*);

static BOOL (*monitor_domains_add)(const char*);

static BOOL (*monitor_domains_remove)(const char*);

static BOOL (*get_group_name)(const char *address, char *group);

static BOOL group_monitor_add_table(STR_HASH_TABLE *ptable, int type,
	const char *tag, const char *address);

static BOOL group_monitor_free_table(STR_HASH_TABLE *ptable);

static int group_monitor_add_group(const char *group);

static void group_monitor_remove_group(const char *group);

static void group_monitor_forward(const char *group, STR_HASH_TABLE *phash,
	const char *from, MEM_FILE *fp_rcpt_to, MAIL *pmail,
	MESSAGE_CONTEXT *pforward_context);

/*
 *	mail forwarder's init function
 *	@param
 *		root_path [in]		indicate the list file path
 *		subject [in]		subject for forward mail
 *		growing_num			growing number of hash table
 */
void group_monitor_init(const char *root_path, const char *subject,
	int growing_num)
{
	strcpy(g_root_path, root_path);
	strcpy(g_subject, subject);
	g_growing_num = growing_num;
	g_hash_cap = 0;
	pthread_rwlock_init(&g_table_lock, NULL);
	g_group_hash = NULL;
}

/*
 *	run the module
 *	@return
 *		 0			OK
 *		<>0			fail 
 */
int group_monitor_run()
{
	DIR *dirp;
	int group_num;
	int i, temp_len;
	char temp_group[256];
	struct dirent *direntp;

	monitor_domains_check = query_service("monitor_domains_check");
	if (NULL == monitor_domains_check) {
		printf("[group_monitor]: fail to get \"monitor_domains_check\" "
			"service\n");
		return -1;
	}
	
	monitor_domains_add = query_service("monitor_domains_add");
	if (NULL == monitor_domains_add) {
		printf("[group_monitor]: fail to get \"monitor_domains_add\" "
			"service\n");
		return -2;
	}
	
	monitor_domains_remove = query_service("monitor_domains_remove");
	if (NULL == monitor_domains_remove) {
		printf("[group_monitor]: fail to get \"monitor_domains_remove\" "
			"service\n");
		return -3;
	}
	
	get_group_name = query_service("get_user_groupname");
	if (NULL == get_group_name) {
		printf("[group_monitor]: fail to get \"get_group_name\" service\n");
		return -4;
	}
	
	dirp = opendir(g_root_path);
	if (NULL == dirp) {
		printf("[group_monitor]: fail to open %s\n", g_root_path);
		return -5;
	}
	group_num = 0;
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		group_num ++;
	}
	g_hash_cap = group_num + g_growing_num;
	g_group_hash = str_hash_init(g_hash_cap, sizeof(STR_HASH_TABLE), NULL);
	if (NULL == g_group_hash) {
		closedir(dirp);
		printf("[group_monitor]: fail to init group hash table\n");
		return -6;
	}
	seekdir(dirp, 0);
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		strcpy(temp_group, direntp->d_name);
		temp_len = strlen(temp_group);
		if (temp_len <= 4 || 0 != strcasecmp(
			temp_group + temp_len - 4, ".txt")) {
			continue;
		}
		temp_group[temp_len - 4] = '\0';
		for (i=0; i<temp_len-4; i++) {
			if (0 != isupper(temp_group[i])) {
				break;
			}
		}
		if (i < temp_len - 4) {
			continue;
		}
		group_monitor_add_group(temp_group);
	}
	closedir(dirp);
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
BOOL group_monitor_process(MESSAGE_CONTEXT *pcontext)
{
	BOOL b_found;
	char *pdomain;
	char temp_from[256];
	char temp_rcpt[256];
	char temp_group[256];
	char temp_group1[256];
	STR_HASH_TABLE **pphash;
	MEM_FILE f_rcpt_to;
	MEM_FILE temp_file;
	MESSAGE_CONTEXT *pforward_context;

	
	if (pcontext->pcontrol->bound_type >= BOUND_SELF) {
		return FALSE;
	}
	

	mem_file_init(&f_rcpt_to, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_init(&temp_file, pcontext->pcontrol->f_rcpt_to.allocator);
	mem_file_copy(&pcontext->pcontrol->f_rcpt_to, &f_rcpt_to);
	strcpy(temp_from, pcontext->pcontrol->from);
	lower_string(temp_from);
	pdomain = strchr(temp_from, '@');
	if (NULL != pdomain) {
		pdomain ++;
		/* check if the domain is in monitor domains table */
		if (TRUE == monitor_domains_check(pdomain)) {
			/* get the group name of the address */
			if (TRUE == get_group_name(temp_from, temp_group) &&
				'\0' != temp_group[0]) {
				mem_file_writeline(&temp_file, temp_group);
				lower_string(temp_group);
				pforward_context = NULL;
				pthread_rwlock_rdlock(&g_table_lock);
				pphash = (STR_HASH_TABLE**)str_hash_query(g_group_hash,
							temp_group);
				if (NULL != pphash) {
					pforward_context = get_context();
					if (NULL != pforward_context) {
						group_monitor_forward(temp_group, *pphash, temp_from,
							&f_rcpt_to, pcontext->pmail, pforward_context);
					}
				}
				pthread_rwlock_unlock(&g_table_lock);
				if (NULL != pforward_context) {
					if (0 != mem_file_get_total_length(
						&pforward_context->pcontrol->f_rcpt_to)) {
						throw_context(pforward_context);
					} else {
						put_context(pforward_context);
					}
				}
			}
		}
	}
	while (MEM_END_OF_FILE != mem_file_readline(&pcontext->pcontrol->f_rcpt_to,
		temp_rcpt, 256)) {
		pdomain = strchr(temp_rcpt, '@');
		if (NULL != pdomain) {
			pdomain ++;
			/* check if the domain is in monitor domains table */
			if (TRUE == monitor_domains_check(pdomain)) {
				/* get the group name of the address */
				if (TRUE == get_group_name(temp_rcpt, temp_group) &&
					'\0' != temp_group[0]) {
					b_found = FALSE;
					mem_file_seek(&temp_file, MEM_FILE_READ_PTR, 0,
						MEM_FILE_SEEK_BEGIN);
					while (MEM_END_OF_FILE != mem_file_readline(&temp_file,
						temp_group1, 256)) {
						if (0 == strcasecmp(temp_group, temp_group1)) {
							b_found = TRUE;
							break;
						}
					}
					if (TRUE == b_found) {
						continue;
					} else {
						mem_file_writeline(&temp_file, temp_group);
					}
					lower_string(temp_group);
					pforward_context = NULL;
					pthread_rwlock_rdlock(&g_table_lock);
					pphash = (STR_HASH_TABLE**)str_hash_query(g_group_hash,
								temp_group);
					if (NULL != pphash) {
						pforward_context = get_context();
						if (NULL != pforward_context) {
							group_monitor_forward(temp_group, *pphash,
								temp_from, &f_rcpt_to, pcontext->pmail,
								pforward_context);
						}
					}
					pthread_rwlock_unlock(&g_table_lock);
					if (NULL != pforward_context) {
						if (0 != mem_file_get_total_length(
							&pforward_context->pcontrol->f_rcpt_to)) {
							throw_context(pforward_context);
						} else {
							put_context(pforward_context);
						}
					}
				}
			}
		}
	}
	mem_file_free(&f_rcpt_to);
	mem_file_free(&temp_file);
	return FALSE;

}

static void group_monitor_forward(const char *group, STR_HASH_TABLE *phash,
	const char *from, MEM_FILE *fp_rcpt_to, MAIL *pmail,
	MESSAGE_CONTEXT *pforward_context)
{
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;
	char temp_domain[256];
	char rcpt_to[256], origin_rcpt[256];
	char composed_subject[1024];
	char original_subject[1024];
	char *pdomain, *pdomain1;
	FORWARD_DATA *pdata;
	MEM_FILE file_forward;
	BOOL should_forward;
	MIME *pmime;

	pdomain = strchr(group, '@');
	if (NULL == pdomain) {
		return;
	}
	strcpy(temp_domain, pdomain + 1);
	
	/* first search the "from" domain */
	pdomain = strchr(from, '@');
	if (NULL == pdomain) {
		return;
	}
	pdomain ++;

	mem_file_init(&file_forward, fp_rcpt_to->allocator);
	
	plist = (DOUBLE_LIST*)str_hash_query(phash, pdomain);
	if (NULL != plist) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			pdata = (FORWARD_DATA*)pnode->pdata;
			if (FORWARD_IN != pdata->type) {
				mem_file_writeline(&file_forward, pdata->forward_to);
			}
		}
	}
	plist = (DOUBLE_LIST*)str_hash_query(phash, (char*)from);
	if (NULL != plist) {
		for (pnode=double_list_get_head(plist); NULL!=pnode;
			pnode=double_list_get_after(plist, pnode)) {
			pdata = (FORWARD_DATA*)pnode->pdata;
			if (FORWARD_IN != pdata->type) {
				mem_file_writeline(&file_forward, pdata->forward_to);
			}
		}
	}

	/* search every recipient and check if they have forwarder */
	mem_file_seek(fp_rcpt_to, MEM_FILE_READ_PTR, 0, MEM_FILE_SEEK_BEGIN);
	while (MEM_END_OF_FILE != mem_file_readline(fp_rcpt_to, rcpt_to, 256)) {
		lower_string(rcpt_to);
		pdomain1 = strchr(rcpt_to, '@');
		if (NULL == pdomain1) {
			continue;
		}
		pdomain1 ++;
		plist = (DOUBLE_LIST*)str_hash_query(phash, pdomain1);
		if (NULL != plist) {
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				pdata = (FORWARD_DATA*)pnode->pdata;
				if (FORWARD_OUT != pdata->type) {
					mem_file_writeline(&file_forward, pdata->forward_to);
				}
			}
		}
		plist = (DOUBLE_LIST*)str_hash_query(phash, rcpt_to);
		if (NULL != plist) {
			for (pnode=double_list_get_head(plist); NULL!=pnode;
				pnode=double_list_get_after(plist, pnode)) {
				pdata = (FORWARD_DATA*)pnode->pdata;
				if (FORWARD_OUT != pdata->type) {
					mem_file_writeline(&file_forward, pdata->forward_to);
				}
			}
		}
	}
	/* if there's no forwarder, return immediately */
	if (mem_file_get_total_length(&file_forward) == 0) {
		mem_file_free(&file_forward);
		return;
	}

	/* merge the replicate forwarder */
	while (MEM_END_OF_FILE != mem_file_readline(&file_forward, rcpt_to, 256)) {
		should_forward = TRUE;
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
		return;
	}
	
	sprintf(pforward_context->pcontrol->from, "forward@%s", temp_domain);
	pforward_context->pcontrol->need_bounce = FALSE;
	mail_dup(pmail, pforward_context->pmail);
	pmime = mail_get_head(pforward_context->pmail);
	if (NULL == pmime) {
		mem_file_clear(&pforward_context->pcontrol->f_rcpt_to);
		mem_file_free(&file_forward);
		return;
	}
	strcpy(original_subject, "no subject");
	mime_get_field(pmime, "Subject", original_subject, 1024);
	snprintf(composed_subject, 1024, "%s:%s", g_subject, original_subject);
	mime_set_field(pmime, "Subject", composed_subject);
	mem_file_free(&file_forward);
	return;
}

/*
 *	stop the module
 *	@return
 *		 0				OK
 *		<>0				fail
 */
int group_monitor_stop()
{
	STR_HASH_ITER *iter;
	STR_HASH_TABLE **pphash;
	
	if (NULL != g_group_hash) {
		iter = str_hash_iter_init(g_group_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			pphash = (STR_HASH_TABLE**)str_hash_iter_get_value(iter, NULL);
			group_monitor_free_table(*pphash);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_group_hash);
		g_group_hash = NULL;
	}
	return 0;
}

/*
 *	mail forwarder's destruct function
 *
 */
void group_monitor_free()
{
	g_root_path[0] = '\0';
	g_subject[0] = '\0';
	pthread_rwlock_destroy(&g_table_lock);
}


static int group_monitor_add_group(const char *group)
{
	STR_HASH_TABLE *phash;
	STR_HASH_TABLE **pphash;
	STR_HASH_TABLE *ptemp_hash;
	STR_HASH_TABLE **ppitem_hash;
	STR_HASH_ITER *iter;
	int i, list_len, type;
	LIST_FILE *plist_file;
	char *pdomain, *pitem, temp_path[256];
	char temp_group[256], temp_buff[256];
	char *str_type, *str_tag, *str_value;

	strcpy(temp_group, group);
	lower_string(temp_group);
	pdomain = strchr(temp_group, '@');
	if (NULL == pdomain) {
		return GROUP_LOAD_NAME_ERROR;
	}
	pdomain ++;
	sprintf(temp_path, "%s/%s.txt", g_root_path, temp_group);
	/* initialize the list filter */
	plist_file = list_file_init(temp_path, "%s:16%s:256:%s:256");
	if (NULL == plist_file) {
		printf("[group_monitor]: fail to open list file %s\n", temp_path);
		return GROUP_LOAD_FILE_ERROR;
	}
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	phash = str_hash_init(list_len + 1, sizeof(DOUBLE_LIST), NULL);
	if (NULL == phash) {
		printf("[group_monitor]: fail to allocate hash map for %s", group);
		list_file_free(plist_file);
		return GROUP_LOAD_HASH_FAIL;
	}
	for (i=0; i<list_len; i++) {
		str_type = pitem + 528*i;
		str_tag = str_type + 16;
		str_value = str_tag + 256;
		if (0 == strcasecmp("F_IN", str_type)) {
			type = FORWARD_IN;
		} else if (0 == strcasecmp("F_OUT", str_type)) {
			type = FORWARD_OUT;
		} else if (0 == strcasecmp("F_ALL", str_type)) {
			type = FORWARD_ALL;
		} else {
			printf("[group_monitor]: type error in item %d, only can be one "
				"of \"F_IN\", \"F_OUT\", \"F_ALL\"\n", i + 1);
			continue;
		}
		lower_string(str_tag);
		if (FALSE == group_monitor_add_table(phash, type, str_tag, 
			str_value)) {
			printf("[group_monitor]: fail to add %s into table, it may "
				"already exist!\n", str_tag);
		}
	}
	list_file_free(plist_file);
	pthread_rwlock_wrlock(&g_table_lock);
	pphash = (STR_HASH_TABLE**)str_hash_query(g_group_hash, temp_group);
	if (NULL != pphash) {
		group_monitor_free_table(*pphash);
		str_hash_remove(g_group_hash, temp_group);
	}
	if (1 != str_hash_add(g_group_hash, temp_group, &phash)) {
		ptemp_hash = str_hash_init(g_hash_cap + g_growing_num,
						sizeof(STR_HASH_TABLE), NULL);
		if (NULL == ptemp_hash) {
			pthread_rwlock_unlock(&g_table_lock);
			group_monitor_free_table(phash);
			return GROUP_LOAD_HASH_FAIL;
		}
		iter = str_hash_iter_init(g_group_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			ppitem_hash = (STR_HASH_TABLE**)str_hash_iter_get_value(iter,
							temp_buff);
			str_hash_add(ptemp_hash, temp_buff, ppitem_hash);
		}
		str_hash_iter_free(iter);
		str_hash_free(g_group_hash);
		g_group_hash = ptemp_hash;
		g_hash_cap += g_growing_num;
		if (1 != str_hash_add(g_group_hash, temp_group, &phash)) {
			group_monitor_free_table(phash);
			pthread_rwlock_unlock(&g_table_lock);
			return GROUP_LOAD_HASH_FAIL;
		}	
	}
	/* add domain into monitor table */
	if (FALSE == monitor_domains_add(pdomain)) {
		group_monitor_free_table(phash);
		str_hash_remove(g_group_hash, temp_group);
		pthread_rwlock_unlock(&g_table_lock);
		return GROUP_LOAD_DOMAIN_ERROR;
	}
	pthread_rwlock_unlock(&g_table_lock);
	return GROUP_LOAD_OK;
}

static void group_monitor_remove_group(const char *group)
{
	BOOL b_found;
	char *pdomain;
	char *pdomain1;
	char temp_buff[256];
	char temp_path[256];
	char temp_group[256];
	STR_HASH_TABLE **pphash;
	STR_HASH_TABLE *phash = NULL;
	STR_HASH_ITER *iter;

	strcpy(temp_group, group);
	lower_string(temp_group);
	pdomain = strchr(temp_group, '@');
	if (NULL == pdomain) {
		return;
	}
	pdomain ++;
	
	pthread_rwlock_wrlock(&g_table_lock);
	pphash = (STR_HASH_TABLE**)str_hash_query(g_group_hash, temp_group);
	if (NULL != pphash) {
		phash = *pphash;
		str_hash_remove(g_group_hash, temp_group);
		/* remove domain from monitor domains table */
		b_found = FALSE;
		iter = str_hash_iter_init(g_group_hash);
		for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
			str_hash_iter_forward(iter)) {
			str_hash_iter_get_value(iter, temp_buff);
			pdomain1 = strchr(temp_buff, '@');
			if (NULL == pdomain1) {
				continue;
			}
			pdomain1 ++;
			if (0 == strcmp(pdomain, pdomain1)) {
				b_found = TRUE;
				break;
			}
		}
		str_hash_iter_free(iter);
		if (FALSE == b_found) {
			monitor_domains_remove(pdomain);
		}
	}
	pthread_rwlock_unlock(&g_table_lock);
	if (NULL != phash) {
		group_monitor_free_table(phash);
	}
	sprintf(temp_path, "%s/%s.txt", g_root_path, temp_group);
	remove(temp_path);
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
static BOOL group_monitor_add_table(STR_HASH_TABLE *ptable, int type,
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
static BOOL group_monitor_free_table(STR_HASH_TABLE *ptable)
{
	STR_HASH_ITER *iter;
	DOUBLE_LIST *plist;
	DOUBLE_LIST_NODE *pnode;

	iter = str_hash_iter_init(ptable);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		plist = (DOUBLE_LIST*)str_hash_iter_get_value(iter, NULL);
		while ((pnode = double_list_get_from_head(plist)) != NULL)
			free(pnode->pdata);
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
void group_monitor_console_talk(int argc, char **argv, char *result,
	int length)
{
	char help_string[] = "250 group monitor help information:\r\n"
						 "\t%s add <group>\r\n"
						 "\t    --add group monitor table into system\r\n"
						 "\t%s remove <group>\r\n"
						 "\t    --remove group monitor table from system";
	if (1 == argc) {
		strncpy(result, "550 too few arguments", length);
		return;
	}
	if (2 == argc && 0 == strcmp("--help", argv[1])) {
		snprintf(result, length, help_string, argv[0], argv[0]);
		result[length - 1] ='\0';
		return;
	}
	if (3 == argc && 0 == strcmp("add", argv[1])) {
		switch (group_monitor_add_group(argv[2])) {
		case GROUP_LOAD_OK:
			snprintf(result, length, "250 group %s's monitor list added OK",
				argv[2]);
			break;
		case GROUP_LOAD_NAME_ERROR:
			snprintf(result, length, "550 seems %s is not a legal group name",
				argv[2]);
			break;
		case GROUP_LOAD_FILE_ERROR:
			snprintf(result, length, "550 fail to open group %s's monitor "
				"list file", argv[2]);
			break;
		case GROUP_LOAD_HASH_FAIL:
			snprintf(result, length, "550 fail to add group %s's monitor "
				"list into hash table", argv[2]);
			break;
		case GROUP_LOAD_DOMAIN_ERROR:
			snprintf(result, length, "550 fail to add group %s's domain into "
				"domain table", argv[2]);
			break;
		}
		return;
	}
	if (3 == argc && 0 == strcmp("remove", argv[1])) {
		group_monitor_remove_group(argv[2]);
		snprintf(result, length, "250 group %s's monitor list removed OK",
			argv[2]);
		return;
	}
	snprintf(result, length, "550 invalid argument %s", argv[1]);
	return;
}


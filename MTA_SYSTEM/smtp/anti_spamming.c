/*
 *	  there're one list named g_list_lib, which contains all plugins loaded int 
 *	  system. another hash is named as g_hash_type, every unit in this hash also
 *	  has a list, the list indicate the filters of this type, for auditors, they
 *	  actually compare the data in mail body and the judge whether this mail is 
 *	  spamming 
 */
#include <libHX/string.h>
#include "anti_spamming.h"
#include "double_list.h"
#include "lib_buffer.h"
#include "vstack.h"
#include "util.h"
#include "str_hash.h"
#include "resource.h"
#include "service.h"
#include "contexts_pool.h"
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <stdio.h>

#define SERVICE_VERSION		   0x00000001
/* struct for describing the plugin */
typedef struct _SHARELIB{
	DOUBLE_LIST_NODE	node;
	DOUBLE_LIST			list_reference;
	/* list for judges registered by this plugin */
	DOUBLE_LIST			list_judge;
	/* list for auditors registered by this plugin */
	DOUBLE_LIST			list_auditor;
	/* list for filters registered by this plugin */
	DOUBLE_LIST			list_filter;
	/* list for statistics registered by the plugin */
	DOUBLE_LIST			list_statistic;
	char				file_name[256];
	char				full_path[256];
	void				*handle;
	PLUGIN_MAIN			lib_main;
	TALK_MAIN			talk_main;
} SHARELIB;

/* structure for describing service reference */
typedef struct _SERVICE_NODE{
	DOUBLE_LIST_NODE	node;
	void				*service_addr;
	char				*service_name;
} SERVICE_NODE;

/* structure for describing statistic */
typedef struct _STATISTIC_NODE{
	DOUBLE_LIST_NODE	node_statistic;
	DOUBLE_LIST_NODE	node_lib;
	struct _SHARELIB	*plib;
	STATISTIC_FUNCTION	statistic_func;
} STATISTIC_NODE;
/* structure for describing filter */
typedef struct _FILTER_NODE{
	DOUBLE_LIST_NODE	node_type;
	DOUBLE_LIST_NODE	node_lib;
	struct _SHARELIB	*plib;
	FILTER_FUNCTION		filter_func;
	char				type[256];
} FILTER_NODE;

/* struct for describing auditor */
typedef struct _AUDITOR_NODE{
	DOUBLE_LIST_NODE	node_auditor;
	DOUBLE_LIST_NODE	node_lib;
	struct _SHARELIB	*plib;
	AUDITOR_FUNCTION	auditor_func;
} AUDITOR_NODE;

/* struct for describing judge */
typedef struct _JUDGE_NODE{
	DOUBLE_LIST_NODE	node_judge;
	DOUBLE_LIST_NODE	node_lib;
	struct _SHARELIB	*plib;
	JUDGE_FUNCTION		judge_func;
} JUDGE_NODE;

/* filters are arranged in types, the following struct is for describing type*/
typedef struct _TYPE_NODE{
	DOUBLE_LIST			list;
	char				type[256];
} TYPE_NODE;

static BOOL anti_spamming_register_statistic(STATISTIC_FUNCTION func);

static BOOL anti_spamming_unregister_statistic(STATISTIC_FUNCTION func);

static BOOL anti_spamming_register_filter(char* type, FILTER_FUNCTION func);

static BOOL anti_spamming_unregister_filter(char* type, FILTER_FUNCTION func);

static BOOL anti_spamming_register_auditor(AUDITOR_FUNCTION func);

static BOOL anti_spamming_unregister_auditor(AUDITOR_FUNCTION func);

static BOOL anti_spamming_register_judge(JUDGE_FUNCTION func);

static BOOL anti_spamming_unregister_judge(JUDGE_FUNCTION func);

static BOOL anti_spamming_register_talk(TALK_MAIN talk);

static BOOL anti_spamming_unregister_talk(TALK_MAIN talk);

static int anti_spamming_getversion();

static void* anti_spamming_queryservice(char *service);

static void anti_spamming_reset_envelop_files(ENVELOP_INFO *penvelop);

static void anti_spamming_reset_head_files(MAIL_HEAD *phead);

static void anti_spamming_reset_body_files(MAIL_BODY *pbody);

static CONNECTION* get_connection_by_id(int context_ID);

static MAIL_ENTITY get_mail_entity_by_id(int context_ID);

static BOOL anti_spamming_set_extra_value(int context_ID, char* tag,char* pval);

static void anti_spamming_mark_context_spam(int context_ID);

static BOOL anti_spamming_is_need_auth();

static BOOL anti_spamming_is_domainlist_valid();

static const char* anti_spamming_get_default_domain();

static const char* anti_spamming_get_plugin_name();

static const char* anti_spamming_get_config_path();

static const char *anti_spamming_get_data_path();

static int anti_spamming_get_context_num();

static char g_init_path[256];
static const char *const *g_plugin_names;
static DOUBLE_LIST	  g_list_lib;
static STR_HASH_TABLE *g_hash_type;
static DOUBLE_LIST	  g_list_judge;
static DOUBLE_LIST	  g_list_auditor;
static DOUBLE_LIST	  g_list_statistic;
/* 
plugin lock is a read write lock, which control the resource of types list and 
auditors list. they are actually registered in plugin 
*/
static pthread_rwlock_t g_plugin_lock;
/* for remembering the lib pointer when register plugin's filter function */
static SHARELIB *g_cur_lib;

/*
 *	  anti-spamming's construct function
 *	  @param
 *		  path	  indicate the path for searching
 */
void anti_spamming_init(const char *path, const char *const *names)
{	 
	strncpy(g_init_path, path, 256);
	g_plugin_names = names;
}


/*
 *	  run the anti-spamming module
 *	  @return
 *		   0	success
 *		  -1	fail to open the plugins' directory
 */
int anti_spamming_run() 
{	 
	double_list_init(&g_list_lib);
	double_list_init(&g_list_judge);
	g_hash_type = str_hash_init(256, sizeof(TYPE_NODE), NULL);
	double_list_init(&g_list_auditor);
	double_list_init(&g_list_statistic);
	pthread_rwlock_init(&g_plugin_lock, NULL);
	for (const char *const *i = g_plugin_names; *i != NULL; ++i) {
		int ret = anti_spamming_load_library(*i);
		if (ret != PLUGIN_LOAD_OK)
			return -1;
	}
	return 0;
}

/*
 *	  load a library into anti-spamming module
 *	  @param	
 *		  path	  indicate the file name
 *	  @return	  
 *		  PLUGIN_LOAD_OK			  success
 *		  PLUGIN_ALREADY_LOADED		  already loaded by anti-spamming module
 *		  PLUGIN_FAIL_OPEN			  error to load the file
 *		  PLUGIN_NO_MAIN			  error to find library function
 *		  PLUGIN_FAIL_ALLOCNODE		  fail to allocate memory for a node
 *		  PLUGIN_FAIL_EXCUTEMAIN	  error to excute plugin's init function	
 */
int anti_spamming_load_library(const char* path)
{
	const char *fake_path = path;
	void* two_server_funcs[2];
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	SHARELIB *plib;

	two_server_funcs[0] = (void*)anti_spamming_getversion;
	two_server_funcs[1] = (void*)anti_spamming_queryservice;

	/* check whether the library is already loaded */
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
			if (strcmp(((SHARELIB*)(pnode->pdata))->file_name, path) == 0) {
				printf("[anti_spamming]: %s is already loaded by anti-spamming module\n", path);
				return PLUGIN_ALREADY_LOADED;
			}
	}
	void *handle = dlopen(path, RTLD_LAZY);
	if (handle == NULL && strchr(path, '/') == NULL) {
		char altpath[256];
		snprintf(altpath, sizeof(altpath), "%s/%s", g_init_path, path);
		handle = dlopen(altpath, RTLD_LAZY);
	}
	if (NULL == handle){
		printf("[anti_spamming]: error to load %s reason: %s\n", fake_path, 
				dlerror());
		printf("[anti_spamming]: the plugin %s is not loaded\n", fake_path);
		return PLUGIN_FAIL_OPEN;
	}
	func = (PLUGIN_MAIN)dlsym(handle, "AS_LibMain");
	if (NULL == func) {
		printf("[anti_spamming]: error to find AS_LibMain function in %s\n",
				fake_path);
		printf("[anti_spamming]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_NO_MAIN;
	}
	plib = (SHARELIB*)malloc(sizeof(SHARELIB));
	if (NULL == plib) {
		printf("[anti_spamming]: fail to allocate memory for %s\n", fake_path);
		printf("[anti_spamming]: the plugin %s is not loaded\n", fake_path);
		dlclose(handle);
		return PLUGIN_FAIL_ALLOCNODE;
	}
	memset(plib, 0, sizeof(SHARELIB));
	/* make the node's pdata ponter point to the SHARELIB struct */
	plib->node.pdata = plib;
	/* for all plugins, there's should be a read-write lock for controlling 
	   its modification. ervery time, the anti-spamming function is invoked, 
	   the read lock is acquired. when the plugin is going to be modified, 
	   acquire the write lock.
	*/
	double_list_init(&plib->list_reference);
	double_list_init(&plib->list_judge);
	double_list_init(&plib->list_auditor);
	double_list_init(&plib->list_filter);
	double_list_init(&plib->list_statistic);
	strncpy(plib->file_name, path, 255);
	strncpy(plib->full_path, fake_path, 255);
	plib->handle = handle;
	plib->lib_main = func;
	/* append the plib node into lib list */
	double_list_append_as_tail(&g_list_lib, &plib->node);
	/* 
	indicate the current lib node when plugin rigisters auditor or filter, the 
	plugin can only register the auditor or filter functions in "AS_LibMain" 
	whith the paramter PLUGIN_INIT
	*/
	g_cur_lib = plib;
	/* invoke the plugin's main function with the parameter of PLUGIN_INIT */
	if (FALSE == func(PLUGIN_INIT, (void**) two_server_funcs)) {
		printf("[anti_spamming]: error to excute plugin's init function "
				"in %s\n", fake_path);
		printf("[anti_spamming]: the plugin %s is not loaded\n", fake_path);
		/*
		the lib node will automatically removed from libs list in 
		anti-spamming_unload_library function
		*/
		anti_spamming_unload_library(fake_path);
		g_cur_lib = NULL;
		return PLUGIN_FAIL_EXCUTEMAIN;
	}
	g_cur_lib = NULL;
	return 0;
}

/*
 *	register a certain statistic in the anti-spamming module
 *	@param
 *		func	the statistic function
 *	@return
 *		TRUE	OK to register the function
 *		FALSE	fail to register function
 */
static BOOL anti_spamming_register_statistic(STATISTIC_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	STATISTIC_NODE *pstatistic;

	if (NULL == func) {
		return FALSE;
	}
	/*check if register statistic is invoked only in AS_LibMain(PLUGIN_INIT..)*/
	if (NULL == g_cur_lib) {
		return FALSE;
	}

	/* check if the statistic is already registered in statistic list */	
	for (pnode=double_list_get_head(&g_list_statistic); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_statistic, pnode)) {
		if (((STATISTIC_NODE*)(pnode->pdata))->statistic_func == func) {
			break;
		}
	}
	if (NULL != pnode) {
		return FALSE;
	}
	pstatistic = malloc(sizeof(STATISTIC_NODE));
	if (NULL == pstatistic) {
		return FALSE;
	}
	memset(pstatistic, 0, sizeof(STATISTIC_NODE));
	pstatistic->node_statistic.pdata = pstatistic;
	pstatistic->node_lib.pdata = pstatistic;
	pstatistic->plib = g_cur_lib;
	pstatistic->statistic_func = func;		  
	/* aquire write lock when to modify the auditors list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_append_as_tail(&g_list_statistic, &pstatistic->node_statistic);
	pthread_rwlock_unlock(&g_plugin_lock);
	/* append also the auditer into lib's auditers list */
	double_list_append_as_tail(&g_cur_lib->list_statistic,
		&pstatistic->node_lib);
	return TRUE;	
}

/*
 *	  register a certain type of filter in the anti-spamming module
 *	  @param
 *		  type	  indicate which type of content the filter make effect, for 
 *				  example "txt/plain"
 *		  func	  the filter function
 *	  @return
 *		  TRUE	  OK to register the function
 *		  FALSE	  fail to register function
 */
static BOOL anti_spamming_register_filter(char* type, FILTER_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	TYPE_NODE	 *ptype, tmp_type;
	FILTER_NODE	 *pfilter;
	char		 tmp_buff[256];
	char		 all_type = '\0';

	if (NULL == func) {
		return FALSE;
	}
	/* check if register filter is invoked only in AS_LibMain(PLUGIN_INIT...)*/
	if (NULL == g_cur_lib) {
		return FALSE;
	}
	/* NULL is reserved for all types */
	if (NULL == type) {
		type = &all_type;
	}
	if (255 < strlen(type)) {
		return FALSE;
	}
	swap_string(tmp_buff, type);
	HX_strlower(tmp_buff);
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, tmp_buff);
	/* allocate the filter node and fill it */
	pfilter = malloc(sizeof(FILTER_NODE));
	if (NULL == pfilter) {
		printf("[anti_spamming]: fail to allocate filter node in register"
				" filter\n");
		return FALSE;
	}
	memset(pfilter, 0, sizeof(FILTER_NODE));
	pfilter->node_type.pdata = pfilter;
	pfilter->node_lib.pdata = pfilter;
	pfilter->plib = g_cur_lib;
	pfilter->filter_func = func;
	strncpy(pfilter->type, type, 256);
	/* check first in types hash whether it is already in */
	if (NULL == ptype) {
		/* allocate the type node and add filter node in type node's 
		   filters list 
		*/
		ptype = &tmp_type;
		memset(ptype, 0, sizeof(TYPE_NODE));
		strncpy(ptype->type, type, 256);
		double_list_init(&ptype->list);
		double_list_append_as_tail(&ptype->list, &pfilter->node_type);
		/* aquire write lock when to modify the types list */
		pthread_rwlock_wrlock(&g_plugin_lock);
		str_hash_add(g_hash_type, tmp_buff, ptype); 
		pthread_rwlock_unlock(&g_plugin_lock);
	} else {
		/*
		search the filter list of certain "type" and check if the function 
		already exists
		*/
		for(pnode=double_list_get_head(&ptype->list); NULL!=pnode; 
			pnode=double_list_get_after(&ptype->list, pnode)) {
			if (((FILTER_NODE*)(pnode->pdata))->filter_func == func) {
				break;
			}
		}
		if (NULL != pnode) {
			printf("[anti_spamming]: function is already registered \n");
			free(pfilter);
			return FALSE;
		}
		/* aquire write lock when to modify the type's filters list */
		pthread_rwlock_wrlock(&g_plugin_lock);
		double_list_append_as_tail(&ptype->list, &pfilter->node_type);
		pthread_rwlock_unlock(&g_plugin_lock);
	}
	/* append also the filter into lib's filters list */
	double_list_append_as_tail(&g_cur_lib->list_filter, &pfilter->node_lib);
	return TRUE;
}

/*
 *	register a certain auditor in the anti-spamming module
 *	@param
 *		func	the auditor function
 *	@return
 *		TRUE	OK to register the function
 *		FALSE	fail to register function
 */
static BOOL anti_spamming_register_auditor(AUDITOR_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	AUDITOR_NODE *pauditor;

	if (NULL == func) {
		return FALSE;
	}
	/*check if register auditor is invoked only in AS_LibMain(PLUGIN_INIT,..)*/
	if (NULL == g_cur_lib) {
		return FALSE;
	}

	/* check if the auditor is already registered in auditor list */	
	for (pnode=double_list_get_head(&g_list_auditor); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_auditor, pnode)) {
		if (((AUDITOR_NODE*)(pnode->pdata))->auditor_func == func) {
			break;
		}
	}
	if (NULL != pnode) {
		return FALSE;
	}
	pauditor = malloc(sizeof(AUDITOR_NODE));
	if (NULL == pauditor) {
		return FALSE;
	}
	memset(pauditor, 0, sizeof(AUDITOR_NODE));
	pauditor->node_auditor.pdata = pauditor;
	pauditor->node_lib.pdata = pauditor;
	pauditor->plib = g_cur_lib;
	pauditor->auditor_func = func;		  
	/* aquire write lock when to modify the auditors list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_append_as_tail(&g_list_auditor, &pauditor->node_auditor);
	pthread_rwlock_unlock(&g_plugin_lock);
	/* append also the auditer into lib's auditers list */
	double_list_append_as_tail(&g_cur_lib->list_auditor, &pauditor->node_lib);
	return TRUE;	
}

/*
 *	register a certain judge in the anti-spamming module
 *	@param
 *		func	the judge function
 *	@return
 *		TRUE	OK to register the function
 *		FALSE	fail to register function
 */
static BOOL anti_spamming_register_judge(JUDGE_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	JUDGE_NODE *pjudge;

	if (NULL == func) {
		return FALSE;
	}
	/*check if register judge is invoked only in AS_LibMain(PLUGIN_INIT,..)*/
	if (NULL == g_cur_lib) {
		return FALSE;
	}

	/* check if the judge is already registered in judge list */ 
	for (pnode=double_list_get_head(&g_list_judge); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_judge, pnode)) {
		if (((JUDGE_NODE*)(pnode->pdata))->judge_func == func) {
			break;
		}
	}
	if (NULL != pnode) {
		return FALSE;
	}
	pjudge = malloc(sizeof(JUDGE_NODE));
	if (NULL == pjudge) {
		return FALSE;
	}
	memset(pjudge, 0, sizeof(JUDGE_NODE));
	pjudge->node_judge.pdata = pjudge;
	pjudge->node_lib.pdata = pjudge;
	pjudge->plib = g_cur_lib;
	pjudge->judge_func = func; 
	/* aquire write lock when to modify the judges list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_append_as_tail(&g_list_judge, &pjudge->node_judge);
	pthread_rwlock_unlock(&g_plugin_lock);
	/* append also the judge into lib's judges list */
	double_list_append_as_tail(&g_cur_lib->list_judge, &pjudge->node_lib);
	return TRUE; 
}

/*
 *	unregister a statistic in the anti-spamming module
 *	@param
 *		func	indicate the statistic function
 *	@return
 *		TRUE	OK to unrigister
 *		FALSE	fail to unrigister
 */
static BOOL anti_spamming_unregister_statistic(STATISTIC_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	STATISTIC_NODE *pstatistic;
	
	/* find the statistic node in statistics list */
	for (pnode=double_list_get_head(&g_list_statistic); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_statistic, pnode)) {
		if (((STATISTIC_NODE*)(pnode->pdata))->statistic_func == func) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	pstatistic = (STATISTIC_NODE*)pnode->pdata;
	/* remove it first from lib's statistic list, do not need rw lock */
	double_list_remove(&pstatistic->plib->list_statistic,
		&pstatistic->node_lib);
	/* remove the statistic from the statistics list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_remove(&g_list_statistic, &pstatistic->node_statistic);
	free(pstatistic);
	pthread_rwlock_unlock(&g_plugin_lock);
	return TRUE;
}

/*
 *	  unregister a certain type of filter in the anti-spamming module	 
 *	  @param
 *		  type	  indicate the type of the filter
 *		  func	  indicate the filter function
 *	  @return
 *		  TRUE	  OK to unrigister
 *		  FALSE	  fail to unrigister
 */
static BOOL anti_spamming_unregister_filter(char* type, FILTER_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	TYPE_NODE		 *ptype;
	FILTER_NODE		 *pfilter;
	char			 tmp_buff[256];
	char			 all_type = '\0';

	if (NULL == func) {
		return FALSE;
	}
	if (NULL == type) {
		type = &all_type;
	}
	if (255 < strlen(type)) {
		return FALSE;
	}
	swap_string(tmp_buff, type);
	HX_strlower(tmp_buff);
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, tmp_buff);
	
	if (NULL == ptype) {
		return FALSE;
	} else {
		for (pnode=double_list_get_head(&ptype->list); NULL!=pnode;
			 pnode=double_list_get_after(&ptype->list, pnode)) {
			if (((FILTER_NODE*)(pnode->pdata))->filter_func == func) {
				break;
			}	 
		}
		if (NULL == pnode) {
			return FALSE;
		}
		pfilter = (FILTER_NODE*)pnode->pdata;
		/* remove it first from lib's filter list, do not need rw lock */
		double_list_remove(&pfilter->plib->list_filter, &pfilter->node_lib);
		/* remove the filter from the type's filters list */
		pthread_rwlock_wrlock(&g_plugin_lock);
		double_list_remove(&ptype->list, &pfilter->node_type);
		free(pfilter);
		if (0 == double_list_get_nodes_num(&ptype->list)) {
			str_hash_remove(g_hash_type, tmp_buff);
			ptype = NULL;
		}
		pthread_rwlock_unlock(&g_plugin_lock);
		return TRUE;
	}
}

/*
 *	unregister a auditor in the anti-spamming module
 *	@param
 *		func	indicate the auditer function
 *	@return
 *		TRUE	OK to unrigister
 *		FALSE	fail to unrigister
 */
static BOOL anti_spamming_unregister_auditor(AUDITOR_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	AUDITOR_NODE *pauditor;
	
	/* find the auditor node in auditors list */
	for (pnode=double_list_get_head(&g_list_auditor); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_auditor, pnode)) {
		if (((AUDITOR_NODE*)(pnode->pdata))->auditor_func == func) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	pauditor = (AUDITOR_NODE*)pnode->pdata;
	/* remove it first from lib's auditor list, do not need rw lock */
	double_list_remove(&pauditor->plib->list_auditor, &pauditor->node_lib);
	/* remove the auditor from the auditors list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_remove(&g_list_auditor, &pauditor->node_auditor);
	free(pauditor);
	pthread_rwlock_unlock(&g_plugin_lock);
	return TRUE;
}

/*
 *	unregister a judge in the anti-spamming module
 *	@param
 *		func	indicate the judge function
 *	@return
 *		TRUE	OK to unrigister
 *		FALSE	fail to unrigister
 */
static BOOL anti_spamming_unregister_judge(JUDGE_FUNCTION func)
{
	DOUBLE_LIST_NODE *pnode;
	JUDGE_NODE *pjudge;
	
	/* find the judge node in judges list */
	for (pnode=double_list_get_head(&g_list_judge); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_judge, pnode)) {
		if (((JUDGE_NODE*)(pnode->pdata))->judge_func == func) {
			break;
		}
	}
	if (NULL == pnode) {
		return FALSE;
	}
	pjudge = (JUDGE_NODE*)pnode->pdata;
	/* remove it first from lib's judge list, do not need rw lock */
	double_list_remove(&pjudge->plib->list_judge, &pjudge->node_lib);
	/* remove the judge from the judges list */
	pthread_rwlock_wrlock(&g_plugin_lock);
	double_list_remove(&g_list_judge, &pjudge->node_judge);
	free(pjudge);
	pthread_rwlock_unlock(&g_plugin_lock);
	return TRUE;
}

/*
 *	unload the the plugin. CAUTION!!! can not invoke judge, auditor or filter's 
 *	unregister function because of the traversing of the double list (unregister
 *	functions will remove the node from list but the list is now traversed now)
 *	@param
 *		  path	  indicate the filename of plugin
 *	@return
 *		  PLUGIN_UNLOAD_OK	  success
 *		  PLUGIN_NOT_FOUND	  plugin is not found in anti-spamming module
 *		  PLUGIN_SYSTEM_ERROR information in lists map differs
 */
int anti_spamming_unload_library(const char* path)
{	 
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	SHARELIB *plib;
	TYPE_NODE *ptype;
	char type[256], tmp_buff[256], *ptr;
	
	ptr = strrchr(path, '/');
	if (NULL != ptr) {
		ptr++;
	} else {
		ptr = (char*)path;
	}
	/* first find the plugin node in lib list */
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode; 
		 pnode=double_list_get_after(&g_list_lib, pnode)){
		if (0 == strcmp(((SHARELIB*)(pnode->pdata))->file_name, ptr)) {
			break;
		}
	}	 
	if(NULL == pnode){
		return PLUGIN_NOT_FOUND;
	}
	plib = (SHARELIB*)(pnode->pdata);
	/* check if the there rests judge(s) that has not been unrigstered */
	if (0 != double_list_get_nodes_num(&plib->list_judge)) {
		for (pnode=double_list_get_head(&plib->list_judge); NULL!=pnode;
			 pnode=double_list_get_after(&plib->list_judge, pnode)) {
			 /*
			aquire the write lock to make sure that there's no judge excuting 
			threads in the judges list
			*/
			pthread_rwlock_wrlock(&g_plugin_lock);
			double_list_remove(&g_list_judge, 
							   &((JUDGE_NODE*)(pnode->pdata))->node_judge);
			pthread_rwlock_unlock(&g_plugin_lock);
		}
		/* free lib's auditor list */
		while ((pnode = double_list_get_from_head(&plib->list_judge))) {
			free(pnode->pdata);
			pnode = NULL;
		}
		double_list_free(&plib->list_judge);
	}
	/* check if the there rests auditor(s) that has not been unrigstered */
	if (0 != double_list_get_nodes_num(&plib->list_auditor)) {
		for (pnode=double_list_get_head(&plib->list_auditor); NULL!=pnode;
			 pnode=double_list_get_after(&plib->list_auditor, pnode)) {
			 /*
			aquire the write lock to make sure that there's no auditor excuting 
			threads in the auditors list
			*/
			pthread_rwlock_wrlock(&g_plugin_lock);
			double_list_remove(&g_list_auditor, 
							   &((AUDITOR_NODE*)(pnode->pdata))->node_auditor);
			pthread_rwlock_unlock(&g_plugin_lock);
		}
		/* free lib's auditor list */
		while ((pnode = double_list_get_from_head(&plib->list_auditor))) {
			free(pnode->pdata);
			pnode = NULL;
		}
		double_list_free(&plib->list_auditor);
	}
	/* check if the there rests filter(s) that has not been unrigstered */
	if(0 != double_list_get_nodes_num(&plib->list_filter)) {
		/* traverse the lib's filter list and remove them in type tree */
		for (pnode=double_list_get_head(&plib->list_filter); NULL!=pnode; 
			 pnode=double_list_get_after(&plib->list_filter, pnode)) {
			strncpy(type, ((FILTER_NODE*)(pnode->pdata))->type, 256);
			swap_string(tmp_buff, type);
			HX_strlower(tmp_buff);
			ptype = (TYPE_NODE*)str_hash_query(g_hash_type, tmp_buff);
			if (NULL == ptype) {
				printf("[anti_spamming]: fatal error when unload the "
						"anti-spamming plugin\n");
				return PLUGIN_SYSTEM_ERROR;
			}
			/* aquire the write lock to make sure that there's no filter
			   excuting threads in the filter tree
			*/
			pthread_rwlock_wrlock(&g_plugin_lock);
			double_list_remove(&ptype->list, 
							   &((FILTER_NODE*)(pnode->pdata))->node_type);
			/* check wether the type's filters list is empty, if it is, remove 
			   the type node from type list 
			*/
			if (0 == double_list_get_nodes_num(&ptype->list)) {
				double_list_free(&ptype->list);
				str_hash_remove(g_hash_type, tmp_buff);
				ptype = NULL;
			} 
			pthread_rwlock_unlock(&g_plugin_lock);
		}
		/* clear the lib's filter list and remove the lib node from libs list */
		while ((pnode = double_list_get_from_head(&plib->list_filter))) {
			free(pnode->pdata);
			pnode = NULL;
		} 
		double_list_free(&plib->list_filter);
	}
	/* check if the there rests statistic(s) that has not been unrigstered */
	if (0 != double_list_get_nodes_num(&plib->list_statistic)) {
		for (pnode=double_list_get_head(&plib->list_statistic); NULL!=pnode;
			 pnode=double_list_get_after(&plib->list_statistic, pnode)) {
			 /*
			aquire the write lock to make sure that there's no statistic 
			excuting threads in the auditors list
			*/
			pthread_rwlock_wrlock(&g_plugin_lock);
			double_list_remove(&g_list_statistic, 
				&((STATISTIC_NODE*)(pnode->pdata))->node_statistic);
			pthread_rwlock_unlock(&g_plugin_lock);
		}
		/* free lib's statistics list */
		while ((pnode = double_list_get_from_head(&plib->list_statistic))) {
			free(pnode->pdata);
			pnode = NULL;
		}
		double_list_free(&plib->list_statistic);
	}
	/* free the service reference of the plugin */
	if (0 != double_list_get_nodes_num(&plib->list_reference)) {
		for (pnode=double_list_get_head(&plib->list_reference); NULL!=pnode;
			pnode=double_list_get_after(&plib->list_reference, pnode)) {
			service_release(((SERVICE_NODE*)(pnode->pdata))->service_name,
							plib->file_name);
		}
		/* free the reference list */
		while ((pnode = double_list_get_from_head(&plib->list_reference))) {
			free(((SERVICE_NODE*)(pnode->pdata))->service_name);
			free(pnode->pdata);
			pnode = NULL;
		}
	}

	double_list_remove(&g_list_lib, &plib->node);
	
	/* notify the plugin that it has been unloaded */
	func = (PLUGIN_MAIN)plib->lib_main;
	func(PLUGIN_FREE, NULL);
	
	dlclose(plib->handle);
	free(plib);
	return PLUGIN_UNLOAD_OK;
}

/*
 *	  reload the plugin, just like first unload the library and then load it
 *
 *	  @param
 *		path	indicate the filename of plugin
 *	  @return
 *		PLUGIN_RELOAD_FAIL_EXCUTEMAIN	fail to execute the main in the plugin
 *		PLUGIN_RELOAD_FAIL_ALLOCNODE	malloc fail
 *		PLUGIN_RELOAD_NO_MAIN			the plugin does not have the entry 
 *										function
 *		PLUGIN_RELOAD_FAIL_OPEN			fail to open the plugin
 *		PLUGIN_RELOAD_NOT_FOUND			plugin not found
 *		PLUGIN_RELOAD_ERROR				reload error
 *		PLUGIN_RELOAD_OK				success
 */

int anti_spamming_reload_library(const char* path)
{
	char	old_path[256],	*ptr;
	DOUBLE_LIST_NODE		*pnode;
	int		retval;

	ptr		= strrchr(path, '/');
	if (NULL != ptr) {
		ptr++;
	} else {
		ptr = (char*)path;
	}

	/* first find the plugin node in lib list */
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode; 
			pnode=double_list_get_after(&g_list_lib, pnode)) {
		if (0 == strcmp(((SHARELIB*)(pnode->pdata))->file_name, ptr)) {
			break;
		}
	}	 
	if (NULL == pnode){
		return PLUGIN_RELOAD_NOT_FOUND;
	}

	strncpy(old_path, ((SHARELIB*)(pnode->pdata))->full_path, 255);
	retval	= anti_spamming_unload_library(path);

	switch (retval) {
	case PLUGIN_UNLOAD_OK:
		break;

	case PLUGIN_NOT_FOUND:
		return PLUGIN_RELOAD_NOT_FOUND;

	default:
		return PLUGIN_RELOAD_ERROR;
	}

	retval	= anti_spamming_load_library(old_path);

	switch (retval) {
	case PLUGIN_LOAD_OK:
		return PLUGIN_RELOAD_OK;

	case PLUGIN_FAIL_EXCUTEMAIN:
		return PLUGIN_RELOAD_FAIL_EXCUTEMAIN;
	case PLUGIN_FAIL_ALLOCNODE:
		return PLUGIN_RELOAD_FAIL_ALLOCNODE;
	case PLUGIN_NO_MAIN:
		return PLUGIN_RELOAD_NO_MAIN;
	case PLUGIN_FAIL_OPEN:
		return PLUGIN_RELOAD_FAIL_OPEN;
	default:
		return PLUGIN_RELOAD_ERROR;
	}

	/* never reach here */
	return PLUGIN_RELOAD_ERROR;
}
/*
 *	  let plugins' "judges" to judge wheter the mail is spamming
 *	  @param
 *		  reason [out]	   buffer for retrieving the reason when FALSE
 *		  length		   length of "reason" buffer 
 *	  @return
 *		  MESSAGE_ACCEPT	OK, it's not spam
 *		  MESSAGE_REJECT	it is spam
 *		  MESSAGE_RETRYING	it may be spam, need retry
 */
int anti_spamming_pass_judges(SMTP_CONTEXT* pcontext, char *reason, int length)
{
	ENVELOP_INFO *penvelop;
	CONNECTION *pconnection;
	DOUBLE_LIST_NODE *pnode;
	int context_ID, judge_result;

	penvelop = &pcontext->mail.envelop;
	pconnection = &pcontext->connection;
	context_ID	= pcontext - smtp_parser_get_contexts_list();
	/* acquire the read lock when to pass the judges */
	pthread_rwlock_rdlock(&g_plugin_lock);
	for (pnode=double_list_get_head(&g_list_judge); NULL!=pnode; 
		 pnode= double_list_get_after(&g_list_judge, pnode)) {
		anti_spamming_reset_envelop_files(penvelop);
		judge_result = ((JUDGE_NODE*)(pnode->pdata))->judge_func(context_ID,
			penvelop, pconnection, reason, length);
		if (MESSAGE_ACCEPT != judge_result &&
			MESSAGE_REJECT != judge_result &&
			MESSAGE_RETRYING != judge_result) {
			printf("[anti_spamming]: return value error in judge function "
				"%p!!!\n", ((JUDGE_NODE*)(pnode->pdata))->judge_func);
			continue;
		}
		if (MESSAGE_ACCEPT != judge_result) {
			pthread_rwlock_unlock(&g_plugin_lock);
			return judge_result;
		}
	}
	/* everything is OK */
	pthread_rwlock_unlock(&g_plugin_lock);
	return MESSAGE_ACCEPT;
}

/*
 *	  let plugins' auditors to judge wheter the mail is spamming
 *	  @param
 *		  pmail [in]	   some information about the mail
 *		  pconnection [in] some information about connection
 *		  reason [out]	   buffer for retieving the reason
 *		  length		   length of buffer "reason"
 *	  @return
 *		  MESSAGE_ACCEPT   OK, it's not spam
 *		  MESSAGE_REJECT   it is spam
 *		  MESSAGE_RETRYING it may be spam, need retry
 */
int anti_spamming_pass_auditors(SMTP_CONTEXT* pcontext, char *reason,
	int length)
{
	DOUBLE_LIST_NODE *pnode;
	MAIL_ENTITY entity;
	CONNECTION *pconnection;
	int context_ID, audit_result;

	context_ID = pcontext - smtp_parser_get_contexts_list();
	pconnection = &pcontext->connection;
	entity.penvelop = &pcontext->mail.envelop;
	entity.phead = &pcontext->mail.head;
	/* acquire the read lock when to pass the auditors */
	pthread_rwlock_rdlock(&g_plugin_lock);
	for (pnode=double_list_get_head(&g_list_auditor); NULL!=pnode; 
		 pnode= double_list_get_after(&g_list_auditor, pnode)) {
		anti_spamming_reset_envelop_files(&pcontext->mail.envelop);
		anti_spamming_reset_head_files(&pcontext->mail.head);
		audit_result = ((AUDITOR_NODE*)(pnode->pdata))->auditor_func(context_ID, 
			&entity, pconnection, reason, length);
		if (MESSAGE_ACCEPT != audit_result &&
			MESSAGE_REJECT != audit_result &&
			MESSAGE_RETRYING != audit_result) {
			printf("[anti_spamming]: return value error in auditor function "
				"%p!!!\n", ((AUDITOR_NODE*)(pnode->pdata))->auditor_func);
			continue;
		}
		if (MESSAGE_ACCEPT != audit_result) {
			pthread_rwlock_unlock(&g_plugin_lock);
			return audit_result;
		}
	}
	/* everything is OK */
	pthread_rwlock_unlock(&g_plugin_lock);
	return MESSAGE_ACCEPT;
}

/*
 *	  inform filters of a certain type that a block is now available or going 
 *	  to be free
 *	  @param
 *		  type					  indicate the type to filter
 *		  pcontext[in]			  context pointer for get context_ID
 *		  action				  ACTION_BLOCK_NEW or ACTION_BLOCK_FREE
 *		  block_ID				  indicate the ID of block
 */
void anti_spamming_inform_filters(const char *type, SMTP_CONTEXT *pcontext,
	int action, int block_ID)
{
	DOUBLE_LIST_NODE *pnode;
	TYPE_NODE		 *ptype;
	MAIL_BLOCK		 block_info;
	char			 tmp_buff[256];
	int				 context_ID;
	char			 all_type = '\0';

	if (255 < strlen(type)) {
		return;
	}
	context_ID	= pcontext - smtp_parser_get_contexts_list();
	memset(&block_info, 0, sizeof(MAIL_BLOCK));
	block_info.block_ID = block_ID;
	swap_string(tmp_buff, type);
	HX_strlower(tmp_buff);
	/* acquire the read lock when to pass the filters */
	pthread_rwlock_rdlock(&g_plugin_lock);
	/* an empty string is reserved for all types, first find in all type list */
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, &all_type);
	if (NULL != ptype) {
		for (pnode=double_list_get_head(&ptype->list); NULL!=pnode;
			 pnode=double_list_get_after(&ptype->list, pnode)) {
			((FILTER_NODE*)(pnode->pdata))->filter_func(
					 action, context_ID, &block_info, NULL, 0);
		}
	}
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, tmp_buff);
	/* if the type is not found in type list return OK */
	if (NULL == ptype) {
		pthread_rwlock_unlock(&g_plugin_lock);
		return;
	}
	for (pnode=double_list_get_head(&ptype->list); NULL!=pnode;
		 pnode=double_list_get_after(&ptype->list, pnode)) {
		((FILTER_NODE*)(pnode->pdata))->filter_func(
				 action, context_ID, &block_info, NULL, 0);
	}
	pthread_rwlock_unlock(&g_plugin_lock);
	return;
}

/*
 *	  let filters of "type" judge whether it is spamming
 *	  @param
 *		  type					  indicate the type to filter
 *		  context_ID			  indicate the ID of context
 *		  pblock				  indicate the block information
 *		  reason[out]			  reason when fail to pass
 *		  length				  length of reason buffer
 */
int anti_spamming_pass_filters(const char* type, SMTP_CONTEXT* pcontext, 
	MAIL_BLOCK *pblock, char *reason, int length)
{
	DOUBLE_LIST_NODE *pnode;
	TYPE_NODE		 *ptype;
	char			 tmp_buff[256];
	int				 result;
	int				 context_ID;
	char			 all_type = '\0';
	
	if (255 < strlen(type)) {
		return MESSAGE_REJECT;
	}
	context_ID	= pcontext - smtp_parser_get_contexts_list();
	swap_string(tmp_buff, type);
	HX_strlower(tmp_buff);
	/* acquire the read lock when to pass the filters */
	pthread_rwlock_rdlock(&g_plugin_lock);
	/* an empty string is reserved for all types, first find in all type list */
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, &all_type);
	if (NULL != ptype) {
		for (pnode=double_list_get_head(&ptype->list); NULL!=pnode;
			 pnode=double_list_get_after(&ptype->list, pnode)) {

			mem_file_seek(pblock->fp_mime_info, MEM_FILE_READ_PTR, 0,
				MEM_FILE_SEEK_BEGIN);
			anti_spamming_reset_envelop_files(&pcontext->mail.envelop);
			anti_spamming_reset_head_files(&pcontext->mail.head);
		   
			result = ((FILTER_NODE*)(pnode->pdata))->filter_func(
				   ACTION_BLOCK_PROCESSING, context_ID, pblock, reason, length);
			if (MESSAGE_ACCEPT != result &&
				MESSAGE_REJECT != result &&
				MESSAGE_RETRYING != result) {
				printf("[anti_spamming]: return value error in filter function "
					"%p!!!\n", ((FILTER_NODE*)(pnode->pdata))->filter_func);
				continue;
			}
			if (MESSAGE_ACCEPT != result) {
				pthread_rwlock_unlock(&g_plugin_lock);
				return result;
			}
		}
	}
	/* find then in the type corresponding list */
	ptype = (TYPE_NODE*)str_hash_query(g_hash_type, tmp_buff);
	/* if the type is not found in type list return OK */
	if (NULL == ptype) {
		pthread_rwlock_unlock(&g_plugin_lock);
		return MESSAGE_ACCEPT;
	}
	for (pnode=double_list_get_head(&ptype->list); NULL!=pnode;
		 pnode=double_list_get_after(&ptype->list, pnode)) {
		mem_file_seek(pblock->fp_mime_info, MEM_FILE_READ_PTR, 0, 
					  MEM_FILE_SEEK_BEGIN);
		anti_spamming_reset_envelop_files(&pcontext->mail.envelop);
		anti_spamming_reset_head_files(&pcontext->mail.head);
		result = ((FILTER_NODE*)(pnode->pdata))->filter_func(
				 ACTION_BLOCK_PROCESSING, context_ID, pblock, reason, length);
		if (MESSAGE_ACCEPT != result &&
			MESSAGE_REJECT != result &&
			MESSAGE_RETRYING != result) {
			printf("[anti_spamming]: return value error in filter function "
				"%p!!!\n", ((FILTER_NODE*)(pnode->pdata))->filter_func);
			continue;
		}
		if (MESSAGE_ACCEPT != result) {
			pthread_rwlock_unlock(&g_plugin_lock);
			return result;
		}
	}
	pthread_rwlock_unlock(&g_plugin_lock);
	return MESSAGE_ACCEPT;
}

/*
 *	  let plugins' statistics to judge wether the mail is spamming
 *	  @param
 *		  pmail [in]	   some information about the mail
 *		  pconnection [in] some information about connection
 *		  reason [out]	   buffer for retieving the reason
 *		  length		   length of buffer "reason"
 *	  @return
 *		  MESSAGE_ACCEPT	OK, it's not spam
 *		  MESSAGE_REJECT	it is spam
 *		  MESSAGE_RETRYING	it may be spam, need retry
 */
int anti_spamming_pass_statistics(SMTP_CONTEXT* pcontext, char *reason,
	int length)
{
	DOUBLE_LIST_NODE *pnode;
	CONNECTION *pconnection;
	MAIL_WHOLE entity;
	int context_ID, statistic_result;

	context_ID = pcontext - smtp_parser_get_contexts_list();
	pconnection = &pcontext->connection;
	entity.penvelop = &pcontext->mail.envelop;
	entity.phead = &pcontext->mail.head;
	entity.pbody = &pcontext->mail.body;
	/* acquire the read lock when to pass the statistics */
	pthread_rwlock_rdlock(&g_plugin_lock);
	for (pnode=double_list_get_head(&g_list_statistic); NULL!=pnode; 
		 pnode= double_list_get_after(&g_list_statistic, pnode)) {
		anti_spamming_reset_envelop_files(&pcontext->mail.envelop);
		anti_spamming_reset_head_files(&pcontext->mail.head);
		anti_spamming_reset_body_files(&pcontext->mail.body);
		statistic_result = ((STATISTIC_NODE*)(pnode->pdata))->statistic_func(
			context_ID, &entity, pconnection, reason, length);
		if (MESSAGE_ACCEPT != statistic_result &&
			MESSAGE_REJECT != statistic_result &&
			MESSAGE_RETRYING != statistic_result) {
			printf("[anti_spamming]: return value error in statistic function "
				"%p!!!\n", ((STATISTIC_NODE*)(pnode->pdata))->statistic_func);
			continue;
		}
		if (MESSAGE_ACCEPT != statistic_result) {
			pthread_rwlock_unlock(&g_plugin_lock);
			return statistic_result;
		}
	}
	/* everything is OK */
	pthread_rwlock_unlock(&g_plugin_lock);
	return MESSAGE_ACCEPT;
}

/*
 *	  talk to a certain plugin
 *	  @param
 *		  argc		   indicate the number in argument list
 *		  argv [in]	   argument list
 *		  result [out] buffer for retriving result text
 *		  length	   indicate the buffer length of "result"
 *	  @return
 *		  PLUGIN_TALK_OK	found plugin
 *		  PLUGIN_NO_FILE	plug in not in list
 *		  PLUGIN_NO_TALK	plug has not registered talk function
 */	   
int anti_spamming_console_talk(int argc, char** argv, char *result, int length)
{
	DOUBLE_LIST_NODE *pnode;
	SHARELIB *plib;

	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
		plib = (SHARELIB*)(pnode->pdata);
		if (0 == strncmp(plib->file_name, argv[0], 256)) {
			if (NULL != plib->talk_main) {
				plib->talk_main(argc, argv, result, length);
				return PLUGIN_TALK_OK;
			} else {
				return PLUGIN_NO_TALK;
			}
		}
	}
	return PLUGIN_NO_FILE;
}

/*
 *	  stop the anti-spamming module
 *	  @param
 *		   0	success
 *		  <>0	fail
 */
int anti_spamming_stop()
{
	DOUBLE_LIST_NODE *pnode;
	VSTACK stack;
	LIB_BUFFER *pallocator;

	pallocator = vstack_allocator_init(256, 1024, FALSE);
	if (NULL == pallocator) {
		debug_info("[anti_spamming]: fail to init allocator for stack in" 
				"anti_spamming_stop\n");
		return -1;
	}
	vstack_init(&stack, pallocator, 256, 1024);
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
		vstack_push(&stack, ((SHARELIB*)(pnode->pdata))->file_name);
	}
	while (FALSE == vstack_is_empty(&stack)) {
		anti_spamming_unload_library(vstack_get_top(&stack));
		vstack_pop(&stack);
	}
	vstack_free(&stack);
	vstack_allocator_free(pallocator);
	double_list_free(&g_list_lib);
	str_hash_free(g_hash_type);
	double_list_free(&g_list_auditor);
	double_list_free(&g_list_judge);
	pthread_rwlock_destroy(&g_plugin_lock);
	return 0;
}


/*
 *	  anti-spamming modile's destruct function
 */
void anti_spamming_free()
{
	g_init_path[0] = '\0';
	g_plugin_names = NULL;
}

/*
 *	  register the talk function
 *	  @param
 *		  talk	  function for talking
 *	  @return
 *		  TRUE	  ok to register
 *		  FALSE	  fail to register
 */
static BOOL anti_spamming_register_talk(TALK_MAIN talk)
{
	if(NULL == g_cur_lib) {
		return FALSE;
	}
	g_cur_lib->talk_main = talk;
	return TRUE;
}

/*
 *	unregister the talk function
 *	@param
 *		talk	function for talking
 *	@return
 *		TRUE	ok to unregister
 *		FALSE	fail to unregister
 */
static BOOL anti_spamming_unregister_talk(TALK_MAIN talk)
{
	DOUBLE_LIST_NODE *pnode;
	SHARELIB	*plib;
	
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
		plib = (SHARELIB*)(pnode->pdata);
		if (plib->talk_main == talk) {
			plib->talk_main = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

/*
 *	  get version of services
 *	  @return
 *		  services version
 */
static int anti_spamming_getversion()
{
	return SERVICE_VERSION;
}

/*
 *	  get services
 *	  @param
 *		  service	 name of service
 *	  @return
 *		  address of function
 */
static void* anti_spamming_queryservice(char *service)
{
	DOUBLE_LIST_NODE *pnode;
	SERVICE_NODE	 *pservice;
	void			 *ret_addr;
	
	if (NULL == g_cur_lib) {
		return NULL;
	}
	if (strcmp(service, "register_filter") == 0) {
		return anti_spamming_register_filter;
	}
	if (strcmp(service, "unregister_filter") == 0) {
		return anti_spamming_unregister_filter;
	}
	if (strcmp(service, "register_auditor") == 0) {
		return anti_spamming_register_auditor;
	}
	if (strcmp(service, "unregister_auditor") == 0) {
		return anti_spamming_unregister_auditor;
	}
	if (strcmp(service, "register_judge") == 0) {
		return anti_spamming_register_judge;
	}
	if (strcmp(service, "unregister_judge") == 0) {
		return anti_spamming_unregister_judge;
	}
	if (strcmp(service, "register_statistic") == 0) {
		return anti_spamming_register_statistic;
	}
	if (strcmp(service, "unregister_statistic") == 0) {
		return anti_spamming_unregister_statistic;
	}
	if (strcmp(service, "register_talk") == 0) {
		return anti_spamming_register_talk;
	}
	if (strcmp(service, "unregister_talk") == 0) {
		return anti_spamming_unregister_talk;
	}
	if (strcmp(service, "get_connection") == 0) {
		return get_connection_by_id;
	}
	if (strcmp(service, "get_mail_entity") == 0) {
		return get_mail_entity_by_id;
	}
	if (strcmp(service, "set_extra_value") == 0) {
		return anti_spamming_set_extra_value;
	}
	if (strcmp(service, "mark_context_spam") == 0) {
		return anti_spamming_mark_context_spam;
	}
	if (strcmp(service, "is_need_auth") == 0) {
		return anti_spamming_is_need_auth;
	}
	if (strcmp(service, "is_domainlist_valid") == 0) {
		return anti_spamming_is_domainlist_valid;
	}
	if (strcmp(service, "get_default_domain") == 0) {
		return anti_spamming_get_default_domain;
	}
	if (strcmp(service, "get_plugin_name") == 0) {
		return anti_spamming_get_plugin_name;
	}
	if (strcmp(service, "get_config_path") == 0) {
		return anti_spamming_get_config_path;
	}
	if (strcmp(service, "get_data_path") == 0) {
		return anti_spamming_get_data_path;
	}
	if (strcmp(service, "get_context_num") == 0) {
		return anti_spamming_get_context_num;
	}
	/* check if already exists in the reference list */
	for (pnode=double_list_get_head(&g_cur_lib->list_reference); NULL!=pnode;
		 pnode=double_list_get_after(&g_cur_lib->list_reference, pnode)) {
		pservice =	(SERVICE_NODE*)(pnode->pdata);
		if (0 == strcmp(service, pservice->service_name)) {
			return pservice->service_addr;
		}
	}
	ret_addr = service_query(service, g_cur_lib->file_name);
	if (NULL == ret_addr) {
		return NULL;
	}
	pservice = malloc(sizeof(SERVICE_NODE));
	if (NULL == pservice) {
		debug_info("[anti-spamming]: fail to allocate memory for service node");
		service_release(service, g_cur_lib->file_name);
		return NULL;
	}
	pservice->service_name = malloc(strlen(service) + 1);
	if (NULL == pservice->service_name) {
		debug_info("[anti-spamming]: fail to allocate memory for service name");
		service_release(service, g_cur_lib->file_name);
		free(pservice);
		return NULL;

	}
	strcpy(pservice->service_name, service);
	pservice->node.pdata = pservice;
	pservice->service_addr = ret_addr;
	double_list_append_as_tail(&g_cur_lib->list_reference, &pservice->node);
	return ret_addr;
}

static const char* anti_spamming_get_default_domain()
{
	return resource_get_string("DEFAULT_DOMAIN");
}

static const char* anti_spamming_get_plugin_name()
{
	if (NULL == g_cur_lib) {
		return NULL;
	}
	if (strncmp(g_cur_lib->file_name, "libmtapas_", 10) == 0)
		return g_cur_lib->file_name + 10;
	return g_cur_lib->file_name;
}

static const char* anti_spamming_get_config_path()
{
	const char *ret_value = resource_get_string("CONFIG_FILE_PATH");
	if (NULL == ret_value) {
		ret_value = "../config";
	}
	return ret_value;
}

static const char *anti_spamming_get_data_path()
{
	const char *ret_value = resource_get_string("DATA_FILE_PATH");
	if (NULL == ret_value) {
		ret_value = "../data";
	}
	return ret_value;
}

static int anti_spamming_get_context_num()
{
	return contexts_pool_get_param(MAX_CONTEXTS_NUM);
}

static BOOL anti_spamming_is_need_auth()
{
	if (FALSE == smtp_parser_get_param(SMTP_NEED_AUTH)) {
		return FALSE;
	}
	return TRUE;
}

static BOOL anti_spamming_is_domainlist_valid()
{
	return smtp_parser_domainlist_valid();
}

static BOOL anti_spamming_set_extra_value(int context_ID, char* tag, char* pval)
{
	SMTP_CONTEXT*	pcontext;

	pcontext	= smtp_parser_get_contexts_list();
	pcontext	= pcontext	+ context_ID;
	return smtp_parser_set_extra_value(pcontext, tag, pval);
}

static void anti_spamming_mark_context_spam(int context_ID)
{
	SMTP_CONTEXT*	pcontext;

	pcontext	= smtp_parser_get_contexts_list();
	pcontext	= pcontext	+ context_ID;
	pcontext->is_spam = TRUE;
}

void anti_spamming_enum_plugins(ENUM_PLUGINS enum_func)
{
	DOUBLE_LIST_NODE *pnode;

	if (NULL == enum_func) {
		return;
	}
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode;
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
		enum_func(((SHARELIB*)(pnode->pdata))->file_name);
	}
}

static MAIL_ENTITY get_mail_entity_by_id(int context_ID)
{
	MAIL_ENTITY entry;
	SMTP_CONTEXT*	pcontext;
	pcontext	= smtp_parser_get_contexts_list();
	pcontext	= pcontext + context_ID;
	entry.phead = &pcontext->mail.head;
	entry.penvelop	= &pcontext->mail.envelop;
	return entry;
}

static CONNECTION* get_connection_by_id(int context_ID)
{
	SMTP_CONTEXT*	pcontext;
	pcontext	= smtp_parser_get_contexts_list();
	pcontext	= pcontext + context_ID;

	return &pcontext->connection;
}

static void anti_spamming_reset_envelop_files(ENVELOP_INFO *penvelop)
{
	 mem_file_seek(&penvelop->f_rcpt_to, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
}

static void anti_spamming_reset_head_files(MAIL_HEAD *phead)
{
	 mem_file_seek(&phead->f_mime_from, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_mime_to, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_mime_cc, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_mime_delivered_to, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_xmailer, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_subject, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_content_type, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
	 mem_file_seek(&phead->f_others, MEM_FILE_READ_PTR, 0,
		 MEM_FILE_SEEK_BEGIN);
}

static void anti_spamming_reset_body_files(MAIL_BODY *pbody)
{
	 mem_file_seek(&pbody->f_mail_parts, MEM_FILE_READ_PTR, 0,
				   MEM_FILE_SEEK_BEGIN);
}


void anti_spamming_threads_event_proc(int action)
{
	DOUBLE_LIST_NODE *pnode;
	PLUGIN_MAIN func;
	SHARELIB *plib;
	
	for (pnode=double_list_get_head(&g_list_lib); NULL!=pnode; 
		 pnode=double_list_get_after(&g_list_lib, pnode)) {
		plib = (SHARELIB*)(pnode->pdata);
		func = (PLUGIN_MAIN)plib->lib_main;
		func(action, NULL);
	}
}


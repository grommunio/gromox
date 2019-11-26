#include "util.h"
#include "mail_func.h"
#include "system_log.h"
#include "cmd_parser.h"
#include "classify_engine.h"
#include "mysql_pool.h"
#include "mem_file.h"
#include "double_list.h"
#include "sphinxclient.h"
#include "mjson.h"
#include <iconv.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>


#define MJSON_ALLOC_NUM			3000

#define MAX_DIGLEN				256*1024

#define VDIR_PER_PARTITION		200

#define SUBDIR_PER_VDIR			250



enum {
	CONDITION_UNIT,
	CONDITION_SENDER,
	CONDITION_RCPT,
	CONDITION_ATTACHED,
	CONDITION_PRIORITY,
	CONDITION_ATIME,
	CONDITION_RTIME,
	CONDITION_CTIME,
	CONDITION_FROM,
	CONDITION_TO,
	CONDITION_CC,
	CONDITION_SUBJECT,
	CONDITION_CONTENT,
	CONDITION_FILENAME,
	CONDITION_SIZE,
	CONDITION_HEADER,
	CONDITION_REFERENCE,
	CONDITION_ID
};


typedef struct _RESULT_NODE {
	DOUBLE_LIST_NODE node;
	uint64_t mail_id;
} RESULT_NODE;

typedef struct _CONDITION_NODE {
	DOUBLE_LIST_NODE node;
	DOUBLE_LIST_NODE node_temp;
	int condition;
	void *pstatment;
} CONDITION_NODE;

static char g_storage_path[128];

static char g_sphinx_host[128];

static int g_sphinx_port;

static long g_tmptbl_size;

static int g_valid_days;

static LIB_BUFFER *g_alloc_mjson;      /* mjson allocator */

static DOUBLE_LIST g_dir_list;
static DOUBLE_LIST_NODE *g_list_tail;
static uint64_t g_turn_num;
static pthread_mutex_t g_list_lock;

static DOUBLE_LIST* classify_engine_cl_build(int argc, char **argv);

static void classify_engine_cl_destroy(DOUBLE_LIST *pclist);

static DOUBLE_LIST* classify_engine_cl_match(const char *charset,
	DOUBLE_LIST *pclist);

static BOOL classify_engine_cl_search_head(const char *charset,
	const char *file_path, const char *tag, const char *value);

static BOOL classify_engine_cl_check_numstring(const char *string);

static char* classify_engine_cl_decode_mime(const char *charset,
	const char *mime_string);

static void classify_engine_encode_squote(const char *in, char *out);

static void classify_engine_escase_string(const char *in, char *out);

static void classify_engine_enum_mime(MJSON_MIME *pmime, int *pattach);

static DOUBLE_LIST* classify_engine_sphinx_search(DOUBLE_LIST *pclist);

static void classify_engine_calculate_path(char *path);

static BOOL classify_engine_create_results0(MYSQL *pmysql, uint64_t ref_id);

static void classify_engine_destroy_results0(MYSQL *pmysql);

static BOOL classify_engine_create_results1(MYSQL *pmysql);

static void classify_engine_destroy_results1(MYSQL *pmysql);

void classify_engine_init(char *storage_path, int valid_days,
	char *sphinx_host, int sphinx_port, long tmptbl_size)
{
	strcpy(g_storage_path, storage_path);
	strcpy(g_sphinx_host, sphinx_host);
	g_sphinx_port = sphinx_port;
	g_tmptbl_size = tmptbl_size;
	g_valid_days = valid_days;
	double_list_init(&g_dir_list);
	pthread_mutex_init(&g_list_lock, NULL);
}

static int classify_engine_asrch(int argc, char **argv, int sockd)
{
	int offset;
	DOUBLE_LIST *pclist;
	DOUBLE_LIST *presult;
	RESULT_NODE *presnode;
	DOUBLE_LIST_NODE *pnode;
	char list_buff[256*1024];
	

	if (argc < 4 || strlen(argv[2]) > 63) {
        return 1;
	}
	
	pclist = classify_engine_cl_build(argc - 2, &argv[2]);
	if (NULL == pclist) {
		return 1;
	}

	presult = classify_engine_cl_match(argv[1], pclist);

	classify_engine_cl_destroy(pclist);

	if (NULL == presult) {
		return 2;	
	}

    offset = sprintf(list_buff, "TRUE %d\r\n",
				double_list_get_nodes_num(presult));
	while ((pnode = double_list_get_from_head(presult)) != NULL) {
		presnode = (RESULT_NODE*)pnode->pdata;
        offset += snprintf(list_buff + offset, 256*1024 - offset,
					"%lld\r\n", presnode->mail_id);
		if (offset > 256*1023) {
			write(sockd, list_buff, offset);
			offset = 0;
		}
		free(presnode);
    }

	double_list_free(presult);
	free(presult);


	if (offset > 0) {
		write(sockd, list_buff, offset);
	}
	return 0;
}


static int classify_engine_ainst(int argc, char **argv, int sockd)
{
	int i;
	int offset;
	int attach;
	int msg_len;
	int tmp_len;
	size_t size;
	char *prcpt;
	char *punit;
	char *punit1;
	int last_pos;
	int priority;
	BOOL b_found;
	char *pdomain;
	char *pdomain1;
	MYSQL_ROW myrow;
	MJSON temp_mjson;
	uint64_t mail_id;
	uint64_t temp_id;
	struct tm tmp_tm;
	time_t temp_time;
	size_t decode_len;
	MYSQL_RES *pmyres;
	char temp_path[128];
	char tmp_msgid[256];
	char archived_time[32];
	char received_time[32];
	char composed_time[32];
	char temp_string[1024];
	char reference_buff[1024];
	char envelop_buff[MAX_DIGLEN];
	char sql_string[2*MAX_DIGLEN];
	MYSQL_CONNECTION *pconnection;
	
	
	time(&temp_time);
	
	if (3 != argc || strlen(argv[2]) > MAX_DIGLEN) {
        return 1;
	}
	
	if (0 != decode64(argv[1], strlen(argv[1]), envelop_buff, &decode_len)) {
		return 1;	
	}
	
	envelop_buff[decode_len] = '\0';
	
	mjson_init(&temp_mjson, g_alloc_mjson);
	if (TRUE == mjson_retrieve(&temp_mjson, argv[2], strlen(argv[2]), NULL)) {
		attach = 0;
		mjson_enum_mime(&temp_mjson, (MJSON_MIME_ENUM)classify_engine_enum_mime, &attach);
	} else {
		mjson_free(&temp_mjson);
		return 1;
	}
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	localtime_r(&temp_time, &tmp_tm);
	strftime(archived_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
	
	if (TRUE == parse_rfc822_timestamp(mjson_get_mail_received(&temp_mjson),
		&temp_time)) {
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		localtime_r(&temp_time, &tmp_tm);
		strftime(received_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
	} else {
		received_time[0] = '\0';
	}
	
	if (TRUE == parse_rfc822_timestamp(mjson_get_mail_date(&temp_mjson),
		&temp_time)) {
		memset(&tmp_tm, 0, sizeof(tmp_tm));
		localtime_r(&temp_time, &tmp_tm);
		strftime(composed_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
	} else {
		composed_time[0] = '\0';
	}
	
	strncpy(temp_string, mjson_get_mail_messageid(&temp_mjson), 128);
	msg_len = strlen(temp_string);
	if ('<' == temp_string[0] && '>' == temp_string[msg_len - 1]) {
		temp_string[msg_len - 1] = '\0';
		classify_engine_encode_squote(temp_string + 1, tmp_msgid);
	} else {
		classify_engine_encode_squote(temp_string, tmp_msgid);
	}
	
	strncpy(reference_buff, mjson_get_mail_references(&temp_mjson), 1024);
	
	priority = mjson_get_mail_priority(&temp_mjson);
	
	size = mjson_get_mail_length(&temp_mjson);
	
	mjson_free(&temp_mjson);
	
	classify_engine_calculate_path(temp_path);

	classify_engine_encode_squote(temp_path, temp_string);
	
	offset = snprintf(sql_string, 1024, "INSERT INTO mails (path, "
		"priority, attach, archived, received, composed, msgid, "
		"size, digest) VALUES ('%s', %d, %d, '%s', '%s', "
		"'%s', '%s', '%ld', '", temp_string, priority, attach,
		archived_time, received_time, composed_time, tmp_msgid, size);

	classify_engine_encode_squote(argv[2], sql_string + offset);
	strcat(sql_string, "')");
	
	pconnection = mysql_pool_get_connection();
	if (NULL == pconnection) {
		return 2;
	}
	if (0 != mysql_query(pconnection->pmysql, sql_string)) {
		mysql_pool_put_connection(pconnection, FALSE);
		return 2;
	}
	mail_id = mysql_insert_id(pconnection->pmysql);

	pdomain = strchr(envelop_buff, '@');
	if (NULL != pdomain) {
		classify_engine_encode_squote(pdomain + 1, temp_string);
		snprintf(sql_string, 1024, "INSERT INTO envelopes "
			"(unit, mail_id, bound) VALUES ('%s', %lld, 0)",
			temp_string, mail_id);
		if (0 != mysql_query(pconnection->pmysql, sql_string)) {
			mysql_pool_put_connection(pconnection, FALSE);
			return 2;
		}
	}
	
	classify_engine_encode_squote(envelop_buff, temp_string);
	snprintf(sql_string, 1024, "INSERT INTO envelopes "
		"(unit, mail_id, bound) VALUES ('%s', %lld, 0)",
		temp_string, mail_id);
	if (0 != mysql_query(pconnection->pmysql, sql_string)) {
		mysql_pool_put_connection(pconnection, FALSE);
		return 2;
	}
	
	prcpt = envelop_buff + strlen(envelop_buff) + 1;
	punit = prcpt;
	
	while ('\0' != *punit && punit - envelop_buff < decode_len) {
		pdomain = strchr(punit, '@');
		if (NULL != pdomain) {
			punit1 = prcpt;
			b_found = FALSE;
			while (punit1 < punit) {
				pdomain1 = strchr(punit1, '@');
				if (0 == strcasecmp(pdomain1, pdomain)) {
					b_found = TRUE;
					break;
				}
				punit1 += strlen(punit1) + 1;
			}
			
			if (FALSE == b_found) {
				classify_engine_encode_squote(pdomain + 1, temp_string);
				snprintf(sql_string, 1024, "INSERT INTO envelopes "
					"(unit, mail_id, bound) VALUES ('%s', %lld, 1)",
					temp_string, mail_id);
				if (0 != mysql_query(pconnection->pmysql, sql_string)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return 2;
				}
			}
		}
		
		punit1 = prcpt;
		b_found = FALSE;
		while (punit1 < punit) {
			if (0 == strcasecmp(punit1, punit)) {
				b_found = TRUE;
				break;
			}
			punit1 += strlen(punit1) + 1;
		}
		
		if (FALSE == b_found) {
			classify_engine_encode_squote(punit, temp_string);
			snprintf(sql_string, 1024, "INSERT INTO envelopes "
				"(unit, mail_id, bound) VALUES ('%s', %lld, 1)",
				temp_string, mail_id);
			if (0 != mysql_query(pconnection->pmysql, sql_string)) {
				mysql_pool_put_connection(pconnection, FALSE);
				return 2;
			}
		}
		punit += strlen(punit) + 1;
	}

	tmp_len = strlen(reference_buff);
	if (tmp_len > 0) {
		reference_buff[tmp_len] = ' ';
		last_pos = 0;
		for (i=0; i<=tmp_len; i++) {
			if (';' == reference_buff[i] ||
				',' == reference_buff[i] ||
				' ' == reference_buff[i]) {
				reference_buff[i] = '\0';
				strncpy(tmp_msgid, reference_buff + last_pos, 128);
				ltrim_string(tmp_msgid);
				rtrim_string(tmp_msgid);
				if ('\0' == tmp_msgid[0] || 0 == strcmp(tmp_msgid, "<>")) {
					last_pos = i + 1;
					continue;
				}
				msg_len = strlen(tmp_msgid);
				if ('<' == tmp_msgid[0] && '>' == tmp_msgid[ msg_len - 1]) {
					tmp_msgid[msg_len - 1] = '\0';
					classify_engine_encode_squote(tmp_msgid + 1, temp_string);
				} else {
					classify_engine_encode_squote(tmp_msgid, temp_string);
				}
				snprintf(sql_string, 1024, "SELECT id FROM mails "
					"WHERE msgid='%s'", temp_string);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return 2;
				}
				if (mysql_num_rows(pmyres) > 0) {
					myrow = mysql_fetch_row(pmyres);
					temp_id = atoll(myrow[0]);
					mysql_free_result(pmyres);
					snprintf(sql_string, 1024, "INSERT INTO refs "
						"(ref_id, mail_id) VALUES (%lld, %lld)",
						mail_id, temp_id);
					mysql_query(pconnection->pmysql, sql_string);
				} else {
					mysql_free_result(pmyres);
				}
				last_pos = i + 1;
			}

		}

	}

	mysql_pool_put_connection(pconnection, TRUE);

	offset = sprintf(temp_string, "TRUE %lld %s\r\n", mail_id, temp_path);

	write(sockd, temp_string, offset);
	return 0;
}


static int classify_engine_amtch(int argc, char **argv, int sockd)
{
	int length;
	MYSQL_ROW myrow;
	uint64_t mail_id;
	MYSQL_RES *pmyres;
	char sql_string[1024];
	MYSQL_CONNECTION *pconnection;
	char temp_buff[MAX_DIGLEN + 1024];

	if (2 != argc) {
		return 1;
	}

	mail_id = atoll(argv[1]);
	if (mail_id <= 0) {
		return 1;
	}

	sprintf(sql_string, "SELECT path, digest FROM mails "
		"WHERE id=%lld", mail_id);
	pconnection = mysql_pool_get_connection();
	if (NULL == pconnection) {
		return 2;
	}
	if (0 != mysql_query(pconnection->pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
		mysql_pool_put_connection(pconnection, FALSE);
		return 2;
	}
	mysql_pool_put_connection(pconnection, TRUE);
	
	if (mysql_num_rows(pmyres) != 1) {
		mysql_free_result(pmyres);
		return 3;
	}

	myrow = mysql_fetch_row(pmyres);

	length = snprintf(temp_buff, sizeof(temp_buff),
				"TRUE %s %s\r\n", myrow[0], myrow[1]);
	mysql_free_result(pmyres);
	write(sockd, temp_buff, length);
	return 0;
}

static int classify_engine_adele(int argc, char **argv, int sockd)
{
	int i, offset;
	char sql_string[MAX_DIGLEN];
	MYSQL_CONNECTION *pconnection;


	if (argc < 2) {
		return 1;
	}

	offset = sprintf(sql_string, "DELETE FROM mails WHERE id IN (");
	for (i=1; i<argc; i++) {
		if (1 == i) {
			offset += snprintf(sql_string + offset, MAX_DIGLEN - offset,
						"%s", argv[1]);
		} else {
			offset += snprintf(sql_string + offset, MAX_DIGLEN - offset,
						",%s", argv[i]);
		}
	}

	offset += snprintf(sql_string + offset, MAX_DIGLEN - offset, ")");
	pconnection = mysql_pool_get_connection();
	if (NULL == pconnection) {
		return 2;
	}
	if (0 != mysql_query(pconnection->pmysql, sql_string)) {
		mysql_pool_put_connection(pconnection, FALSE);
		return 2;
	}
	mysql_pool_put_connection(pconnection, TRUE);
	write(sockd, "TRUE\r\n", 6);
	return 0;
}

static BOOL classify_engine_dinfo(int argc, char **argv, int sockd)
{
	int length;
	char buff[1024];

	length = snprintf(buff, 1024,
				"TRUE 2\r\n"
				"alive connection num             %d\r\n"
				"dead connection num              %d\r\n",
				mysql_pool_get_param(MYSQL_POOL_ALIVE_CONNECTION),
				mysql_pool_get_param(MYSQL_POOL_DEAD_CONNECTION));
	write(sockd, buff, length);
	return 0;

}

int classify_engine_run()
{
	DIR *dirp;
	struct dirent *direntp;
	DOUBLE_LIST_NODE *pnode;
	
	
	g_alloc_mjson = mjson_allocator_init(MJSON_ALLOC_NUM, TRUE);
	if (NULL == g_alloc_mjson) {
		return -1;
	}
	
	dirp = opendir(g_storage_path);
	if (NULL == dirp) {
		lib_buffer_free(g_alloc_mjson);
		g_alloc_mjson = NULL;
		printf("[classify_engine]: fail to open directory %s\n", g_storage_path);
		return -2;
	}
	
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;	
		}
		pnode = malloc(sizeof(DOUBLE_LIST_NODE));
		if (NULL == pnode) {
			continue;
		}
		pnode->pdata = strdup(direntp->d_name);
		if (NULL == pnode->pdata) {
			free(pnode);
			continue;
		}
		double_list_append_as_tail(&g_dir_list, pnode);
	}
	closedir(dirp);
	if (0 == double_list_get_nodes_num(&g_dir_list)) {
		printf("[classify_engine]: can not find sub-dir under %s\n", g_storage_path);
		while ((pnode = double_list_get_from_head(&g_dir_list)) != NULL) {
			free(pnode->pdata);
			free(pnode);
		}
		lib_buffer_free(g_alloc_mjson);
		g_alloc_mjson = NULL;
		return -3;
	}
	g_list_tail = double_list_get_tail(&g_dir_list);
	
	cmd_parser_register_command("A-INST", classify_engine_ainst);
	cmd_parser_register_command("A-MTCH", classify_engine_amtch);
	cmd_parser_register_command("A-SRCH", classify_engine_asrch);
	cmd_parser_register_command("A-DELE", classify_engine_adele);
	cmd_parser_register_command("D-INFO", classify_engine_dinfo);
	
	return 0;
}

int classify_engine_stop()
{
	DOUBLE_LIST_NODE *pnode;
	
	if (NULL != g_alloc_mjson) {
		lib_buffer_free(g_alloc_mjson);
		g_alloc_mjson = NULL;
	}
	
	while ((pnode = double_list_get_from_head(&g_dir_list)) != NULL) {
		free(pnode->pdata);
		free(pnode);
	}

	return 0;
}

void classify_engine_free()
{
	double_list_free(&g_dir_list);
	pthread_mutex_destroy(&g_list_lock);
}


static DOUBLE_LIST* classify_engine_cl_build(int argc, char **argv)
{
	int i, tmp_len;
	long temp_long;
	size_t decode_len;
	DOUBLE_LIST *pclist;
	uint64_t temp_uint64;
	CONDITION_NODE *pconnode;

	pclist = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST));
	if (NULL == pclist) {
		return NULL;
	}
	double_list_init(pclist);
	
	
	for (i=0; i<argc; i++) {
		pconnode = (CONDITION_NODE*)malloc(sizeof(CONDITION_NODE));
		if (NULL == pconnode) {
			classify_engine_cl_destroy(pclist);
			return NULL;
		}
		pconnode->node.pdata = pconnode;
		pconnode->node_temp.pdata = pconnode;
		if (0 == strcasecmp(argv[i], "UNIT")||
			0 == strcasecmp(argv[i], "SENDER") ||
			0 == strcasecmp(argv[i], "RCPT") ||
			0 == strcasecmp(argv[i], "FROM") ||
			0 == strcasecmp(argv[i], "TO") ||
			0 == strcasecmp(argv[i], "CC") ||
			0 == strcasecmp(argv[i], "SUBJECT") ||
			0 == strcasecmp(argv[i], "CONTENT") ||
			0 == strcasecmp(argv[i], "FILENAME")) { 
			if (i + 1 >= argc) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i], "UNIT")) {
				pconnode->condition = CONDITION_UNIT;
			} else if (0 == strcasecmp(argv[i], "SENDER")) {
				pconnode->condition = CONDITION_SENDER;
			} else if (0 == strcasecmp(argv[i], "RCPT")) {
				pconnode->condition = CONDITION_RCPT;
			} else if (0 == strcasecmp(argv[i], "FROM")) {
				pconnode->condition = CONDITION_FROM;
			} else if (0 == strcasecmp(argv[i], "TO")) {
				pconnode->condition = CONDITION_TO;
			} else if (0 == strcasecmp(argv[i], "CC")) {
				pconnode->condition = CONDITION_CC;
			} else if (0 == strcasecmp(argv[i], "SUBJECT")) {
				pconnode->condition = CONDITION_SUBJECT;
			} else if (0 == strcasecmp(argv[i], "CONTENT")) {
				pconnode->condition = CONDITION_CONTENT;
			} else if (0 == strcasecmp(argv[i], "FILENAME")) {
				pconnode->condition = CONDITION_FILENAME;
			}
			tmp_len = strlen(argv[i + 1]);
			pconnode->pstatment = malloc(tmp_len);
			if (NULL == pconnode->pstatment) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 != decode64(argv[i + 1], tmp_len,
				pconnode->pstatment, &decode_len)) {
				free(pconnode->pstatment);
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			((char*)pconnode->pstatment)[decode_len] = '\0';
			i ++;
		} else if (0 == strcasecmp(argv[i], "ATTACHED")) {
			if (i + 1 >= argc || (0 != strcasecmp(argv[i + 1], "YES") &&
				0 != strcasecmp(argv[i + 1], "NO"))) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			pconnode->condition = CONDITION_ATTACHED;
			if (0 == strcasecmp(argv[i + 1], "NO")) {
				pconnode->pstatment = NULL;
			} else {
				pconnode->pstatment = (void*)1;
			}
			i ++;
		} else if (0 == strcasecmp(argv[i], "PRIORITY")) {
			if (i + 1 >= argc || strlen(argv[i + 1]) != 1 ||
				!isdigit(argv[i + 1][0])) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			temp_long =  atoi(argv[i + 1]);
			if (temp_long <= 0 || temp_long > 5) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			pconnode->condition = CONDITION_PRIORITY;
			pconnode->pstatment = (void*)temp_long;
			i ++;
		} else if (0 == strcasecmp(argv[i], "ATIME") ||
			0 == strcasecmp(argv[i], "RTIME") ||
			0 == strcasecmp(argv[i], "CTIME")) {
			if (i + 2 >= argc || (0 != strcasecmp(argv[i + 1], "GE") &&
				0 != strcasecmp(argv[i + 1], "LE") &&
				FALSE == classify_engine_cl_check_numstring(argv[i + 1])) ||
				FALSE == classify_engine_cl_check_numstring(argv[i + 2])) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i], "ATIME")) {
				pconnode->condition = CONDITION_ATIME;
			} else if (0 == strcasecmp(argv[i], "RTIME")) {
				pconnode->condition = CONDITION_RTIME;
			} else if (0 == strcasecmp(argv[i], "CTIME")) {
				pconnode->condition = CONDITION_CTIME;
			}
			pconnode->pstatment = malloc(2*sizeof(time_t));
			if (NULL == pconnode->pstatment) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i + 1], "GE")) {
				((time_t*)pconnode->pstatment)[0] = atol(argv[i + 2]);
				((time_t*)pconnode->pstatment)[1] = -1;
			} else if (0 == strcasecmp(argv[i + 1], "LE")) {
				((time_t*)pconnode->pstatment)[0] = 0;
				((time_t*)pconnode->pstatment)[1] = atol(argv[i + 2]);
			} else {
				((time_t*)pconnode->pstatment)[0] = atol(argv[i + 1]);
				((time_t*)pconnode->pstatment)[1] = atol(argv[i + 2]);
				if (((time_t*)pconnode->pstatment)[0] >
					((time_t*)pconnode->pstatment)[1]) {
					temp_long = ((time_t*)pconnode->pstatment)[0];
					((time_t*)pconnode->pstatment)[0] =
						((time_t*)pconnode->pstatment)[1];
					((time_t*)pconnode->pstatment)[1] = temp_long;
				}
			}
			i += 2;
		} else if (0 == strcasecmp(argv[i], "SIZE") ||
			0 == strcasecmp(argv[i], "ID")) {
			if (i + 2 >= argc || (0 != strcasecmp(argv[i + 1], "GE") &&
				0 != strcasecmp(argv[i + 1], "LE") &&
				FALSE == classify_engine_cl_check_numstring(argv[i + 1])) ||
				FALSE == classify_engine_cl_check_numstring(argv[i + 2])) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i], "SIZE")) {
				pconnode->condition = CONDITION_SIZE;
			} else if (0 == strcasecmp(argv[i], "ID")) {
				pconnode->condition = CONDITION_ID;
			}
			pconnode->pstatment = malloc(2*sizeof(uint64_t));
			if (NULL == pconnode->pstatment) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 == strcasecmp(argv[i + 1], "GE")) {
				((uint64_t*)pconnode->pstatment)[0] = atoll(argv[i + 2]);
				((uint64_t*)pconnode->pstatment)[1] = -1;
			} else if (0 == strcasecmp(argv[i + 1], "LE")) {
				((uint64_t*)pconnode->pstatment)[0] = 0;
				((uint64_t*)pconnode->pstatment)[1] = atoll(argv[i + 2]);
			} else {
				((uint64_t*)pconnode->pstatment)[0] = atoll(argv[i + 1]);
				((uint64_t*)pconnode->pstatment)[1] = atoll(argv[i + 2]);
				if (((uint64_t*)pconnode->pstatment)[0] >
					((uint64_t*)pconnode->pstatment)[1]) {
					temp_uint64 = ((uint64_t*)pconnode->pstatment)[0];
					((uint64_t*)pconnode->pstatment)[0] =
						((uint64_t*)pconnode->pstatment)[1];
					((uint64_t*)pconnode->pstatment)[1] = temp_uint64;
				}
			}
			i += 2;
		} else if (0 == strcasecmp(argv[i], "HEADER")) {
			if (i + 2 >= argc) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			pconnode->condition = CONDITION_HEADER;
			pconnode->pstatment = malloc(2*sizeof(char*));
			if (NULL == pconnode->pstatment) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			i ++;

			tmp_len = strlen(argv[i]);
			((char**)pconnode->pstatment)[0] = malloc(tmp_len);
			if (NULL == ((char**)pconnode->pstatment)[0]) {
				free(pconnode->pstatment);
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 != decode64(argv[i], tmp_len,
				((char**)pconnode->pstatment)[0], &decode_len)) {
				free(((char**)pconnode->pstatment)[0]);
				free(pconnode->pstatment);
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			((char**)pconnode->pstatment)[0][decode_len] = '\0';
			i ++;

			tmp_len = strlen(argv[i]);
			((char**)pconnode->pstatment)[1] = malloc(tmp_len);
			if (NULL == ((char**)pconnode->pstatment)[1]) {
				free(((char**)pconnode->pstatment)[0]);
				free(pconnode->pstatment);
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			if (0 != decode64(argv[i], tmp_len,
				((char**)pconnode->pstatment)[1], &decode_len)) {
				free(((char**)pconnode->pstatment)[1]);
				free(((char**)pconnode->pstatment)[0]);
				free(pconnode->pstatment);
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			((char**)pconnode->pstatment)[1][decode_len] = '\0';
		} else if (0 == strcasecmp(argv[i], "REFERENCE")) {
			if (i + 1 >= argc) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			pconnode->condition = CONDITION_REFERENCE;
			pconnode->pstatment = malloc(sizeof(uint64_t));
			if (NULL == pconnode->pstatment) {
				free(pconnode);
				classify_engine_cl_destroy(pclist);
				return NULL;
			}
			*(uint64_t*)(pconnode->pstatment) = atoll(argv[i + 1]);
			i ++;
		} else {
			classify_engine_cl_destroy(pclist);
			return NULL;
		}
			
		double_list_append_as_tail(pclist, &pconnode->node);
	}
	return pclist;
}

static void classify_engine_cl_destroy(DOUBLE_LIST *pclist)
{
	DOUBLE_LIST_NODE *pnode;
	CONDITION_NODE *pconnode;

	
	while ((pnode = double_list_get_from_head(pclist)) != NULL) {
		pconnode = (CONDITION_NODE*)pnode->pdata;
		if (CONDITION_UNIT == pconnode->condition ||
			CONDITION_SENDER == pconnode->condition ||
			CONDITION_RCPT == pconnode->condition ||
			CONDITION_FROM == pconnode->condition ||
			CONDITION_TO == pconnode->condition ||
			CONDITION_CC == pconnode->condition ||
			CONDITION_SUBJECT == pconnode->condition ||
			CONDITION_CONTENT == pconnode->condition ||
			CONDITION_FILENAME == pconnode->condition ||
			CONDITION_REFERENCE == pconnode->condition ||
			CONDITION_ATIME == pconnode->condition ||
			CONDITION_RTIME == pconnode->condition ||
			CONDITION_CTIME == pconnode->condition ||
			CONDITION_SIZE == pconnode->condition ||
			CONDITION_ID == pconnode->condition) {
			free(pconnode->pstatment);
			pconnode->pstatment = NULL;
		} else if (CONDITION_HEADER == pconnode->condition) {
			free(((void**)pconnode->pstatment)[0]);
			free(((void**)pconnode->pstatment)[1]);
			free(pconnode->pstatment);
			pconnode->pstatment = NULL;
		}
		free(pconnode);
	}
	double_list_free(pclist);
	free(pclist);
}

static BOOL classify_engine_cl_search_head(const char *charset, const char *file_path,
	const char *tag, const char *value)
{
	FILE * fp;
	int tag_len;
	char *str_mime;
	BOOL stat_head;
	int head_offset;
	int offset, len;
	MIME_FIELD mime_field;
	char head_buff[64*1024];
	
	stat_head = FALSE;
	fp = fopen(file_path, "r");
	if (NULL == fp) {
		return FALSE;
	}
	
	head_offset = 0;
	while (NULL != fgets(head_buff + head_offset, 64*1024 - head_offset, fp)) {
		len = strlen(head_buff + head_offset);
		head_offset += len;
		
		if (head_offset >= 64*1024 - 1) {
			break;
		}
		
		if (2 == len && 0 == strcmp("\r\n", head_buff + head_offset - 2)) {
			stat_head = TRUE;
			break;
		}
	}
	
	fclose(fp);

	if (FALSE == stat_head) {
		return FALSE;
	}
	
	offset = 0;
	tag_len = strlen(tag);
	while ((len = parse_mime_field(head_buff + offset, head_offset - offset, &mime_field)) != 0) {
		offset += len;
		if (tag_len == mime_field.field_name_len &&
			0 == strncasecmp(tag, mime_field.field_name, tag_len)) {
				mime_field.field_value[mime_field.field_value_len] = '\0';
				str_mime = classify_engine_cl_decode_mime(charset, mime_field.field_value);
				if (NULL != str_mime) {
					if (NULL != search_string(str_mime, value, strlen(str_mime))) {
						free(str_mime);
						return TRUE;
					}
					free(str_mime);
				}
			}
	}
	
	return FALSE;
}

static char* classify_engine_cl_to_utf8(const char *charset, const char *string)
{
	int length;
	iconv_t conv_id;
	char *ret_string;
	char *pin, *pout;
	size_t in_len, out_len;

	
	if (0 == strcasecmp(charset, "UTF-8") ||
		0 == strcasecmp(charset, "US-ASCII")) {
		return strdup(string);
	}
	
	length = strlen(string) + 1;
	ret_string = malloc(2*length);
	if (NULL == ret_string) {
		return NULL;
	}
	conv_id = iconv_open("UTF-8", charset);
	if ((iconv_t)-1 == conv_id) {
		free(ret_string);
		return NULL;
	}
	pin = (char*)string;
	pout = ret_string;
	in_len = length;
	out_len = 2*length;
	if (-1 == iconv(conv_id, &pin, &in_len, &pout, &out_len)) {
		iconv_close(conv_id);
		free(ret_string);
		return NULL;
	}
	iconv_close(conv_id);
	return ret_string;
}

static char* classify_engine_cl_decode_mime(const char *charset,
	const char *mime_string)
{
	int i, buff_len;
	int offset;
	size_t tmp_len, decode_len;
	int last_pos, begin_pos, end_pos;
	ENCODE_STRING encode_string;
	char *in_buff, *out_buff;
	char *ret_string, *tmp_string;
	char temp_buff[1024];

	buff_len = strlen(mime_string);
	ret_string = malloc(2*(buff_len + 1));
	if (NULL == ret_string) {
		return NULL;
	}
	
	in_buff = (char*)mime_string;
	out_buff = ret_string;
	offset = 0;
	begin_pos = -1;
	end_pos = -1;
	last_pos = 0;
	for (i=0; i<buff_len-1&&offset<2*buff_len+1; i++) {
		if (-1 == begin_pos && '=' == in_buff[i] && '?' == in_buff[i + 1]) {
			begin_pos = i;
			if (i > last_pos) {
				memcpy(temp_buff, in_buff + last_pos, begin_pos - last_pos);
				temp_buff[begin_pos - last_pos] = '\0';
				tmp_string = classify_engine_cl_to_utf8(charset, temp_buff);
				if (NULL == tmp_string) {
					free(ret_string);
					return NULL;
				}
				tmp_len = strlen(tmp_string);
				memcpy(out_buff + offset, tmp_string, tmp_len);
				free(tmp_string);
				offset += tmp_len;
				last_pos = i;
			}
		}
		if (end_pos == -1 && begin_pos != -1 && in_buff[i] == '?' &&
		    in_buff[i+1] == '=' && ((in_buff[i-1] != 'q' &&
		    in_buff[i-1] != 'Q') || in_buff[i-2] != '?'))
			end_pos = i + 1;
		if (-1 != begin_pos && -1 != end_pos) {
			parse_mime_encode_string(in_buff + begin_pos, 
				end_pos - begin_pos + 1, &encode_string);
			tmp_len = strlen(encode_string.title);
			if (0 == strcmp(encode_string.encoding, "base64")) {
				decode_len = 0;
				decode64(encode_string.title, tmp_len, temp_buff, &decode_len);
				temp_buff[decode_len] = '\0';
				tmp_string = classify_engine_cl_to_utf8(encode_string.charset, temp_buff);
			} else if (0 == strcmp(encode_string.encoding, "quoted-printable")){
				decode_len = qp_decode(temp_buff, encode_string.title, tmp_len);
				temp_buff[decode_len] = '\0';
				tmp_string = classify_engine_cl_to_utf8(encode_string.charset, temp_buff);
			} else {
				tmp_string = classify_engine_cl_to_utf8(charset, encode_string.title);
			}
			if (NULL == tmp_string) {
				free(ret_string);
				return NULL;
			}
			tmp_len = strlen(tmp_string);
			memcpy(out_buff + offset, tmp_string, tmp_len);
			free(tmp_string);
			offset += tmp_len;
			
			last_pos = end_pos + 1;
			i = end_pos;
			begin_pos = -1;
			end_pos = -1;
			continue;
		}
	}
	if (i > last_pos) {
		tmp_string = classify_engine_cl_to_utf8(charset, in_buff + last_pos);
		if (NULL == tmp_string) {
			free(ret_string);
			return NULL;
		}
		tmp_len = strlen(tmp_string);
		memcpy(out_buff + offset, tmp_string, tmp_len);
		free(tmp_string);
		offset += tmp_len;
	} 
	out_buff[offset] = '\0';
	return ret_string;

}


static DOUBLE_LIST* classify_engine_cl_match(const char *charset,
	DOUBLE_LIST *pclist)
{
	int length;
	int i, count;
	BOOL b_first;
	int64_t ref_id;
	int64_t mail_id;
	char* header[2];
	MYSQL_ROW myrow;
	time_t temp_time;
	struct tm tmp_tm;
	char str_time[64];
	MYSQL_RES *pmyres;
	char str_time1[64];
	DOUBLE_LIST *plist;
	DOUBLE_LIST *plist1;
	char temp_path[256];
	RESULT_NODE *presnode;
	char sql_string[4096];
	char sql_string1[1024];
	char sql_string3[1024];
	DOUBLE_LIST_NODE *pnode;
	DOUBLE_LIST_NODE *ptail;
	DOUBLE_LIST_NODE *pnode1;
	DOUBLE_LIST clist_scope1;
	DOUBLE_LIST clist_scope2;
	DOUBLE_LIST clist_scope3;
	CONDITION_NODE *pconnode;
	MYSQL_CONNECTION *pconnection;

	
	ref_id = -1;
	header[0] = NULL;
	header[1] = NULL;
	double_list_init(&clist_scope1);
	double_list_init(&clist_scope2);
	double_list_init(&clist_scope3);
	sql_string1[0] = '\0';
	sql_string3[0] = '\0';


	for (pnode=double_list_get_head(pclist); NULL!=pnode;
		pnode=double_list_get_after(pclist, pnode)) {
		pconnode = (CONDITION_NODE*)pnode->pdata;
		switch (pconnode->condition) {
		case CONDITION_REFERENCE:
			ref_id = *(uint64_t*)(pconnode->pstatment);
			break;
		case CONDITION_UNIT:
		case CONDITION_SENDER:
		case CONDITION_RCPT:
			double_list_append_as_tail(&clist_scope1, &pconnode->node_temp);
			break;
		case CONDITION_FROM:
		case CONDITION_TO:
		case CONDITION_CC:
		case CONDITION_SUBJECT:
		case CONDITION_CONTENT:
		case CONDITION_FILENAME:
			double_list_append_as_tail(&clist_scope2, &pconnode->node_temp);
			break;
		case CONDITION_ATTACHED:
		case CONDITION_ATIME:
		case CONDITION_RTIME:
		case CONDITION_CTIME:
		case CONDITION_SIZE:
		case CONDITION_ID:
		case CONDITION_PRIORITY:
			double_list_append_as_tail(&clist_scope3, &pconnode->node_temp);
			break;
		case CONDITION_HEADER:
			header[0] = ((char**)(pconnode->pstatment))[0];
			header[1] = ((char**)(pconnode->pstatment))[0];
			break;
		}
	}

	if (0 != double_list_get_nodes_num(&clist_scope3)) {
		b_first = TRUE;
		length = 0;
		for (pnode=double_list_get_head(&clist_scope3); NULL!=pnode;
			pnode=double_list_get_after(&clist_scope3, pnode)) {
			pconnode = (CONDITION_NODE*)pnode->pdata;
			if (TRUE == b_first) {
				b_first = FALSE;
			} else {
				length += snprintf(sql_string3 + length, 1024 - length, " AND");
			}
			switch (pconnode->condition) {
			case CONDITION_ATTACHED:
				if (NULL == pconnode->pstatment) {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.attach=0");
				} else {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.attach=1");
				}
				break;
			case CONDITION_ATIME:
				if (0 == ((time_t*)pconnode->pstatment)[0]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.archived <= '%s'", str_time);
				} else if (-1 == ((time_t*)pconnode->pstatment)[1]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.archived >= '%s'", str_time);
				} else {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time1, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.archived BETWEEN '%s' AND '%s'",
								str_time, str_time1);
				}
				break;
			case CONDITION_RTIME:
				if (0 == ((time_t*)pconnode->pstatment)[0]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.received <= '%s'", str_time);
				} else if (-1 == ((time_t*)pconnode->pstatment)[1]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.received >= '%s'", str_time);
				} else {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time1, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.received BETWEEN '%s' AND '%s'",
								str_time, str_time1);
				}
				break;
			case CONDITION_CTIME:
				if (0 == ((time_t*)pconnode->pstatment)[0]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.composed <= '%s'", str_time);
				} else if (-1 == ((time_t*)pconnode->pstatment)[1]) {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.composed >= '%s'", str_time);
				} else {
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[0];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					memset(&tmp_tm, 0, sizeof(tmp_tm));
					temp_time = ((time_t*)pconnode->pstatment)[1];
					localtime_r(&temp_time, &tmp_tm);
					strftime(str_time1, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.composed BETWEEN '%s' AND '%s'",
								str_time, str_time1);
				}
				break;
			case CONDITION_SIZE:
				if (0 == ((uint64_t*)pconnode->pstatment)[0]) {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.size <= %lu",
								((uint64_t*)pconnode->pstatment)[1]);
				} else if (-1 == ((uint64_t*)pconnode->pstatment)[1]) {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.size >= %lu",
								((uint64_t*)pconnode->pstatment)[0]);
				} else {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.size BETWEEN %lu AND %lu",
								((uint64_t*)pconnode->pstatment)[0],
								((uint64_t*)pconnode->pstatment)[1]);
				}
				break;
			case CONDITION_ID:
				if (0 == ((uint64_t*)pconnode->pstatment)[0]) {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.id <= %lu",
								((uint64_t*)pconnode->pstatment)[1]);
				} else if (-1 == ((uint64_t*)pconnode->pstatment)[1]) {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.id >= %lu",
								((uint64_t*)pconnode->pstatment)[0]);
				} else {
					length += snprintf(sql_string3 + length, 1024 - length,
								" mails.id BETWEEN %llu AND %llu",
								((uint64_t*)pconnode->pstatment)[0],
								((uint64_t*)pconnode->pstatment)[1]);
				}
				break;
			case CONDITION_PRIORITY:
				length += snprintf(sql_string3 + length, 1024 - length,
							" mails.priority=%ld", pconnode->pstatment);
				break;
			}
		}

	}

	if (0 != double_list_get_nodes_num(&clist_scope1)) {
		b_first = TRUE;
		length = 0;
		for (pnode=double_list_get_head(&clist_scope1); NULL!=pnode;
			pnode=double_list_get_after(&clist_scope1, pnode)) {
			pconnode = (CONDITION_NODE*)pnode->pdata;
			if (FALSE == b_first) {
				length += snprintf(sql_string1 + length, 1024 - length, 
							" AND envelopes.mail_id IN "
							"(SELECT mail_id FROM envelopes WHERE");
			}
			switch (pconnode->condition) {
			case CONDITION_UNIT:
				length += snprintf(sql_string1 + length, 1024 - length,
							" envelopes.unit='%s'", pconnode->pstatment);
				break;
			case CONDITION_SENDER:
				length += snprintf(sql_string1 + length, 1024 - length,
							" envelopes.unit='%s' AND envelopes.bound=0",
							pconnode->pstatment);
				break;
			case CONDITION_RCPT:
				length += snprintf(sql_string1 + length, 1024 - length,
							" envelopes.unit='%s' AND envelopes.bound=1",
							pconnode->pstatment);
				break;
			}
			
			if (FALSE == b_first) {
				sql_string1[length] = ')';
				length ++;
				sql_string1[length] = '\0';
			} else {
				b_first = FALSE;
			}
		}
	}

	
	pmyres = NULL;
	sql_string[0] = '\0';
	if ('\0' != sql_string3[0]) {
		if ('\0' != sql_string1[0]) {
			if (-1 != ref_id) {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}

				if (FALSE == classify_engine_create_results0(
					pconnection->pmysql, ref_id)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}

				if (FALSE == classify_engine_create_results1(
					pconnection->pmysql)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}

				snprintf(sql_string, 4096, "INSERT INTO tmp_results1 (id) "
					"(SELECT envelopes.mail_id FROM envelopes INNER JOIN "
					"tmp_results0 ON envelopes.mail_id=tmp_results0.id "
					"WHERE %s)", sql_string1);
				if (0 != mysql_query(pconnection->pmysql, sql_string)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				
				
				snprintf(sql_string, 4096, "SELECT DISTINCT mails.id FROM "
					"mails INNER JOIN tmp_results1 ON "
					"mails.id=tmp_results1.id WHERE %s", sql_string3);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				
				classify_engine_destroy_results0(pconnection->pmysql);
				classify_engine_destroy_results1(pconnection->pmysql);
				mysql_pool_put_connection(pconnection, TRUE);

			} else {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}
				
				if (FALSE == classify_engine_create_results1(
					pconnection->pmysql)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}

				snprintf(sql_string, 4096, "INSERT INTO tmp_results1 (id) "
					"(SELECT envelopes.mail_id FROM envelopes WHERE %s)",
					sql_string1);
				if (0 != mysql_query(pconnection->pmysql, sql_string)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}

				snprintf(sql_string, 4096, "SELECT DISTINCT mails.id FROM "
					"mails INNER JOIN tmp_results1 ON "
					"mails.id=tmp_results1.id WHERE %s", sql_string3);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				classify_engine_destroy_results1(pconnection->pmysql);
				mysql_pool_put_connection(pconnection, TRUE);
			}

		} else {
			if (-1 != ref_id) {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}

				if (FALSE == classify_engine_create_results0(
					pconnection->pmysql, ref_id)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}

				snprintf(sql_string, 4096, "SELECT DISTINCT mails.id FROM "
					"mails INNER JOIN tmp_results0 ON "
					"mails.id=tmp_results0.id WHERE %s", sql_string3);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				classify_engine_destroy_results0(pconnection->pmysql);
				mysql_pool_put_connection(pconnection, TRUE);

			} else {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}
				snprintf(sql_string, 4096, "SELECT mails.id FROM mails "
					"WHERE %s", sql_string3);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				mysql_pool_put_connection(pconnection, TRUE);
			}
		}
	} else {
		if ('\0' != sql_string1[0]) {
			if (-1 != ref_id) {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}

				if (FALSE == classify_engine_create_results0(
					pconnection->pmysql, ref_id)) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				snprintf(sql_string, 4096, "SELECT DISTINCT "
					"envelopes.mail_id FROM envelopes "
					"INNER JOIN tmp_results0 ON "
					"envelopes.mail_id=tmp_results0.id WHERE %s",
					sql_string1);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				classify_engine_destroy_results0(pconnection->pmysql);
				mysql_pool_put_connection(pconnection, TRUE);
				
			} else {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}
				snprintf(sql_string, 4096, "SELECT DISTINCT "
					"envelopes.mail_id FROM envelopes WHERE %s",
					sql_string1);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				mysql_pool_put_connection(pconnection, TRUE);
			}
		} else {
			if (-1 != ref_id) {
				pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}
				sprintf(sql_string, "SELECT DISTINCT ref_id FROM refs WHERE "
					"mail_id=%lld UNION SELECT DISTINCT mail_id FROM refs "
					"WHERE ref_id=%lld", ref_id, ref_id);
				if (0 != mysql_query(pconnection->pmysql, sql_string) ||
					NULL == (pmyres = mysql_store_result(
					pconnection->pmysql))) {
					mysql_pool_put_connection(pconnection, FALSE);
					return NULL;
				}
				mysql_pool_put_connection(pconnection, TRUE);
			} else {
				sql_string[0] = '\0';
			}
		}
	}

	if (0 != double_list_get_nodes_num(&clist_scope2)) {
		plist1 = classify_engine_sphinx_search(&clist_scope2);
		if (NULL == plist1) {
			if (NULL != pmyres) {
				mysql_free_result(pmyres);
			}
			return NULL;
		}
		if ('\0' == sql_string[0]) {
			plist = plist1;
			plist1 = NULL;
			goto HEADER_MATCH;
		}
	} else {
		plist1 = NULL;
		if ('\0' == sql_string[0]) {
			pconnection = mysql_pool_get_connection();
				if (NULL == pconnection) {
					return NULL;
				}
			sprintf(sql_string, "SELECT id FROM mails");
			if (0 != mysql_query(pconnection->pmysql, sql_string) ||
				NULL == (pmyres = mysql_store_result(
				pconnection->pmysql))) {
				mysql_pool_put_connection(pconnection, FALSE);
				return NULL;
			}
			mysql_pool_put_connection(pconnection, TRUE);
		}
	}
	

	plist = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST));
	if (NULL == plist) {
		mysql_free_result(pmyres);
		return NULL;
	}
	double_list_init(plist);
	count = mysql_num_rows(pmyres);
	for (i=0; i<count; i++) {
		myrow = mysql_fetch_row(pmyres);
		mail_id = atoll(myrow[0]);
		if (NULL != plist1) {
			for (pnode1=double_list_get_head(plist1); NULL!=pnode1;
				pnode1=double_list_get_after(plist1, pnode1)) {
				if (mail_id == ((RESULT_NODE*)pnode1->pdata)->mail_id) {
					break;
				}
			}
			if (NULL == pnode1) {
				continue;
			}
			
			double_list_remove(plist1, pnode1);
		}
		presnode = (RESULT_NODE*)malloc(sizeof(RESULT_NODE));
		if (NULL == presnode) {
			continue;
		}
		presnode->node.pdata = presnode;
		presnode->mail_id = mail_id;
		double_list_append_as_tail(plist, &presnode->node);
	}
	mysql_free_result(pmyres);
	
	if (NULL != plist1) {
		while ((pnode1 = double_list_get_from_head(plist1)) != NULL)
			free(pnode1->pdata);
		double_list_free(plist1);
		free(plist1);
		plist1 = NULL;
	}

HEADER_MATCH:
	if (NULL != header[0] && NULL != header[1]) {
		ptail = double_list_get_tail(plist);
		while ((pnode = double_list_get_from_head(plist)) != NULL) {
			presnode = (RESULT_NODE*)pnode->pdata;
			pconnection = mysql_pool_get_connection();
			if (NULL == pconnection) {
				continue;
			}
			sprintf(sql_string, "SELECT path FROM mails WHERE id=%lld",
				presnode->mail_id);
			if (0 != mysql_query(pconnection->pmysql, sql_string) &&
				NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
				mysql_pool_put_connection(pconnection, FALSE);
				goto NEXT_LOOP;
			}
			myrow = mysql_fetch_row(pmyres);
			snprintf(temp_path, 256, "%s/%lld", myrow[0],
				presnode->mail_id);
			mysql_free_result(pmyres);
			mysql_pool_put_connection(pconnection, TRUE);
			
			if (FALSE == classify_engine_cl_search_head(charset,
				temp_path, header[0], header[1])) {
				free(presnode);
			} else {
				double_list_append_as_tail(plist, pnode);
			}
NEXT_LOOP:
			if (pnode == ptail) {
				break;
			}
		}
	}

	return plist;
}

static BOOL classify_engine_create_results0(MYSQL *pmysql, uint64_t ref_id)
{
	char sql_string[1024];
	
	sprintf(sql_string, "DROP TABLE IF EXISTS tmp_results0");
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "CREATE TEMPORARY TABLE tmp_results0 "
		"(id bigint(12) unsigned NOT NULL, KEY (id)) ENGINE=MEMORY");
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "INSERT INTO tmp_results0 (id) "
		"(SELECT ref_id FROM refs WHERE mail_id=%lld)",
		ref_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "INSERT INTO tmp_results0 (id) "
		"(SELECT mail_id FROM refs WHERE ref_id=%lld)",
		ref_id);
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}
	return TRUE;
}

static void classify_engine_destroy_results0(MYSQL *pmysql)
{
	mysql_query(pmysql, "DROP TABLE tmp_results0");
}

static BOOL classify_engine_create_results1(MYSQL *pmysql)
{
	char sql_string[1024];
	
	sprintf(sql_string, "DROP TABLE IF EXISTS tmp_results1");
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "SET max_heap_table_size=%ld", g_tmptbl_size);
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "SET tmp_table_size=%ld", g_tmptbl_size);
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}

	sprintf(sql_string, "CREATE TEMPORARY TABLE tmp_results1 "
		"(id bigint(12) unsigned NOT NULL, KEY (id)) ENGINE=MEMORY");
	if (0 != mysql_query(pmysql, sql_string)) {
		return FALSE;
	}
	
	return TRUE;
}

static void classify_engine_destroy_results1(MYSQL *pmysql)
{
	mysql_query(pmysql, "DROP TABLE tmp_results1");
}

static void classify_engine_enum_mime(MJSON_MIME *pmime, int *pattach)
{
	const char *cid;
	const char *cntl;
	const char *filename;
	

	if (0 != *pattach) {
		return;
	}
	
	if (MJSON_MIME_SINGLE != mjson_get_mime_mtype(pmime)) {
		return;
	}
	
	cid = mjson_get_mime_cid(pmime);
	cntl = mjson_get_mime_cntl(pmime);
	filename = mjson_get_mime_filename(pmime);
	
	
	if ('\0' != filename[0] && ('\0' == cid[0] ||
		0 == strncasecmp(mjson_get_mime_ctype(pmime), "application/", 12)) &&
		'\0' == cntl[0]) {
		*pattach = 1;	
	}
	
}


static BOOL classify_engine_cl_check_numstring(const char *string)
{
	int i, len;

	len = strlen(string);

	for (i=0; i<len; i++) {
		if (!isdigit(string[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

static void classify_engine_calculate_path(char *path)
{
	int num1, num2;
	uint64_t temp_id;
	DOUBLE_LIST_NODE *pnode;
	
	pthread_mutex_lock(&g_list_lock);
	temp_id = g_turn_num;
	pnode = double_list_get_from_head(&g_dir_list);
	if (pnode == g_list_tail) {
		g_turn_num ++;
	}
	double_list_append_as_tail(&g_dir_list, pnode);
	pthread_mutex_unlock(&g_list_lock);
	
	num1 = temp_id % VDIR_PER_PARTITION + 1;
	
	num2 = temp_id / VDIR_PER_PARTITION % SUBDIR_PER_VDIR + 1;
	
	snprintf(path, 128, "/%s/v%d/%d", pnode->pdata, num1, num2);
	
	
}


static void classify_engine_encode_squote(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		if ('\'' == in[i] || '\\' == in[i]) {
			out[j] = '\\';
			j ++;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

static void classify_engine_escase_string(const char *in, char *out)
{
	int len, i, j;

	len = strlen(in);
	for (i=0, j=0; i<len; i++, j++) {
		switch(in[i]) {
		case '\\':
		case '(':
		case ')':
		case '|':
		case '-':
		case '!':
		case '@':
		case '~':
		case '"':
		case '&':
		case '/':
		case '^':
		case '$':
		case '=':
		case '<':
			out[j] = '\\';
			j ++;
			break;
		}
		out[j] = in[i];
	}
	out[j] = '\0';
}

static DOUBLE_LIST* classify_engine_sphinx_search(DOUBLE_LIST *pclist)
{
	int i;
	RESULT_NODE *presnode;
	DOUBLE_LIST *pretlist;
	sphinx_result *psphres;
	sphinx_client *psphinx;
	char query_string[2048];
	DOUBLE_LIST_NODE *pnode;
	char escape_string[2048];
	CONDITION_NODE *pconnode;
	
	
	psphinx = sphinx_create(SPH_TRUE);
	
	if (NULL == psphinx) {
		return NULL;
	}
	
	pretlist = (DOUBLE_LIST*)malloc(sizeof(DOUBLE_LIST));
	if (NULL == pretlist) {
		sphinx_destroy(psphinx);
		return NULL;
	}
	
	sphinx_set_server(psphinx, g_sphinx_host, g_sphinx_port);
	
	sphinx_set_match_mode(psphinx, SPH_MATCH_EXTENDED2);
	
	sphinx_set_limits(psphinx, 0, 5000, 5000, 0);
	
	for (pnode=double_list_get_head(pclist); NULL!=pnode;
		pnode=double_list_get_after(pclist, pnode)) {
		pconnode = (CONDITION_NODE*)pnode->pdata;	
		switch (pconnode->condition) {
		case CONDITION_FROM:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@from %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		case CONDITION_TO:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@to %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		case CONDITION_CC:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@cc %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		case CONDITION_SUBJECT:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@subject %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		case CONDITION_CONTENT:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@content %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		case CONDITION_FILENAME:
			classify_engine_escase_string(pconnode->pstatment, escape_string);
			snprintf(query_string, 2048, "@attachment %s", escape_string);
			sphinx_add_query(psphinx, query_string, "*", NULL);
			break;
		}
	}
	
	psphres = sphinx_run_queries(psphinx);
	
	if (NULL == psphres) {
		free(pretlist);
		sphinx_destroy(psphinx);
		return NULL;
	}
	
	double_list_init(pretlist);
	
	for (i=0; i<psphres->num_matches; i++) {
		presnode = (RESULT_NODE*)malloc(sizeof(RESULT_NODE));
		if (NULL == presnode) {
			continue;
		}
		presnode->node.pdata = presnode;
		presnode->mail_id = sphinx_get_id(psphres, i);
		double_list_append_as_tail(pretlist, &presnode->node);
	}
	
	sphinx_destroy(psphinx);
	return pretlist;
}

void classify_engine_clean(time_t cur_time)
{
	int i, num;
	time_t tmp_time;
	MYSQL_ROW myrow;
	struct tm tmp_tm;
	MYSQL_RES *pmyres;
	char str_time[32];
	char tmp_path[256];
	char sql_string[1024];
	MYSQL_CONNECTION *pconnection;
	
	if (0 == g_valid_days) {
		return;
	}
	
	tmp_time = cur_time - g_valid_days*24*60*60;
	localtime_r(&tmp_time, &tmp_tm);
	strftime(str_time, 32, "%Y-%m-%d %H:%M:%S", &tmp_tm);
	
	pconnection = mysql_pool_get_connection();
	if (NULL == pconnection) {
		return;
	}
		
	sprintf(sql_string, "SELECT id, path FROM mails WHERE archived <= '%s'",
		str_time);
	if (0 != mysql_query(pconnection->pmysql, sql_string) ||
		NULL == (pmyres = mysql_store_result(pconnection->pmysql))) {
		mysql_pool_put_connection(pconnection, FALSE);
		return;
	}
	mysql_pool_put_connection(pconnection, TRUE);
	
	num = mysql_num_rows(pmyres);
	for (i=0; i<num; i++) {
		myrow = mysql_fetch_row(pmyres);
		snprintf(tmp_path, 256, "%s/%s/%s",
			g_storage_path, myrow[1], myrow[0]);
		remove(tmp_path);
	}
	mysql_free_result(pmyres);
	
	pconnection = mysql_pool_get_connection();
	if (NULL == pconnection) {
		return;
	}
	sprintf(sql_string, "DELETE FROM mails WHERE archived <= '%s'", str_time);
	if (0 != mysql_query(pconnection->pmysql, sql_string)) {
		mysql_pool_put_connection(pconnection, FALSE);
		return;
	}
	mysql_pool_put_connection(pconnection, TRUE);
}


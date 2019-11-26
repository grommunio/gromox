/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <errno.h>
#include <libHX/string.h>
#include "resource.h"
#include "config_file.h"
#include "single_list.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#define MAX_FILE_LINE_LEN       1024

typedef struct _LANG_FOLDER {
	SINGLE_LIST_NODE node;
	char lang[32];
	char *folders[4];
	char charset[256];
	char draft[256];
	char sent[256];
	char trash[256];
	char junk[256];
} LANG_FOLDER;

static IMAP_RETURN_CODE g_default_code_table[] = {
	{2160001, "BYE logging out"},
	{2160002, "+ idling"},
	{2160003, "+ ready for additional command text"},
	{2160004, "BYE disconnected by autologout"},

	{2170000, "OK <domain> service ready"},
	{2170001, "OK CAPABILITY completed"},
	{2170002, "OK NOOP completed"},
	{2170003, "OK LOGOUT completed"},
	{2170004, "OK begin TLS negotiation now"},
	{2170005, "OK logged in"},
	{2170006, "OK CREATED completed"},
	{2170007, "OK DELETE completed"},
	{2170008, "OK RENAME completed"},
	{2170009, "OK SUBSCRIBE completed"},
	{2170010, "OK UNSUBSCRIBE completed"},
	{2170011, "OK LIST completed"},
	{2170012, "OK XLIST completed"},
	{2170013, "OK LSUB completed"},
	{2170014, "OK STATUS completed"},
	{2170015, "OK <APPENDUID> APPEND completed"},
	{2170016, "OK CHECK completed"},
	{2170017, "OK CLOSE completed"},
	{2170018, "OK UNSELECT completed"},
	{2170019, "OK SEARCH completed"},
	{2170020, "OK FETCH completed"},
	{2170021, "OK STORE completed"},
	{2170022, "OK <COPYUID> COPY completed"},
	{2170023, "OK UID SEARCH completed"},
	{2170024, "OK UID STORE completed"},
	{2170025, "OK <COPYUID> UID COPY completed"},
	{2170026, "OK EXPUNGE completed"},
	{2170027, "OK IDLE completed"},
	{2170028, "OK UID FETCH completed"},
	{2170029, "OK ID completed"},
	{2170030, "OK UID EXPUNGE completed"},

	{2180000, "BAD command not support or parameter error"},
	{2180001, "BAD TLS negotiation only begin in not authenticated state"},
	{2180002, "BAD must issue a STARTTLS command first"},
	{2180003, "BAD cannot relogin in authenticated state"},
	{2180004, "BAD cannot process in not authenticated state"},
	{2180005, "BAD can only process in select state"},
	{2180006, "BAD can not store with read-only status"},
	{2180007, "BAD one or more flags not supported"},
	{2180008, "BAD internal error, fail to retrieve from stream object"},
	{2180009, "BAD internal error, fail to get stream buffer"},
	{2180010, "BAD internal error, fail to dump stream object"},
	{2180011, "BAD time out"},
	{2180012, "BAD internal error, fail to read file"},
	{2180013, "BAD search parameter syntax error"},
	{2180014, "BAD internal error, fail to init SSL object"},
	{2180015, "BAD <host> service not available"},
	{2180016, "BAD access is denied from your IP <remote_ip>"},
	{2180017, "BAD literal size too large"},
	{2180018, "BAD expected DONE"},
	{2180019, "BAD decode username error"},
	{2180020, "BAD decode password error"},

	{2190001, "NO access deny by user filter"},
	{2190002, "NO cannot get mailbox location from database"},
	{2190003, "NO too many failure, user will be blocked for a while"},
	{2190004, "NO login auth fail, <reason>"},
	{2190005, "NO server internal error, missing MIDB connection"},
	{2190006, "NO server internal error, fail to communicate with MIDB"},
	{2190007, "NO server internal error, <reason>"},
	{2190008, "NO cannot parse message, format error"},
	{2190009, "NO fail to save message"},
	{2190010, "NO folder name format error"},
	{2190011, "NO CREATE can not create reserved folder name"},
	{2190012, "NO DELETE can not delete subfolder"},
	{2190013, "NO DELETE can not delete reserved folder name"},
	{2190014, "NO RENAME can not rename reserved folder name"},
	{2190015, "NO server internal error: out of memery"},
	{2190016, "NO COPY failed"},
	{2190017, "NO UID COPY failed"},

	{2200000, "midb command not found"},
	{2200001, "midb command parameter error"},
	{2200002, "midb hash table full"},
	{2200003, "midb fail to read and load folder"},
	{2200004, "midb out of memory"},
	{2200005, "mail not found"},
	{2200006, "mail digest error"},
	{2200007, "folder already exist"},
	{2200008, "reach the limitation of folders"},
	{2200009, "mailbox is full"},
	{2200010, "midb fail to delete the folder"},
};


/* private global variables */
static char *g_cfg_filename, *g_cfg_filename2;
static CONFIG_FILE *g_config_file;
static IMAP_RETURN_CODE *g_return_code_table, *g_def_code_table;
static pthread_rwlock_t g_return_table_lock;
static SINGLE_LIST* g_lang_list;

static int resource_find_imap_code_index(int native_code);

static int resource_construct_imap_table(IMAP_RETURN_CODE **pptable);

static int resource_construct_lang_list(SINGLE_LIST *plist);

static int resource_parse_imap_line(char* dest, char* src_str, int len);

static BOOL resource_load_imap_lang_list();

void resource_init(const char *c1, const char *c2)
{
	g_lang_list = NULL;
	g_cfg_filename  = HX_strdup(c1);
	g_cfg_filename2 = HX_strdup(c2);
    pthread_rwlock_init(&g_return_table_lock, NULL);
}

void resource_free()
{   
    /* to avoid memory leak because of not stop */
    pthread_rwlock_destroy(&g_return_table_lock);
    if (NULL != g_config_file) {
        config_file_free(g_config_file);
        g_config_file = NULL;
    }
	free(g_cfg_filename);
	free(g_cfg_filename2);
	g_cfg_filename  = NULL;
	g_cfg_filename2 = NULL;
}

int resource_run()
{
    int i;

    g_def_code_table = malloc(sizeof(g_default_code_table));
    if (NULL == g_def_code_table) {
        printf("[resource]: fail to allocate default code table\n" );
        return -1;
    }
	g_config_file = config_file_init2(g_cfg_filename, g_cfg_filename2);
	if (g_cfg_filename != NULL && g_config_file == NULL) {
		printf("[resource]: config_file_init %s: %s\n", g_cfg_filename, strerror(errno));
        free(g_def_code_table);
        return -2;
    }

	if (FALSE == resource_load_imap_lang_list()) {
		printf("[resource]: fail to load imap lang\n");
		return -3;
	}
	
    if (FALSE == resource_refresh_imap_code_table()) {
        printf("[resource]: fail to load imap code\n");
		return -4;
    }
    for (i=0; i<sizeof(g_default_code_table)/sizeof(IMAP_RETURN_CODE); i++) {
        g_def_code_table[i].code =
                    g_default_code_table[i].code;

        resource_parse_imap_line(g_def_code_table[i].comment, 
            g_default_code_table[i].comment, 
            strlen(g_default_code_table[i].comment));
    }

    
    return 0;
}

int resource_stop()
{
	SINGLE_LIST_NODE *pnode;

    if (NULL != g_config_file) {
        config_file_free(g_config_file);
        g_config_file = NULL;
    }

    if (NULL != g_def_code_table) {
        free(g_def_code_table);
        g_def_code_table = NULL;
    }
	
	if (NULL != g_lang_list) {
		while ((pnode = single_list_get_from_head(g_lang_list)) != NULL)
			free(pnode->pdata);
		single_list_free(g_lang_list);
		free(g_lang_list);
		g_lang_list = NULL;
	}
    return 0;
}

BOOL resource_save()
{
	if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
		return FALSE;
	}
	return config_file_save(g_config_file);
}

/*
 *  get a specified integer value that match the key
 *
 *  @param
 *      key             key that describe the integer value
 *      value [out]     pointer to the integer value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_get_integer(const char *key, int *value)
{
    char *pvalue    = NULL;     /* string value of the mapped key */

	if (key == NULL) {
        debug_info("[resource]: invalid param resource_get_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }
	pvalue = config_file_get_value(g_config_file, key);
    if (NULL == pvalue) {
        debug_info("[resource]: no value map to the key in "
                    "resource_get_integer");
        return FALSE;
    }
    *value = atoi(pvalue);
    return TRUE;
}

/*
 *  set the specified integer that match the key
 *
 *  @param
 *      key             key that describe the integer value
 *      value           the new value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_set_integer(const char *key, int value)
{
    char m_buf[32];             /* buffer to hold the int string  */

	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_set_integer");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }
    itoa(value, m_buf, 10);
	return config_file_set_value(g_config_file, key, m_buf);
}

/*
 *  set the specified string that match the key
 *
 *  @param
 *      key             key that describe the string value
 *      value [out]     the string value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
BOOL resource_set_string(const char *key, const char *value)
{
	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_set_string");
        return FALSE;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return FALSE;
    }
	return config_file_set_value(g_config_file, key, value);
}

/*
 *  get a specified string value that match the key
 *
 *  @param
 *      key             key that describe the string value
 *      value [out]     pointer to the string value
 *
 *  @return
 *      TRUE        success
 *      FALSE       fail
 */
const char *resource_get_string(const char *key)
{
    const char *pvalue  = NULL;     /* string value of the mapped key */

	if (key == NULL) {
        debug_info("[resource]: invalid param in resource_get_string");
        return NULL;
    }

    if (NULL == g_config_file) {
        debug_info("[resource]: error!!! config file not init or init fail but"
                    " it is now being used");
        return NULL;
    }
	pvalue = config_file_get_value(g_config_file, key);
    if (NULL == pvalue) {
        debug_info("[resource]: no value map to the key in "
                    "resource_get_string");
        return NULL;
    }
    return pvalue;
}

/*
 *  construct a imap error code table, which is as the below table
 *
 *      number              comments
 *      2175018             550 Access denied to you
 *      2175019             550 Access to Mailbox 
 *                              <email_addr>  is denied
 *  @param
 *      pptable [in/out]        pointer to the newly created table
 *
 *  @return
 *      0           success
 *      <>0         fail
 */
static int resource_construct_imap_table(IMAP_RETURN_CODE **pptable)
{
    char line[MAX_FILE_LINE_LEN], buf[MAX_FILE_LINE_LEN];
	char *pbackup, *ptr, code[32];
    IMAP_RETURN_CODE *code_table;
    FILE *file_ptr = NULL;

    int total, index, native_code, len;
	const char *filename = resource_get_string("IMAP_RETURN_CODE_PATH");
	if (NULL == filename) {
		return -1;
	}
    if (NULL == (file_ptr = fopen(filename, "r"))) {
        printf("[resource]: can not open imap return table file  %s\n",
                filename);
        return -1;
    }

    code_table = malloc(sizeof(g_default_code_table));

    if (NULL == code_table) {
        printf("[resource]: fail to allocate memory for imap return code"
                " table\n");
        fclose(file_ptr);
        return -1;
    }

    for (total=0; total<sizeof(g_default_code_table)/sizeof(IMAP_RETURN_CODE); total++) {
        code_table[total].code              = -1;
        memset(code_table[total].comment, 0, 512);
    }

    for (total = 0; fgets(line, MAX_FILE_LINE_LEN, file_ptr); total++) {

        if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
            /* skip empty line or comments */
            continue;
        }

        ptr = (pbackup = line);

        len = 0;
        while (*ptr && *ptr != '\r' && *ptr != '\n') {
            if (*ptr == ' ' || *ptr == '\t') {
                break;
            }
            len++;
            ptr++;
        }

        if (len <= 0 || len > sizeof(code) - 1) {
            printf("[resource]: invalid native code format, file: %s line: "
                    "%d, %s\n", filename, total + 1, line);

            continue;
        }

        memcpy(code, pbackup, len);
        code[len]   = '\0';

        if ((native_code = atoi(code)) <= 0) {
            printf("[resource]: invalid native code, file: %s line: %d, %s\n", 
                filename, total + 1, line);
            continue;
        }

        while (*ptr && (*ptr == ' ' || *ptr == '\t')) {
            ptr++;
        }

        pbackup = ptr;
        len     = 0;
        while (*ptr && *ptr != '\r' && *ptr != '\n') {
            len++;
            ptr++;
        }

        while (len > 0 && (*ptr == ' ' || *ptr == '\t')) {
            len--;
            ptr--;
        }

        if (len <= 0 || len > MAX_FILE_LINE_LEN - 1) {
            printf("[resource]: invalid native comment, file: %s line: %d, "
                    "%s\n", filename, total + 1, line);
            continue;
        }
        memcpy(buf, pbackup, len);
        buf[len]    = '\0';

        if ((index = resource_find_imap_code_index(native_code)) < 0) {
            printf("[resource]: no such native code, file: %s line: %d, %s\n", 
                filename, total + 1, line);
            continue;
        }

        if (-1 != code_table[index].code) {
            printf("[resource]: the return code has already been defined, file:"
                " %s line: %d, %s\n", filename, total + 1, line);
            continue;

        }

        if (resource_parse_imap_line(code_table[index].comment, buf, len) < 0) {
            printf("[resource]: invalid imap code format, file: %s line: %d,"
                    " %s", filename, total + 1, line);
            continue;
        }
        code_table[index].code  = native_code;
    }

    *pptable = code_table;
    fclose(file_ptr);
    return 0;
}

/*
 *  take a description line and construct it into what we need.
 *  for example, if the source string is "hello", we just copy
 *  it to the destination with a its length at the beginning of 
 *  the destination.    8 h e l l o \r \n \0    , the length 
 *  includes the CRLF and null terminator. if the source string
 *  is like "hi <who>, give", the destination format will be:       
 *      4 h i space \0 9 , space g i v e \r \n \0
 *
 *  @param
 *      dest    [in]        where we will copy the source string to
 *      src_str [in]        the source description string
 *      len                 the length of the source string
 *
 *  @return
 *      0       success
 *      <0      fail
 */
static int resource_parse_imap_line(char* dest, char* src_str, int len)
{
    char *ptr = NULL, *end_ptr = NULL, sub_len = 0;

    if (NULL == (ptr = strchr(src_str, '<')) || ptr == src_str) {
        dest[0] = (char)(len + 3);
        strncpy(dest + 1, src_str, len);
        strncpy(dest + len + 1, "\r\n", 2);
        dest[len + 3] = '\0';
    } else {
        sub_len = (char)(ptr - src_str);
        dest[0] = sub_len + 1;          /* include null terminator */
        strncpy(dest + 1, src_str, sub_len);
        dest[sub_len + 1] = '\0';

        if (NULL == (ptr = strchr(ptr, '>'))) {
            return -1;
        }

        end_ptr = src_str + len;
        dest[sub_len + 2] = (char)(end_ptr - ptr + 2);
        end_ptr = ptr + 1;
        ptr     = dest + sub_len + 3;
        sub_len = dest[sub_len + 2];

        strncpy(ptr, end_ptr, sub_len);
        strncpy(ptr + sub_len - 3, "\r\n", 2);
        *(ptr + sub_len - 1) = '\0';
    }
    return 0;

}

const char *resource_get_imap_code(int code_type, int n, int *len)
{
    IMAP_RETURN_CODE *pitem = NULL;
    char *ret_ptr = NULL;
    int   ret_len = 0;
#define FIRST_PART      1
#define SECOND_PART     2

    pthread_rwlock_rdlock(&g_return_table_lock);
    if (NULL == g_return_code_table || g_return_code_table[code_type].code
        == -1) {
        pitem = &g_def_code_table[code_type];
    } else {
        pitem = &g_return_code_table[code_type];
    }
    ret_len = pitem->comment[0];
    ret_ptr = &(pitem->comment[1]);
    if (FIRST_PART == n)    {
        *len = ret_len - 1;
        pthread_rwlock_unlock(&g_return_table_lock);
        return ret_ptr;
    }
    if (SECOND_PART == n)   {
        ret_ptr = ret_ptr + ret_len + 1;
        ret_len = pitem->comment[ret_len + 1];

        if (ret_len > 0) {
            *len = ret_len - 1;
            pthread_rwlock_unlock(&g_return_table_lock);
            return ret_ptr;
        }
    }
    pthread_rwlock_unlock(&g_return_table_lock);
    debug_info("[resource]: not exits nth in resource_get_imap_code");
	*len = 15;
    return "unkown error!\r\n";
}

BOOL resource_refresh_imap_code_table()
{
    IMAP_RETURN_CODE *pnew_table = NULL;

    if (0 != resource_construct_imap_table(
        &pnew_table)) {
        return FALSE;
    }

    pthread_rwlock_wrlock(&g_return_table_lock);
    if (NULL != g_return_code_table) {
        free(g_return_code_table);
    }
    g_return_code_table = pnew_table;
    pthread_rwlock_unlock(&g_return_table_lock);
    return TRUE;
}

static BOOL resource_load_imap_lang_list()
{
	SINGLE_LIST *plist;

	plist = malloc(sizeof(SINGLE_LIST));
	if (NULL == plist) {
		return FALSE;
	}
    if (0 != resource_construct_lang_list(plist)) {
        return FALSE;
    }
	g_lang_list = plist;
    return TRUE;
}

static int resource_find_imap_code_index(int native_code)
{
    int i;

    for (i=0; i<sizeof(g_default_code_table)/sizeof(IMAP_RETURN_CODE); i++) {
        if (g_default_code_table[i].code == native_code) {
            return i;
        }
    }
    return -1;
}

BOOL resource_get_digest_integer(const char *src, const char *tag, long *pinteger)
{
	char num_buff[32];

	if (TRUE == get_digest(src, tag, num_buff, 32)) {
		*pinteger = atol(num_buff);
		return TRUE;
	}
	return FALSE;
}

void resource_set_digest_string(char *src, int length, const char *tag, const char *value)
{
    char temp_value[256];
	
    snprintf(temp_value, 255, "\"%s\"", value);
	set_digest(src, length, tag, temp_value); 
}

void resource_set_digest_integer(char *src, int length, const char *tag, long value)
{
	char num_buff[32];
	
	snprintf(num_buff, 32, "%ld", value);
	set_digest(src, length, tag, num_buff); 
}

static int resource_construct_lang_list(SINGLE_LIST *plist)
{
	int total;
	char *ptr;
	size_t temp_len;
	SINGLE_LIST temp_list;
	FILE *file_ptr;
	SINGLE_LIST_NODE *pnode;
	LANG_FOLDER *plang;
	char temp_buff[256];
	char line[MAX_FILE_LINE_LEN];
	
	single_list_init(&temp_list);
	const char *filename = resource_get_string("IMAP_LANG_PATH");
	if (NULL == filename) {
		return -1;
	}
    if (NULL == (file_ptr = fopen(filename, "r"))) {
        printf("[resource]: can not open imap lang table file  %s\n",
                filename);
        return -1;
    }
	
    for (total=0; fgets(line, MAX_FILE_LINE_LEN, file_ptr); total++) {

		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
		   /* skip empty line or comments */
		   continue;
		}

		ptr = strchr(line, ':');
		if (NULL == ptr) {
			printf("[resource]: line %d format error in %s\n", total + 1,
                filename);
			fclose(file_ptr);
			while ((pnode = single_list_get_from_head(&temp_list)) != NULL)
				free(pnode->pdata);
			single_list_free(&temp_list);
			return -1;
		}
		
		*ptr = '\0';
		plang = (LANG_FOLDER*)malloc(sizeof(LANG_FOLDER));
		if (NULL == plang) {
			printf("[resource]: out of memory while loading file %s\n",
                filename);
			fclose(file_ptr);
			while ((pnode = single_list_get_from_head(&temp_list)) != NULL)
				free(pnode->pdata);
			single_list_free(&temp_list);
			return -1;
		}
		
		plang->node.pdata = plang;
		strncpy(plang->lang, line, 32);
		HX_strrtrim(plang->lang);
		HX_strltrim(plang->lang);
		plang->folders[0] = plang->draft;
		plang->folders[1] = plang->sent;
		plang->folders[2] = plang->trash;
		plang->folders[3] = plang->junk;
		if (0 == strlen(plang->lang) ||
			FALSE == get_digest(ptr + 1, "default-charset",
			plang->charset, 256) || 0 == strlen(plang->charset) ||
			FALSE == get_digest(ptr + 1, "draft", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->draft, &temp_len) ||
			FALSE == get_digest(ptr + 1, "sent", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->sent, &temp_len) ||
			FALSE == get_digest(ptr + 1, "trash", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->trash, &temp_len) ||
			FALSE == get_digest(ptr + 1, "junk", temp_buff, 256) ||
			0 == strlen(temp_buff) ||
			0 != decode64(temp_buff, strlen(temp_buff), plang->junk, &temp_len)) {
			printf("[resource]: line %d format error in %s\n", total + 1, filename);
			free(plang);
			fclose(file_ptr);
			while ((pnode = single_list_get_from_head(&temp_list)) != NULL)
				free(pnode->pdata);
			single_list_free(&temp_list);
			return -1;
		}
		single_list_append_as_tail(&temp_list, &plang->node);
	}
	fclose(file_ptr);
	
	for (pnode=single_list_get_head(&temp_list); NULL!=pnode;
		pnode=single_list_get_after(&temp_list, pnode)) {
		plang = (LANG_FOLDER*)pnode->pdata;
		if (strcasecmp(plang->lang, resource_get_string("DEFAULT_LANG")) == 0)
			break;
	}
	
	if (NULL == pnode) {
		printf("[resource]: cannot find default lang in %s\n", filename);
		while ((pnode = single_list_get_from_head(&temp_list)) != NULL)
			free(pnode->pdata);
		single_list_free(&temp_list);
		return -1;
	}
	
	if (single_list_get_nodes_num(&temp_list) > 127) {
		printf("[resource]: too many langs in %s\n", filename);
		while ((pnode = single_list_get_from_head(&temp_list)) != NULL)
			free(pnode->pdata);
		single_list_free(&temp_list);
		return -1;
	}
	
	*plist = temp_list;
	return 0;
}

const char* resource_get_default_charset(const char *lang)
{
	SINGLE_LIST_NODE *pnode;
	LANG_FOLDER *plang;
	
	for (pnode=single_list_get_head(g_lang_list); NULL!=pnode;
		pnode=single_list_get_after(g_lang_list, pnode)) {
		plang = (LANG_FOLDER*)pnode->pdata;
		if (0 == strcasecmp(plang->lang, lang)) {
			return plang->charset;
		}
	}
	
	for (pnode=single_list_get_head(g_lang_list); NULL!=pnode;
		pnode=single_list_get_after(g_lang_list, pnode)) {
		plang = (LANG_FOLDER*)pnode->pdata;
		if (strcasecmp(plang->lang, resource_get_string("DEFAULT_LANG")) == 0)
			return plang->charset;
	}
	
	return NULL;
}

char** resource_get_folder_strings(const char*lang)
{
	SINGLE_LIST_NODE *pnode;
	LANG_FOLDER *plang;
	
	for (pnode=single_list_get_head(g_lang_list); NULL!=pnode;
		pnode=single_list_get_after(g_lang_list, pnode)) {
		plang = (LANG_FOLDER*)pnode->pdata;
		if (0 == strcasecmp(plang->lang, lang)) {
			return plang->folders;
		}
	}
	
	for (pnode=single_list_get_head(g_lang_list); NULL!=pnode;
		pnode=single_list_get_after(g_lang_list, pnode)) {
		plang = (LANG_FOLDER*)pnode->pdata;
		if (strcasecmp(plang->lang, resource_get_string("DEFAULT_LANG")) == 0)
			return plang->folders;
	}
	
	return NULL;
}

const char *resource_get_error_string(int errno)
{
	int temp_len;
	
	return resource_get_imap_code(IMAP_CODE_2200000 + errno, 1, &temp_len);
}

// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <cerrno>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "resource.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <pthread.h>
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

static POP3_ERROR_CODE g_default_pop3_error_code_table[] = {
    { 2170000, "+OK" },
    { 2170001, "-ERR time out" },
    { 2170002, "-ERR line too long" },
	{2170003, "-ERR command unknown"},
    { 2170004, "-ERR command parameter error" },
    { 2170005, "-ERR input username first" },
	{2170006, "-ERR too many failures, user will be blocked for a while"},
    { 2170007, "-ERR message not found" },
    { 2170008, "-ERR login first" },
	{2170009, "-ERR failed to open message"},
    { 2170010, "+OK quit <host>" },
    { 2170011, "+OK <host> pop service ready" },
	{2170012, "-ERR access denied by ipaddr filter for <ip>"},
    { 2170013, "-ERR <host> pop service unavailable" },
    { 2170014, "-ERR login auth fail, because: <reason>" },
    { 2170015, "-ERR cannot get mailbox location from database" },
	{2170016, "-ERR failed to open/read inbox index"},
	{2170017, "-ERR access denied by user filter for <user>"},
    { 2170018, "-ERR error internal" },
    { 2170019, "-ERR fail to retrieve message" },
    { 2170020, "-ERR cannot relogin under login stat" },
	{ 2170021, "-ERR midb read/write error" },
	{2170022, "-ERR fail to execute command in midb"},
	{ 2170023, "-ERR failed to initialize TLS"},
	{ 2170024, "+OK begin TLS negotiation"},
	{ 2170025, "-ERR TLS negotiation only begin in AUTHORIZATION state"},
	{ 2170026,  "-ERR must issue a STLS command first"}
};

/* private global variables */
static POP3_ERROR_CODE *g_error_code_table, *g_def_code_table;
static pthread_rwlock_t g_error_table_lock;

static int resource_find_pop3_code_index(int native_code);

static int resource_construct_pop3_table(POP3_ERROR_CODE **pptable);

static int resource_parse_pop3_line(char* dest, char* src_str, int len);

void resource_init()
{
    pthread_rwlock_init(&g_error_table_lock, NULL);
}

void resource_free()
{   
    /* to avoid memory leak because of not stop */
    pthread_rwlock_destroy(&g_error_table_lock);
}

int resource_run()
{
    int i;

	g_def_code_table = static_cast<POP3_ERROR_CODE *>(malloc(sizeof(POP3_ERROR_CODE) * POP3_CODE_COUNT));
    if (NULL == g_def_code_table) {
		printf("[resource]: Failed to allocate default code table\n" );
        return -1;
    }
    if (FALSE == resource_refresh_pop3_code_table()) {
		printf("[resource]: Failed to load POP3 codes\n");
    }
    for (i = 0; i < POP3_CODE_COUNT; i++) {
        g_def_code_table[i].code =
                    g_default_pop3_error_code_table[i].code;

        resource_parse_pop3_line(g_def_code_table[i].comment, 
            g_default_pop3_error_code_table[i].comment, 
            strlen(g_default_pop3_error_code_table[i].comment));
    }

    
    return 0;
}

int resource_stop()
{
    if (NULL != g_def_code_table) {
        free(g_def_code_table);
        g_def_code_table = NULL;
    }
    return 0;
}

/*
 *  construct a pop3 error code table, which is as the below table
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
static int resource_construct_pop3_table(POP3_ERROR_CODE **pptable)
{
    char line[MAX_FILE_LINE_LEN], buf[MAX_FILE_LINE_LEN];
	char *pbackup, *ptr, code[32];
	int index, native_code, len;
	const char *filename = resource_get_string("POP3_RETURN_CODE_PATH");
	if (NULL == filename) {
		filename = "pop3_code.txt";
	}
	auto file_ptr = fopen_sd(filename, resource_get_string("data_file_path"));
	if (file_ptr == nullptr) {
		printf("[resource]: fopen_sd %s: %s\n", filename, strerror(errno));
        return -1;
    }

	auto code_table = static_cast<POP3_ERROR_CODE *>(malloc(sizeof(POP3_ERROR_CODE) * POP3_CODE_COUNT));
    if (NULL == code_table) {
		printf("[resource]: Failed to allocate memory for POP3 return code"
                " table\n");
        return -1;
    }

	for (int total = 0; total < POP3_CODE_COUNT; ++total) {
        code_table[total].code              = -1;
        memset(code_table[total].comment, 0, 512);
    }

	for (int total = 0; fgets(line, MAX_FILE_LINE_LEN, file_ptr.get()); ++total) {

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

        if ((index = resource_find_pop3_code_index(native_code)) < 0) {
            printf("[resource]: no such native code, file: %s line: %d, %s\n", 
                filename, total + 1, line);
            continue;
        }

        if (-1 != code_table[index].code) {
            printf("[resource]: the error code has already been defined, file:"
                " %s line: %d, %s\n", filename, total + 1, line);
            continue;

        }

        if (resource_parse_pop3_line(code_table[index].comment, buf, len) < 0) {
            printf("[resource]: invalid pop3 code format, file: %s line: %d,"
                    " %s", filename, total + 1, line);
            continue;
        }
        code_table[index].code  = native_code;
    }

    *pptable = code_table;
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
static int resource_parse_pop3_line(char* dest, char* src_str, int len)
{
    char *ptr = NULL, *end_ptr = NULL, sub_len = 0;

    if (NULL == (ptr = strchr(src_str, '<')) || ptr == src_str) {
        dest[0] = (char)(len + 3);
        strncpy(dest + 1, src_str, len);
		dest[len+1] = '\r';
		dest[len+2] = '\n';
		dest[len+3] = '\0';
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
		ptr[sub_len-3] = '\r';
		ptr[sub_len-2] = '\n';
		ptr[sub_len-1] = '\0';
    }
    return 0;

}

char* resource_get_pop3_code(int code_type, int n, int *len)
{
    POP3_ERROR_CODE *pitem = NULL;
    char *ret_ptr = NULL;
    int   ret_len = 0;
#define FIRST_PART      1
#define SECOND_PART     2

    pthread_rwlock_rdlock(&g_error_table_lock);
    if (NULL == g_error_code_table || g_error_code_table[code_type].code
        == -1) {
        pitem = &g_def_code_table[code_type];
    } else {
        pitem = &g_error_code_table[code_type];
    }
    ret_len = pitem->comment[0];
    ret_ptr = &(pitem->comment[1]);
    if (FIRST_PART == n)    {
        *len = ret_len - 1;
        pthread_rwlock_unlock(&g_error_table_lock);
        return ret_ptr;
    }
    if (SECOND_PART == n)   {
        ret_ptr = ret_ptr + ret_len + 1;
        ret_len = pitem->comment[ret_len + 1];

        if (ret_len > 0) {
            *len = ret_len - 1;
            pthread_rwlock_unlock(&g_error_table_lock);
            return ret_ptr;
        }
    }
    pthread_rwlock_unlock(&g_error_table_lock);
    debug_info("[resource]: not exits nth in resource_get_pop3_code");
    return NULL;
}

BOOL resource_refresh_pop3_code_table()
{
    POP3_ERROR_CODE *pnew_table = NULL;

    if (0 != resource_construct_pop3_table(
        &pnew_table)) {
        return FALSE;
    }

    pthread_rwlock_wrlock(&g_error_table_lock);
    if (NULL != g_error_code_table) {
        free(g_error_code_table);
    }
    g_error_code_table = pnew_table;
    pthread_rwlock_unlock(&g_error_table_lock);
    return TRUE;
}

static int resource_find_pop3_code_index(int native_code)
{
    int i;

    for (i = 0; i < POP3_CODE_COUNT; i++) {
        if (g_default_pop3_error_code_table[i].code == native_code) {
            return i;
        }
    }
    return -1;
}


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
static POP3_ERROR_CODE *g_def_code_table;

static int resource_parse_pop3_line(char* dest, char* src_str, int len);

int resource_run()
{
    int i;

	g_def_code_table = static_cast<POP3_ERROR_CODE *>(malloc(sizeof(POP3_ERROR_CODE) * POP3_CODE_COUNT));
    if (NULL == g_def_code_table) {
		printf("[resource]: Failed to allocate default code table\n" );
        return -1;
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

const char *resource_get_pop3_code(unsigned int code_type, unsigned int n, size_t *len)
{
    POP3_ERROR_CODE *pitem = NULL;
    char *ret_ptr = NULL;
    int   ret_len = 0;
#define FIRST_PART      1
#define SECOND_PART     2

        pitem = &g_def_code_table[code_type];
    ret_len = pitem->comment[0];
    ret_ptr = &(pitem->comment[1]);
    if (FIRST_PART == n)    {
        *len = ret_len - 1;
        return ret_ptr;
    }
    if (SECOND_PART == n)   {
        ret_ptr = ret_ptr + ret_len + 1;
        ret_len = pitem->comment[ret_len + 1];

        if (ret_len > 0) {
            *len = ret_len - 1;
            return ret_ptr;
        }
    }
	debug_info("[resource]: rcode does not exist (resource_get_pop3_code)");
    return NULL;
}

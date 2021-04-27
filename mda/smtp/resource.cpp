// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <cerrno>
#include <libHX/string.h>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include "resource.h"
#include <gromox/util.hpp>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

static SMTP_ERROR_CODE g_default_smtp_error_code_table[] = {
	{2172001, "214 Help availble on " DFL_LOGOLINK},
    { 2172002, "220 <domain> Service ready" },
    { 2172003, "221 <domain> Good-bye" },
    { 2172004, "235 Authentication ok, go ahead" },
    { 2172005, "250 Ok" },
    { 2172006, "250 duplicated RCPT" },
    { 2172007, "250 All SMTP buffer cleared" },
    { 2172008, "251 User not local; will forward to <forward-path>" },
    { 2172009, "252 Cannot VRFY user, but will accept message and attempt" },
	{ 2172010, "220 Ready to start TLS" },
    { 2173001, "334 VXNlcm5hbWU6" },
    { 2173002, "334 UGFzc3dvcmQ6" },
    { 2173003, "354 Start mail input; end with CRLF.CRLF" },
    { 2173004, "334 OK, go on" },
    { 2174001, "421 <domain> Service not available" },
    { 2174002, "421 <domain> Service not available - Unable to chdir" },
    { 2174003, "421 <domain> Service not available - Unable to read system configuration" },
    { 2174004, "421 <domain> Service not available - Unable to figure out my IP addresses" },
    { 2174005, "421 <domain> Service not available - no valid hosted domain" },
    { 2174006, "421 Too much failure in SMTP session" },
    { 2174007, "421 Access is denied from your IP address <remote_ip> for audit reason, try later" },
    { 2174008, "432 A password transition is needed" },
    { 2174009, "450 Requested mail action not taken" },
    { 2174010, "450 Mailbox <email_addr> is full" },
    { 2174011, "451 Requested action aborted: error in processing;" },
    { 2174012, "451 Timeout" },
    { 2174013, "451 Message doesn't conform to the EMIME standard." },
    { 2174014, "451 Temporary internal failure - queue message failed" },
    { 2174015, "451 Temporary internal failure - database in accessible" },
    { 2174016, "452 Temporary internal failure - out of memory" },
    { 2174017, "452 Temporary internal failure - insufficient system storage" },
    { 2174018, "452 Temporary internal failure - failed to initialize TLS" },
    { 2174019, "452 too many RCPTs" },
    { 2174020, "453 Access is denied - sender is in the audit blacklist, try later" },
    { 2175001, "500 syntax error - invalid character" },
    { 2175002, "500 syntax error - line too long" },
    { 2175003, "500 syntax error - command unrecognized" },
    { 2175004, "501 Remote abort the authentication" },
    { 2175005, "501 Syntax error in parameters or arguments" },
    { 2175006, "502 Command not implemented" },
    { 2175007, "503 Bad sequence of commands" },
    { 2175008, "503 Bad sequence of commands MAIL first" },
    { 2175009, "503 Bad sequence of commands RCPT first" },
    { 2175010, "504 Command parameter not implemented" },
    { 2175011, "504 Unrecognized authentication type" },
    { 2175012, "521 Access is denied from your IP address <remote_ip>" },
    { 2175013, "530 Authentication required", },
    { 2175014, "534 Authentication mechanism is too weak" },
    { 2175015, "538 Encryption required for requested authentication mechanism" },
    { 2175016, "550 invalid user - <email_addr>" },
    { 2175017, "550 Mailbox <email_addr> is full" },
    { 2175018, "550 access denied to you" },
    { 2175019, "550 Access to Mailbox <email_addr>  is denied" },
    { 2175020, "550 Must issue a STARTTLS command first" },
    { 2175021, "552 message exceeds fixed maximum message size" },
    { 2175022, "553 Requested action not taken: mailbox name not allowed" },
    { 2175023, "553 Access is denied - sender is in the blacklist" },
    { 2175024, "553 Access is denied - please use the smtp server instead of MX" },
    { 2175025, "554 Requested mail action aborted: exceeded storage allocation; too much mail data" },
    { 2175026, "554 too many hops, this message is looping" },
    { 2175027, "554 no valid recipients" },
    { 2175028, "554 Authentication has failed too many times" },
    { 2175029, "554 Too many MAIL transactions in the same connection" },
    { 2175030, "554 Invalid EHLO/HELO FQDN host" },
    { 2175031, "554 Relay from your IP address <remote_ip> is denied" },
    { 2175032, "554 Relay from your addr <revserse_address> is denied" },
    { 2175033, "554 Relay to <relay_address> is denied" },
    { 2175034, "554 RCPT <forward-address> is in the blacklist" },
    { 2175035, "554 Temporary authentication failure" },
    { 2175036, "554 Message is infected by virus" },
};

/* private global variables */
static SMTP_ERROR_CODE *g_def_code_table;

static int resource_parse_smtp_line(char* dest, char* src_str, int len);

int resource_run()
{
    int i;

	g_def_code_table = static_cast<SMTP_ERROR_CODE *>(malloc(sizeof(SMTP_ERROR_CODE) * SMTP_CODE_COUNT));
    if (NULL == g_def_code_table) {
		printf("[resource]: Failed to allocate default code table\n");
        return -1;
    }
    for (i = 0; i < SMTP_CODE_COUNT; i++) {
        g_def_code_table[i].code =
                    g_default_smtp_error_code_table[i].code;

        resource_parse_smtp_line(g_def_code_table[i].comment, 
            g_default_smtp_error_code_table[i].comment, 
            strlen(g_default_smtp_error_code_table[i].comment));
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
static int resource_parse_smtp_line(char* dest, char* src_str, int len)
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

const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len)
{
    SMTP_ERROR_CODE *pitem = NULL;
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
	debug_info("[resource]: rcode does not exist (resource_get_smtp_code)");
    return NULL;
}

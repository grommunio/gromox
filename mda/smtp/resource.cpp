// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamically
 *
 */
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <libHX/string.h>
#include <string>
#include <unordered_map>
#include <utility>
#include "smtp_aux.hpp"
#define MAX_FILE_LINE_LEN       1024

using namespace gromox;

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
	{201, "214 Help available on " DFL_LOGOLINK},
	{202, "220 <domain> Service ready"},
	{203, "221 <domain> Good-bye"},
	{204, "235 Authentication ok, go ahead"},
	{205, "250 Ok"},
	{206, "250 duplicated RCPT"},
	{207, "250 All SMTP buffer cleared"},
	{208, "251 User not local; will forward to <forward-path>"},
	{209, "252 Cannot VRFY user, but will accept message and attempt"},
	{210, "220 Ready to start TLS"},
	{301, "334 VXNlcm5hbWU6"},
	{302, "334 UGFzc3dvcmQ6"},
	{303, "354 Start mail input; end with CRLF.CRLF"},
	{304, "334 OK, go on"},
	{401, "421 <domain> Service not available"},
	{402, "421 <domain> Service not available - Unable to chdir"},
	{403, "421 <domain> Service not available - Unable to read system configuration"},
	{404, "421 <domain> Service not available - Unable to figure out my IP addresses"},
	{405, "421 <domain> Service not available - no valid hosted domain"},
	{406, "421 Too much failure in SMTP session"},
	{407, "421 Access is denied from your IP address <remote_ip> for audit reason, try later"},
	{408, "432 A password transition is needed"},
	{409, "450 Requested mail action not taken"},
	{410, "450 Mailbox <email_addr> is full"},
	{411, "451 Requested action aborted: error in processing;"},
	{412, "451 Timeout"},
	{413, "451 Message doesn't conform to the EMIME standard."},
	{414, "451 Temporary internal failure - queue message failed"},
	{415, "451 Temporary internal failure - database in accessible"},
	{416, "452 Temporary internal failure - out of memory"},
	{417, "452 Temporary internal failure - insufficient system storage"},
	{418, "452 Temporary internal failure - failed to initialize TLS"},
	{419, "452 too many RCPTs"},
	{420, "453 Access is denied - sender is in the audit blacklist, try later"},
	{501, "500 syntax error - invalid character"},
	{502, "500 syntax error - line too long"},
	{503, "500 syntax error - command unrecognized"},
	{504, "501 Remote abort the authentication"},
	{505, "501 Syntax error in parameters or arguments"},
	{506, "502 Command not implemented"},
	{507, "503 Bad sequence of commands"},
	{508, "503 Bad sequence of commands MAIL first"},
	{509, "503 Bad sequence of commands RCPT first"},
	{510, "504 Command parameter not implemented"},
	{511, "504 Unrecognized authentication type"},
	{512, "521 Access is denied from your IP address <remote_ip>"},
	{513, "530 Authentication required", },
	{514, "534 Authentication mechanism is too weak"},
	{515, "538 Encryption required for requested authentication mechanism"},
	{516, "550 invalid user - <email_addr>"},
	{517, "550 Mailbox <email_addr> is full"},
	{518, "550 access denied to you"},
	{519, "550 Access to Mailbox <email_addr>  is denied"},
	{520, "550 Must issue a STARTTLS command first"},
	{521, "552 message exceeds fixed maximum message size"},
	{522, "553 Requested action not taken: mailbox name not allowed"},
	{523, "553 Access is denied - sender is in the blacklist"},
	{524, "553 Access is denied - please use the smtp server instead of MX"},
	{525, "554 Requested mail action aborted: exceeded storage allocation; too much mail data"},
	{526, "554 too many hops, this message is looping"},
	{527, "554 no valid recipients"},
	{528, "554 Authentication has failed too many times"},
	{529, "554 Too many MAIL transactions in the same connection"},
	{530, "554 Invalid EHLO/HELO FQDN host"},
	{531, "554 Relay from your IP address <remote_ip> is denied"},
	{532, "554 Relay from your addr <revserse_address> is denied"},
	{533, "554 Relay to <relay_address> is denied"},
	{534, "554 RCPT <forward-address> is in the blacklist"},
	{535, "554 Temporary authentication failure"},
	{536, "554 Message is infected by virus"},
};

static std::unordered_map<unsigned int, std::string> g_def_code_table;

int resource_run()
{
	for (size_t i = 0; i < GX_ARRAY_SIZE(g_default_code_table); ++i)
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    return 0;
}

void resource_stop()
{
	g_def_code_table.clear();
}

const char *resource_get_smtp_code(unsigned int code_type, unsigned int n, size_t *len)
{
#define FIRST_PART      1
#define SECOND_PART     2
	auto it = g_def_code_table.find(code_type);
	if (it == g_def_code_table.end())
		return "OMG";
	int ret_len = it->second[0];
	auto ret_ptr = &it->second[1];
    if (FIRST_PART == n)    {
        *len = ret_len - 1;
        return ret_ptr;
    }
    if (SECOND_PART == n)   {
        ret_ptr = ret_ptr + ret_len + 1;
		ret_len = it->second[ret_len+1];
        if (ret_len > 0) {
            *len = ret_len - 1;
            return ret_ptr;
        }
    }
	debug_info("[resource]: rcode does not exist (resource_get_smtp_code)");
    return NULL;
}

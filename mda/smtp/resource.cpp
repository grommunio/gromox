// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
/*
 *  user config resource file, which provide some interface for 
 *  programmer to set and get the configuration dynamicly
 *
 */
#include <cerrno>
#include <string>
#include <unordered_map>
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

static constexpr std::pair<unsigned int, const char *> g_default_code_table[] = {
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

static std::unordered_map<unsigned int, std::string> g_def_code_table;

int resource_run()
{
	for (size_t i = 0; i < GX_ARRAY_SIZE(g_default_code_table); ++i)
		g_def_code_table.emplace(g_default_code_table[i].first,
			resource_parse_stcode_line(g_default_code_table[i].second));
    return 0;
}

int resource_stop()
{
	g_def_code_table.clear();
    return 0;
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

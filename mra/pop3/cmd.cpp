// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2021–2025 grommunio GmbH
// This file is part of Gromox.
/* 
 * collection of functions for handling the pop3 command
 */ 
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <libHX/io.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/authmgr.hpp>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/config_file.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/fileio.h>
#include <gromox/mail_func.hpp>
#include <gromox/midb_agent.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>
#include "pop3.hpp"

using namespace std::string_literals;
using namespace gromox;
namespace exmdb_client = exmdb_client_remote;

template<typename T> static inline T *sa_get_item(std::vector<T> &arr, size_t idx)
{
	return idx < arr.size() ? &arr[idx] : nullptr;
}

int cmdh_capa(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	char buff[256];

	snprintf(buff, sizeof(buff),
			"+OK capability list follows\r\n"
			"STLS\r\n"
			"TOP\r\n"
			"USER\r\n"
			"PIPELINING\r\n"
			"UIDL\r\n"
			"TOP\r\n");
	if (parse_bool(g_config_file->get_value("enable_capa_implementation")))
		snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff),
			"IMPLEMENTATION gromox-pop3-%s\r\n",
			PACKAGE_VERSION);
	snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff), ".\r\n");
	pcontext->connection.write(buff, strlen(buff));
	return DISPATCH_CONTINUE;
}

int cmdh_stls(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (pcontext->connection.ssl != nullptr)
		return 1703;
	if (!g_support_tls)
		return 1703;
	if (pcontext->is_login)
		return 1725;
	pcontext->is_stls = TRUE;
	return 1724;
}

int cmdh_user(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	size_t string_length = 0;
	char buff[1024];
    
	if (g_support_tls && g_force_tls && pcontext->connection.ssl == nullptr)
		return 1726;
	if (argv.size() < 2)
		return 1704;
	if (pcontext->is_login)
		return 1720;
	gx_strlcpy(pcontext->username, argv[1].c_str(), std::size(pcontext->username));
	if (!system_services_judge_user(pcontext->username)) {
		string_length = sprintf(buff, "%s%s%s",
				resource_get_pop3_code(1717, 1, &string_length),
				pcontext->username,
				resource_get_pop3_code(1717, 2, &string_length));
		pcontext->connection.write(buff, string_length);
		pop3_parser_log_info(pcontext, LV_WARN, "user %s is denied by user filter",
				pcontext->username);
		return DISPATCH_SHOULD_CLOSE;
	}
	return 1700;
}    

static bool store_owner_over(const char *actor, const char *mbox, const char *mboxdir)
{
	if (mbox == nullptr)
		return true; /* No impersonation of another store */
	if (strcmp(actor, mbox) == 0)
		return true; /* Silly way of logging in to your own mailbox but ok */
	uint32_t perms = 0;
	xrpc_build_env();
	auto ok = exmdb_client::get_mbox_perm(mboxdir, actor, &perms) &&
	          perms & frightsGromoxStoreOwner;
	xrpc_free_env();
	return ok;
}

int cmdh_pass(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() < 2)
		return 1704;
	if (pcontext->is_login)
		return 1720;
	auto target_mbox = strchr(pcontext->username, '!');
	if (target_mbox != nullptr)
		*target_mbox++ = '\0';
	if (*pcontext->username == '\0')
		return 1705;
	
	sql_meta_result mres_auth, mres /* target */;
	if (!system_services_auth_login(pcontext->username, argv[1].c_str(),
	    USER_PRIVILEGE_POP3, mres_auth)) {
		pop3_parser_log_info(pcontext, LV_WARN, "login rejected: %s",
			mres_auth.errstr.c_str());
		pcontext->auth_times ++;
		if (pcontext->auth_times >= g_max_auth_times) {
			system_services_ban_user(pcontext->username, g_block_auth_fail);
			return 1706 | DISPATCH_SHOULD_CLOSE;
		}
		return 1714 | DISPATCH_CONTINUE;
	}

	safe_memset(argv[1].data(), 0, argv[1].size());
	if (target_mbox == nullptr) {
		mres = std::move(mres_auth);
	} else {
		if (mysql_adaptor_meta(target_mbox, WANTPRIV_METAONLY, mres) != 0)
			return 1715 | DISPATCH_CONTINUE;
		if (!store_owner_over(mres_auth.username.c_str(), mres.username.c_str(),
		    mres.maildir.c_str())) {
			pop3_parser_log_info(pcontext, LV_WARN, "login rejected: %s",
				mres_auth.errstr.c_str());
			pcontext->auth_times ++;
			if (pcontext->auth_times >= g_max_auth_times) {
				system_services_ban_user(pcontext->username, g_block_auth_fail);
				return 1706 | DISPATCH_SHOULD_CLOSE;
			}
			return 1714 | DISPATCH_CONTINUE;
		}
	}
	gx_strlcpy(pcontext->username, mres.username.c_str(), std::size(pcontext->username));
	gx_strlcpy(pcontext->maildir, mres.maildir.c_str(), std::size(pcontext->maildir));
	pcontext->msg_array.clear();
	pcontext->total_size = 0;
	if (*pcontext->maildir == '\0')
		return 1715;

	switch (midb_agent::list_mail(pcontext->maildir, base64_encode("INBOX"),
		pcontext->msg_array, &pcontext->total_mail,
		&pcontext->total_size)) {
	case MIDB_RESULT_OK:
		break;
	case MIDB_NO_SERVER:
		/* write back nothing and close the connection */
		pop3_parser_log_info(pcontext, LV_WARN, "lack of midb connections");
		return DISPATCH_SHOULD_CLOSE;
	case MIDB_RDWR_ERROR:
		/* write back nothing and close the connection */
		pop3_parser_log_info(pcontext, LV_WARN, "read write error with midb server");
		return DISPATCH_SHOULD_CLOSE;
	case MIDB_RESULT_ERROR:
		/* write back nothing and close the connection */
		pop3_parser_log_info(pcontext, LV_WARN, "midb returned error result");
		return DISPATCH_SHOULD_CLOSE;
	case MIDB_TOO_MANY_RESULTS:
		pop3_parser_log_info(pcontext, LV_WARN, "Too many messages in folder");
		return DISPATCH_SHOULD_CLOSE;
	default:
		return DISPATCH_SHOULD_CLOSE;
	}
	if (pcontext->total_mail < 0 ||
	    pcontext->msg_array.size() != static_cast<size_t>(pcontext->total_mail))
		return 1722;
	pcontext->is_login = TRUE;
	pop3_parser_log_info(pcontext, LV_DEBUG, "login ok");
	return 1700;
}

int cmdh_stat(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	size_t string_length = 0;
	char temp_buff[1024];
    
	if (argv.size() != 1)
		return 1704;
	if (!pcontext->is_login)
		return 1708;
	snprintf(temp_buff, sizeof(temp_buff), "+OK %d %llu\r\n",
	         pcontext->total_mail, static_cast<unsigned long long>(pcontext->total_size));
	string_length = strlen(temp_buff);
	pcontext->connection.write(temp_buff, string_length);
    return DISPATCH_CONTINUE;    
}

int cmdh_uidl(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	size_t string_length = 0;
	char temp_buff[1024];
	
	if (argv.size() == 1) {
		if (!pcontext->is_login)
			return 1708;
		pcontext->stream.clear();
		if (pcontext->stream.write("+OK\r\n", 5) != STREAM_WRITE_OK)
			return 1729;

		auto count = pcontext->msg_array.size();
		for (size_t i = 0; i < count; ++i) {
			auto punit = sa_get_item(pcontext->msg_array, i);
			string_length = sprintf(temp_buff, "%zu %s\r\n", i + 1, punit->file_name.c_str());
			if (pcontext->stream.write(temp_buff, string_length) != STREAM_WRITE_OK)
				return 1729;
		}
		if (pcontext->stream.write(".\r\n", 3) != STREAM_WRITE_OK)
			return 1729;
		pcontext->write_offset = 0;
		unsigned int wrlen = MAX_LINE_LENGTH;
		pcontext->write_buff = static_cast<char *>(pcontext->stream.get_read_buf(&wrlen));
		pcontext->write_length = wrlen;
		if (NULL == pcontext->write_buff) {
			pop3_parser_log_info(pcontext, LV_WARN, "error on stream object");
			return 1718;
		}
		return DISPATCH_LIST;
	}
	
	if (argv.size() < 2)
		return 1703;
	if (!pcontext->is_login)
		return 1708;
	int n = strtol(argv[1].c_str(), nullptr, 0);
	if (n > 0 && static_cast<size_t>(n) <= pcontext->msg_array.size()) {
		auto punit = sa_get_item(pcontext->msg_array, n - 1);
		auto z = gx_snprintf(temp_buff, std::size(temp_buff),
		         "+OK %d %s\r\n", n, punit->file_name.c_str());
		pcontext->connection.write(temp_buff, z);
		return DISPATCH_CONTINUE;
	}
	return 1707;
}

int cmdh_list(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	size_t string_length = 0;
	char temp_buff[1024];
	
	if (argv.size() == 1) {
		if (!pcontext->is_login)
			return 1708;
		pcontext->stream.clear();
		if (pcontext->stream.write("+OK\r\n", 5) != STREAM_WRITE_OK)
			return 1729;
		
		auto count = pcontext->msg_array.size();
		for (size_t i = 0; i < count; ++i) {
			auto punit = sa_get_item(pcontext->msg_array, i);
			string_length = sprintf(temp_buff, "%zu %zu\r\n", i + 1, punit->size);
			if (pcontext->stream.write(temp_buff, string_length) != STREAM_WRITE_OK)
				return 1729;
		}
		if (pcontext->stream.write(".\r\n", 3) != STREAM_WRITE_OK)
			return 1729;
		pcontext->write_offset = 0;
		unsigned int maxbufsize = MAX_LINE_LENGTH;
		pcontext->write_buff = static_cast<char *>(pcontext->stream.get_read_buf(&maxbufsize));
		pcontext->write_length = maxbufsize;
		if (NULL == pcontext->write_buff) {
			pop3_parser_log_info(pcontext, LV_WARN, "error on stream object");
			return 1718;
		}
		return DISPATCH_LIST;
	}
	
	if (argv.size() < 2)
		return 1703;
	if (!pcontext->is_login)
		return 1708;
	int n = strtol(argv[1].c_str(), nullptr, 0);
	if (n > 0 && static_cast<size_t>(n) <= pcontext->msg_array.size()) {
		auto punit = sa_get_item(pcontext->msg_array, n - 1);
		string_length = sprintf(temp_buff, "+OK %d %zu\r\n", n, punit->size);	
		pcontext->connection.write(temp_buff, string_length);
		return DISPATCH_CONTINUE;
	}
	return 1707;
}

int cmdh_retr(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() < 2)
		return 1704;
	if (!pcontext->is_login)
		return 1708;
	
	auto &ctx = *pcontext;
	int n = strtol(argv[1].c_str(), nullptr, 0);
	pcontext->cur_line = -1;
	pcontext->until_line = 0x7FFFFFFF;
	if (n <= 0 || static_cast<size_t>(n) > pcontext->msg_array.size())
		return 1707;
	auto punit = sa_get_item(pcontext->msg_array, n - 1);
	std::string eml_path;
	ctx.wrdat_active = false;
	ctx.wrdat_content.clear();
	if (!exmdb_client::imapfile_read(ctx.maildir, "eml", punit->file_name,
	    &ctx.wrdat_content)) {
		mlog(LV_ERR, "E-1469: imapfile_read %s/eml/%s failed",
			ctx.maildir, punit->file_name.c_str());
		return 1709;
	}
	ctx.wrdat_active = true;
	ctx.wrdat_offset = 0;
	pcontext->stream.clear();
	if (pcontext->stream.write("+OK\r\n", 5) != STREAM_WRITE_OK)
		return 1729;
	if (POP3_RETRIEVE_ERROR == pop3_parser_retrieve(pcontext)) {
		pcontext->stream.clear();
		return 1719;
	}
	pop3_parser_log_info(pcontext, LV_DEBUG,
		"message %s is going to be retrieved", eml_path.c_str());
	return DISPATCH_DATA;
}

int cmdh_dele(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() < 2)
		return 1704;
	if (!pcontext->is_login)
		return 1708;
	
	int n = strtol(argv[1].c_str(), nullptr, 0);
	if (n <= 0 || static_cast<size_t>(n) > pcontext->msg_array.size())
		return 1707;
	auto punit = sa_get_item(pcontext->msg_array, n - 1);
	if (!punit->b_deleted) try {
		punit->b_deleted = TRUE;
		pcontext->delmsg_list.push_back(punit);
	} catch (const std::bad_alloc &) {
		mlog(LV_ERR, "E-1961: ENOMEM");
		return 1915;
	}
	return 1700;
}

int cmdh_top(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() < 2)
		return 1704;
	if (!pcontext->is_login)
		return 1708;
	
	auto &ctx = *pcontext;
	int n = strtol(argv[1].c_str(), nullptr, 0);
	pcontext->until_line = argv.size() >= 3 ? strtol(argv[2].c_str(), nullptr, 0) : 0x7FFFFFFF;
	pcontext->cur_line = -1;
	if (n <= 0 || static_cast<size_t>(n) > pcontext->msg_array.size())
		return 1707;
	auto punit = &pcontext->msg_array.at(n - 1);
	std::string eml_path;
	ctx.wrdat_active = false;
	ctx.wrdat_content.clear();
	xrpc_build_env();
	auto cl_0 = make_scope_exit(xrpc_free_env);
	if (!exmdb_client::imapfile_read(ctx.maildir, "eml", punit->file_name,
	    &ctx.wrdat_content))
		return 1709;
	ctx.wrdat_active = true;
	ctx.wrdat_offset = 0;
	pcontext->stream.clear();
	if (pcontext->stream.write("+OK\r\n", 5) != STREAM_WRITE_OK)
		return 1729;
	if (POP3_RETRIEVE_ERROR == pop3_parser_retrieve(pcontext)) {
		pcontext->stream.clear();
		return 1719;
	}
	return DISPATCH_DATA;
}

int cmdh_quit(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	size_t string_length = 0;
	char temp_buff[1024];
    
	if (argv.size() != 1)
		return 1704;
	if (pcontext->is_login && pcontext->delmsg_list.size() > 0) {
		switch (midb_agent::delete_mail(pcontext->maildir, base64_encode("INBOX"),
			pcontext->delmsg_list)) {
		case MIDB_RESULT_OK:
			break;
		case MIDB_NO_SERVER:
			return 1716 | DISPATCH_SHOULD_CLOSE;
		case MIDB_RDWR_ERROR:
			pop3_parser_log_info(pcontext, LV_WARN, "failed RW I/O with midb server");
			return 1721 | DISPATCH_SHOULD_CLOSE;
		case MIDB_RESULT_ERROR:
			pop3_parser_log_info(pcontext, LV_WARN, "failed to execute delete command on midb server");
			return 1722 | DISPATCH_SHOULD_CLOSE;
		case MIDB_LOCAL_ENOMEM:
			return 1728 | DISPATCH_SHOULD_CLOSE;
		default:
			return 1727 | DISPATCH_SHOULD_CLOSE;
		}
		string_length = gx_snprintf(temp_buff, std::size(temp_buff),
			"FOLDER-TOUCH %s inbox", pcontext->username);
		system_services_broadcast_event(temp_buff);

		for (auto punit : pcontext->delmsg_list) try {
			auto eml_path = std::string(pcontext->maildir) + "/eml/" + punit->file_name;
			if (remove(eml_path.c_str()) == 0)
				pop3_parser_log_info(pcontext, LV_DEBUG, "message %s has been deleted",
					eml_path.c_str());
		} catch (const std::bad_alloc &) {
			mlog(LV_ERR, "E-1471: ENOMEM");
		}
		pcontext->delmsg_list.clear();
	}

	pcontext->msg_array.clear();
	sprintf(temp_buff, "%s%s%s", resource_get_pop3_code(1710, 1,
		&string_length), znul(g_config_file->get_value("host_id")),
			resource_get_pop3_code(1710, 2, &string_length));
	pcontext->connection.write(temp_buff, strlen(temp_buff));
	return DISPATCH_SHOULD_CLOSE;
	
}

int cmdh_rset(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() != 1)
		return 1704;
	if (pcontext->is_login)
		for (auto m : pcontext->delmsg_list)
			m->b_deleted = false;
	return 1700;
}    

int cmdh_noop(std::vector<std::string> &&argv, pop3_context *pcontext)
{
	if (argv.size() != 1)
		return 1704;
	return 1700;
}

int cmdh_else(std::vector<std::string> &&argv, pop3_context *pcontext)
{
    /* command not implement*/
	return 1703;
}

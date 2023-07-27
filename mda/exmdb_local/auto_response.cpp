// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace gromox;
namespace exmdb_client = exmdb_client_remote;
unsigned int autoreply_silence_window;

void auto_response_reply(const char *user_home,
    const char *from, const char *rcpt) try
{
	BOOL b_found;
	char *pcontent;
	BOOL b_internal;
	char charset[32]{};
	struct tm tm_buff;
	int i, j, fd, len;
	char subject[1024];
	char buff[64*1024];
	char date_buff[128];
	char temp_path[256];
	MIME_FIELD mime_field;
	struct stat node_stat;
	char content_type[256];
	char template_path[256];
	char new_buff[128*1024];
	MESSAGE_CONTEXT *pcontext;

	if (strcasecmp(from, rcpt) == 0 || strcasecmp(rcpt, ENVELOPE_RCPT_NULL) == 0)
		return;
	auto ptoken = strchr(from, '@');
	auto ptoken1 = strchr(rcpt, '@');
	if (NULL == ptoken || NULL == ptoken1) {
		return;
	}

	if (0 == strcasecmp(ptoken, ptoken1)) {
		b_internal = TRUE;
	} else {
		auto lcldom = exmdb_local_check_domain(ptoken + 1);
		if (lcldom < 0) {
			mlog(LV_ERR, "auto_response: check_domain: %s",
			        strerror(-lcldom));
			return;
		}
		b_internal = lcldom < 1 ? false :
		             exmdb_local_check_same_org2(ptoken + 1, ptoken1 + 1);
	}
	
	snprintf(temp_path, 256, "%s/config/autoreply.cfg", user_home);
	auto pconfig = config_file_init(temp_path, nullptr);
	if (NULL == pconfig) {
		return;
	}
	auto str_value = pconfig->get_value("OOF_STATE");
	if (NULL == str_value) {
		return;
	}
	uint8_t reply_state = strtol(str_value, nullptr, 0);
	if (1 != reply_state && 2 != reply_state) {
		return;
	}
	auto cur_time = time(nullptr);
	if (2 == reply_state) {
		str_value = pconfig->get_value("START_TIME");
		if (str_value != nullptr && strtoll(str_value, nullptr, 0) > cur_time)
			return;
		str_value = pconfig->get_value("END_TIME");
		if (str_value != nullptr && cur_time > strtoll(str_value, nullptr, 0))
			return;
	}
	if (b_internal) {
		snprintf(template_path, 256, "%s/config/internal-reply", user_home);
	} else {
		str_value = pconfig->get_value("ALLOW_EXTERNAL_OOF");
		if (str_value == nullptr || strtol(str_value, nullptr, 0) == 0)
			return;
		str_value = pconfig->get_value("EXTERNAL_AUDIENCE");
		if (str_value != nullptr && strtol(str_value, nullptr, 0) != 0) {
			if (!exmdb_client_remote::check_contact_address(user_home, rcpt,
			    &b_found) || !b_found)
				return;	
		}
		snprintf(template_path, 256, "%s/config/external-reply", user_home);
	}

	uint64_t tdiff;
	if (exmdb_client::autoreply_tsquery(user_home, rcpt,
	    autoreply_silence_window, &tdiff) && tdiff < autoreply_silence_window)
		/* Autoreply already sent */
		return;
	fd = open(template_path, O_RDONLY);
	if (-1 == fd) {
		return;
	}
	if (fstat(fd, &node_stat) != 0 || node_stat.st_size == 0 ||
	    static_cast<unsigned long long>(node_stat.st_size) > sizeof(buff) - 1 ||
	    read(fd, buff, node_stat.st_size) != node_stat.st_size) {
		close(fd);
		return;
	}
	close(fd);

	if ('\n' == buff[0]) {
		new_buff[0] = '\r';
		new_buff[1] = '\n';
		i = 1;
		j = 2;
	} else {
		new_buff[0] = buff[0];
		i = 1;
		j = 1;
	}
	for (; i<node_stat.st_size; i++, j++) {
		if ('\n' == buff[i] && '\r' != buff[i - 1]) {
			new_buff[j++] = '\r';
		}
		new_buff[j] = buff[i];
	}
	new_buff[j] = '\0';


	i = 0;
	pcontent = NULL;
	strcpy(content_type, "text/plain");
	strcpy(subject, "auto response message");
	while (i < j) {
		auto parsed_length = parse_mime_field(new_buff + i, j - i, &mime_field);
		i += parsed_length;
		if (0 != parsed_length) {
			if (strcasecmp(mime_field.name.c_str(), "Content-Type") == 0) {
				gx_strlcpy(content_type, mime_field.value.c_str(), std::size(content_type));
				charset[0] = '\0';
				auto ptoken2 = strchr(content_type, ';');
				if (ptoken2 != nullptr) {
					*ptoken2 = '\0';
					++ptoken2;
					ptoken2 = strcasestr(ptoken2, "charset=");
					if (ptoken2 != nullptr) {
						gx_strlcpy(charset, &ptoken2[8], std::size(charset));
						ptoken2 = strchr(charset, ';');
						if (ptoken2 != nullptr)
							*ptoken2 = '\0';
						HX_strrtrim(charset);
						HX_strltrim(charset);
						len = strlen(charset);
						if ('"' == charset[len - 1]) {
							len --;
							charset[len] = '\0';
						}
						if ('"' == charset[0]) {
							memmove(charset, charset + 1, len);
						}
					}
				}
			} else if (strcasecmp(mime_field.name.c_str(), "Subject") == 0) {
				gx_strlcpy(subject, mime_field.value.c_str(), std::size(subject));
			}
			if ('\r' == new_buff[i] && '\n' == new_buff[i + 1]) {
				pcontent = new_buff + i + 2;
				break;
			}
		} else {
			return;
		}
	}
	if (NULL == pcontent) {
		return;
	}
	pcontext = get_context();
	if (NULL == pcontext) {
		return;
	}
	auto pdomain = strchr(from, '@') + 1;
	snprintf(pcontext->ctrl.from, std::size(pcontext->ctrl.from), "auto-reply@%s", pdomain);
	pcontext->ctrl.rcpt.emplace_back(rcpt);
	auto pmime = pcontext->mail.add_head();
	if (NULL == pmime) {
		put_context(pcontext);
		return;
	}
	pmime->set_content_type(content_type);
	if ('\0' != charset[0]) {
		pmime->set_content_param("charset", charset);
	}
	pmime->set_field("From", from);
	pmime->set_field("To", rcpt);
	pmime->set_field("MIME-Version", "1.0");
	pmime->set_field("X-Auto-Response-Suppress", "All");
	strftime(date_buff, 128, "%a, %d %b %Y %H:%M:%S %z",
		localtime_r(&cur_time, &tm_buff));
	pmime->set_field("Date", date_buff);
	pmime->set_field("Subject", subject);
	if (!pmime->write_content(pcontent,
	    new_buff + j - pcontent, mime_encoding::automatic)) {
		put_context(pcontext);
		return;
	}
	enqueue_context(pcontext);
	exmdb_client::autoreply_tsupdate(user_home, rcpt);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1081: ENOMEM");
}

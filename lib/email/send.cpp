// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <vmime/mailbox.hpp>
#include <vmime/mailboxList.hpp>
#include <vmime/net/transport.hpp>
#include <vmime/utility/inputStreamStringAdapter.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapierr.hpp>

namespace gromox {

ec_error_t cu_send_mail(MAIL &mail, const char *smtp_url, const char *sender,
    const std::vector<std::string> &rcpt_list) try
{
	if (*sender == '\0') {
		mlog(LV_ERR, "cu_send_mail: empty envelope-from\n");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (rcpt_list.size() == 0) {
		mlog(LV_ERR, "cu_send_mail: empty envelope-rcpt\n");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (*smtp_url == '\0') {
		mlog(LV_ERR, "cu_send_mail: no SMTP target given\n");
		return MAPI_W_NO_SERVICE;
	}
	vmime::mailbox vsender(sender);
	vmime::mailboxList vrcpt_list;
	for (const auto &r : rcpt_list)
		vrcpt_list.appendMailbox(vmime::make_shared<vmime::mailbox>(r));
	std::string content;
	auto xwrite = +[](void *fd, const void *buf, size_t z) -> ssize_t {
		try {
			static_cast<std::string *>(fd)->append(static_cast<const char *>(buf), z);
		} catch (const std::bad_alloc &) {
			errno = ENOMEM;
			return -1;
		}
		return z;
	};
	if (!mail.emit(xwrite, &content)) {
		mlog(LV_ERR, "cu_send_mail: mail.serialize failed\n");
		return MAPI_W_NO_SERVICE;
	}
	vmime::utility::inputStreamStringAdapter ct_adap(content); /* copies */
	content.clear();
	auto xprt = vmime::net::session::create()->getTransport(vmime::utility::url(smtp_url));
	try {
		/* vmime default timeout is 30s */
		xprt->connect();
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.connect %s: %s", smtp_url, e.what());
		return MAPI_W_NO_SERVICE;
	}
	try {
		xprt->send(vsender, vrcpt_list, ct_adap, content.size(), nullptr, {}, {});
		xprt->disconnect();
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.send: %s", e.what());
		return MAPI_W_CANCEL_MESSAGE;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1196: ENOMEM");
	return ecServerOOM;
}

}

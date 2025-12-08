// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <openssl/ssl.h>
#include <vmime/exception.hpp>
#include <vmime/mailbox.hpp>
#include <vmime/mailboxList.hpp>
#include <vmime/message.hpp>
#include <vmime/net/service.hpp>
#include <vmime/net/transport.hpp>
#include <vmime/security/cert/certificateVerifier.hpp>
#include <vmime/utility/inputStreamStringAdapter.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/usercvt.hpp>
#if defined(VMIME_HAVE_TLS_SUPPORT) && VMIME_HAVE_TLS_SUPPORT
#	define WITH_TLS 1
#else
#	define WITH_TLS 0
#endif

namespace gromox {

static bool mapi_p1(const TPROPVAL_ARRAY &props)
{
	auto t = props.get<const uint32_t>(PR_RECIPIENT_TYPE);
	return t != nullptr && *t & MAPI_P1;
}

#if 0
static bool xp_is_in_charge(const TPROPVAL_ARRAY &props)
{
	auto v = props.get<const uint32_t>(PR_RESPONSIBILITY);
	return v == nullptr || *v != 0;
}
#endif

ec_error_t cu_rcpt_to_list(const TPROPVAL_ARRAY &props, const char *org_name,
    std::vector<std::string> &list, GET_USERNAME id2user, bool resend) try
{
	if (resend && !mapi_p1(props))
		return ecSuccess;
	/*
	if (!b_submit && xp_is_in_charge(rcpt))
		return ecSuccess;
	*/
	auto str = props.get<const char>(PR_SMTP_ADDRESS);
	if (str != nullptr && *str != '\0') {
		list.emplace_back(str);
		return ecSuccess;
	}
	auto addrtype = props.get<const char>(PR_ADDRTYPE);
	auto emaddr   = props.get<const char>(PR_EMAIL_ADDRESS);
	std::string es_result;
	if (addrtype != nullptr) {
		auto ret = cvt_genaddr_to_smtpaddr(addrtype, emaddr, org_name,
		           id2user, es_result);
		if (ret == ecSuccess) {
			list.emplace_back(std::move(es_result));
			return ecSuccess;
		} else if (ret != ecNullObject) {
			return ret;
		}
	}
	auto ret = cvt_entryid_to_smtpaddr(props.get<const BINARY>(PR_ENTRYID),
	           org_name, id2user, es_result);
	if (ret == ecSuccess)
		list.emplace_back(std::move(es_result));
	return ret == ecNullObject || ret == ecUnknownUser ? ecInvalidRecips : ret;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

static vmime::shared_ptr<vmime::net::transport> make_transport(const char *url)
{
	vmime::utility::url vurl(url);
	bool uv  = strncmp(url, "smtp+unverifiedtls:", 9) == 0;
	bool tls = uv || strncmp(url, "smtp+tls:", 9) == 0;
	if (tls) {
#if WITH_TLS
		vurl.setProtocol("smtp");
		mlog(LV_ERR, "Unable to create vmime transport for \"%s\": "
			"vmime/wmime was built without TLS", url);
#else
		return nullptr;
#endif
	}
	auto xp = vmime::net::session::create()->getTransport(std::move(vurl));
	if (!tls)
		return xp;
#if WITH_TLS
	xp->setProperty("connection.tls", true);
	if (!uv)
		return xp;

	struct uv_impl : public vmime::security::cert::certificateVerifier {
		void verify(const vmime::shared_ptr<vmime::security::cert::certificateChain> &chain, const std::string &host) {}
	};
	xp->setCertificateVerifier(vmime::make_shared<uv_impl>());
	return xp;
#else
	return nullptr;
#endif
}

ec_error_t cu_send_mail(const MAIL &mail, const char *smtp_url, const char *sender,
    const std::vector<std::string> &rcpt_list) try
{
	if (*sender == '\0') {
		mlog(LV_ERR, "cu_send_mail: empty envelope-from");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (rcpt_list.size() == 0) {
		mlog(LV_ERR, "cu_send_mail: empty envelope-rcpt");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (*smtp_url == '\0') {
		mlog(LV_ERR, "cu_send_mail: no SMTP target given");
		return MAPI_W_NO_SERVICE;
	}
	vmime::mailbox vsender(sender);
	vmime::mailboxList vrcpt_list;
	for (const auto &r : rcpt_list)
		vrcpt_list.appendMailbox(vmime::make_shared<vmime::mailbox>(r));
	std::string content;
	auto err = mail.to_str(content);
	if (err != 0) {
		mlog(LV_ERR, "cu_send_mail: mail.serialize failed: %s", strerror(errno));
		return MAPI_W_NO_SERVICE;
	}
	vmime::utility::inputStreamStringAdapter ct_adap(content); /* copies */
	content.clear();
	vmime::shared_ptr<vmime::net::transport> xprt;
	try {
		xprt = make_transport(smtp_url);
		/* vmime default timeout is 30s */
		xprt->connect();
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.connect %s: %s", smtp_url, e.what());
		return MAPI_W_NO_SERVICE;
	}
	try {
		xprt->send(vsender, vrcpt_list, ct_adap, content.size(), nullptr, {}, {});
		xprt->disconnect();
	} catch (const vmime::exceptions::command_error &e) {
		mlog(LV_ERR, "vmime.send: %s: %s", e.command().c_str(), e.response().c_str());
		return MAPI_W_CANCEL_MESSAGE;
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.send: %s", e.what());
		return MAPI_W_CANCEL_MESSAGE;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

ec_error_t cu_send_vmail(vmime::shared_ptr<vmime::message> msg,
    const char *smtp_url, const char *sender,
    const std::vector<std::string> &rcpt_list) try
{
	if (*sender == '\0') {
		mlog(LV_ERR, "cu_send_mail: empty envelope-from");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (rcpt_list.size() == 0) {
		mlog(LV_ERR, "cu_send_mail: empty envelope-rcpt");
		return MAPI_W_CANCEL_MESSAGE;
	} else if (*smtp_url == '\0') {
		mlog(LV_ERR, "cu_send_mail: no SMTP target given");
		return MAPI_W_NO_SERVICE;
	}
	vmime::mailbox vsender(sender);
	vmime::mailboxList vrcpt_list;
	for (const auto &r : rcpt_list)
		vrcpt_list.appendMailbox(vmime::make_shared<vmime::mailbox>(r));
	vmime::shared_ptr<vmime::net::transport> xprt;
	try {
		xprt = make_transport(smtp_url);
		/* vmime default timeout is 30s */
		xprt->connect();
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.connect %s: %s", smtp_url, e.what());
		return MAPI_W_NO_SERVICE;
	}
	try {
		xprt->send(std::move(msg), vsender, vrcpt_list, nullptr, {}, {});
		xprt->disconnect();
	} catch (const vmime::exceptions::command_error &e) {
		mlog(LV_ERR, "vmime.send: %s: %s", e.command().c_str(), e.response().c_str());
		return MAPI_W_CANCEL_MESSAGE;
	} catch (const vmime::exception &e) {
		mlog(LV_ERR, "vmime.send: %s", e.what());
		return MAPI_W_CANCEL_MESSAGE;
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

}

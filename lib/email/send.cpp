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
#include <gromox/svc_loader.hpp>
#include <gromox/usercvt.hpp>
#if defined(VMIME_HAVE_TLS_SUPPORT) && VMIME_HAVE_TLS_SUPPORT
#	define WITH_TLS 1
#else
#	define WITH_TLS 0
#endif

namespace gromox {

/*
 * Per-domain SMTP gateway resolution (grommunio-admin API).
 *
 * Resolves the URL to use for outbound delivery by checking the
 * grommunio `domain_smtp_gateway` table. The actual lookup
 * (including URL building) is implemented in libgxs_mysql_adaptor
 * and exposed through the service registry as
 * `resolve_smtp_url_for_sender`. This indirection avoids a
 * link-time circular dependency between libgromox_mapi and
 * libgxs_mysql_adaptor.
 *
 * The function pointer is looked up once on first use and cached
 * for the lifetime of the process. The resolved URL is stored in
 * a thread_local buffer so that it stays alive for the duration
 * of the call (until `make_transport` has consumed the C string).
 *
 * If the service is not registered (e.g. in a unit test that
 * does not load libgxs_mysql_adaptor) the function simply
 * returns the fallback URL unchanged.
 */
static const char *resolve_smtp_url(const char *sender, const char *fallback,
    std::string &out)
{
	out.clear();
	if (sender == nullptr || *sender == '\0' || fallback == nullptr)
		return fallback;
	using resolve_fn = const char *(*)(const char *, const char *);
	static resolve_fn pfn = nullptr;
	static bool lookup_done = false;
	if (!lookup_done) {
		/* Use typeid(*pfn) (function type, not pointer-to-function
		 * type) so that the mangled typeid name matches the one
		 * the register_service() macro produces on the provider
		 * side; otherwise the registry complains about a type
		 * mismatch on dlname "resolve_smtp_url_for_sender". */
		pfn = reinterpret_cast<resolve_fn>(service_query(
		    "resolve_smtp_url_for_sender",
		    typeid(*pfn)));
		lookup_done = true;
	}
	if (pfn == nullptr)
		return fallback;
	const char *resolved = pfn(sender, fallback);
	if (resolved == nullptr)
		return fallback;
	/* The service returns a thread-stable C string (the
	 * per-thread buffer it owns); we copy into our own buffer
	 * so callers don't have to worry about service-side
	 * lifetime. */
	out = resolved;
	return out.c_str();
}

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
#else
		mlog(LV_ERR, "Unable to create vmime transport for \"%s\": "
			"vmime/wmime was built without TLS", url);
		return nullptr;
#endif
	}
	auto sess = vmime::net::session::create();
	/* We have to force vmime to actually do AUTH. By default
	 * (options.need-authentication=false) it skips AUTH entirely
	 * even if the URL contains credentials. The credentials were
	 * already copied into the session properties by
	 * serviceFactory::create(url), so we only need to flip the
	 * flag here. */
	if (!vurl.getUsername().empty()) {
		mlog(LV_NOTICE, "smtp: URL has credentials, will require authentication");
		sess->getProperties()["transport.smtp.options.need-authentication"] = true;
		sess->getProperties()["transport.smtps.options.need-authentication"] = true;
	}
	auto xp = sess->getTransport(std::move(vurl), vmime::shared_ptr<vmime::security::authenticator>());
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

static void transform_lf_to_crlf(std::string &str)
{
	size_t pos = 0;
	while (true) {
		pos = str.find('\n', pos);
		if (pos == std::string::npos)
			return;
		auto have_cr = pos > 0 && str[pos-1] == '\r';
		if (!have_cr)
			str.insert(pos++, "\r");
		++pos;
	}
}

ec_error_t cu_send_mail(const MAIL &mail, const char *smtp_url, const char *sender,
    const std::vector<std::string> &rcpt_list) try
{
	/* Per-domain SMTP gateway resolution (grommunio-admin API). */
	static thread_local std::string resolved_url;
	smtp_url = resolve_smtp_url(sender, smtp_url, resolved_url);
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

	/* vmime has a LFToCRLFFilteredOutputStream, but nothing for input */
	transform_lf_to_crlf(content);
	vmime::utility::inputStreamStringAdapter ct_adap(content); /* copies */
	content.clear();
	vmime::shared_ptr<vmime::net::transport> xprt;
	try {
		xprt = make_transport(smtp_url);
		if (xprt == nullptr)
			return MAPI_W_NO_SERVICE;
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
	/* Per-domain SMTP gateway resolution (grommunio-admin API). */
	static thread_local std::string resolved_url;
	smtp_url = resolve_smtp_url(sender, smtp_url, resolved_url);
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
		if (xprt == nullptr)
			return MAPI_W_NO_SERVICE;
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

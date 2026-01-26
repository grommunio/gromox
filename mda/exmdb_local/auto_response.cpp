// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstring>
#include <libHX/string.h>
#include <vmime/addressList.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/message.hpp>
#include <vmime/stringContentHandler.hpp>
#include <gromox/exmdb_client.hpp>
#include <gromox/exmdb_rpc.hpp>
#include <gromox/hook_common.h>
#include <gromox/mail_func.hpp>
#include <gromox/mysql_adaptor.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/util.hpp>
#include "exmdb_local.hpp"

using namespace gromox;
DECLARE_HOOK_API(exmdb_local, extern);
using namespace exmdb_local;
unsigned int autoreply_silence_window;

static int is_same_org(const char *a, const char *b)
{
	a = strchr(a, '@');
	b = strchr(b, '@');
	if (a == nullptr || b == nullptr)
		return -1;
	++a; ++b;
	return strcasecmp(a, b) == 0 ? 1 : mysql_adaptor_check_same_org2(a, b);
}

/**
 * @user_home: Maildir for basically @rcpt
 * @from:      Sender for the autoresponse (Original Envelope-To)
 * @rcpt:      Recipient for the autoresponse (Original Envelope-From)
 */
void auto_response_reply(const char *user_home,
    const char *from, const char *rcpt) try
{
	auto same_org = is_same_org(from, rcpt);
	if (same_org < 0)
		return;

	static constexpr proptag_t tags_1[] = {PR_OOF_STATE};
	TPROPVAL_ARRAY store_props;
	if (!exmdb_client->get_store_properties(user_home, CP_UTF8, tags_1, &store_props)) {
		mlog(LV_ERR, "get_store_properties %s failed", user_home);
		return;
	}
	auto bval = store_props.get<const uint8_t>(PR_OOF_STATE);
	if (bval == nullptr || *bval == 0)
		return;

	/* Elvis has left the building */
	uint64_t tdiff;
	if (exmdb_client->autoreply_tsquery(user_home, rcpt,
	    autoreply_silence_window, &tdiff) && tdiff < autoreply_silence_window)
		/* Autoreply already sent */
		return;

	static constexpr proptag_t tags_2[] = {
		PR_EC_OUTOFOFFICE_SUBJECT, PR_EC_OUTOFOFFICE_MSG,
		PR_EC_ALLOW_EXTERNAL, PR_EC_EXTERNAL_AUDIENCE,
		PR_EC_EXTERNAL_SUBJECT, PR_EC_EXTERNAL_REPLY,
	};
	TPROPVAL_ARRAY ar_props;
	if (!exmdb_client->autoreply_getprop(user_home, CP_UTF8,
	    tags_2, &ar_props)) {
		mlog(LV_ERR, "autoreply_getprop %s failed", user_home);
		return;
	}

	if (!same_org) {
		bval = ar_props.get<const uint8_t>(PR_EC_ALLOW_EXTERNAL);
		if (bval == nullptr || *bval == 0)
			return;
		//Note: counterintuitive but intentional: known (contacts_only) -> 1, all_audiences -> 0
		bval = ar_props.get<const uint8_t>(PR_EC_EXTERNAL_AUDIENCE);
		if (bval != nullptr && *bval != 0) {
			BOOL b_found = false;
			if (!exmdb_client_remote::check_contact_address(user_home, rcpt,
			    &b_found) || !b_found)
				return;
		}
	}

	auto subject_text = znul(ar_props.get<const char>(same_org ? PR_EC_OUTOFOFFICE_SUBJECT : PR_EC_EXTERNAL_SUBJECT));
	auto message_text = znul(ar_props.get<const char>(same_org ? PR_EC_OUTOFOFFICE_MSG : PR_EC_EXTERNAL_REPLY));
	vmime::parsingContext vpctx;
	vpctx.setInternationalizedEmailSupport(true); /* RFC 6532 */
	vmime::message vmsg;

	auto hdr = vmsg.getHeader();
	hdr->getField("MIME-Version")->setValue("1.0");
	hdr->From()->setValue(from);
	{
		vmime::addressList target_list;
		vmime::mailbox target;
		target.setEmail(rcpt);
		target_list.appendAddress(vmime::make_shared<vmime::mailbox>(target));
		hdr->To()->setValue(target_list);
	}
	hdr->getField("X-Auto-Response-Suppress")->setValue("All");
	hdr->Date()->setValue(vmime::datetime::now());
	hdr->Subject()->setValue(vmime::text(subject_text, vmime::charsets::UTF_8));

	vmime::encoding enc;
	enc.setUsage(vmime::encoding::EncodingUsage::USAGE_TEXT);
	vmsg.getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(message_text, std::move(enc)),
                vmime::mediaType(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_HTML),
                vmime::charsets::UTF_8);

	auto ctx = get_context();
	if (ctx == nullptr)
		return;
	gx_strlcpy(ctx->ctrl.from, from, std::size(ctx->ctrl.from));
	ctx->ctrl.rcpt.emplace_back(rcpt);
	if (!vmail_to_mail(vmsg, ctx->mail)) {
		mlog(LV_ERR, "%s: vmail_to_mail failed", __func__);
		put_context(ctx);
		return;
	}
	enqueue_context(ctx);
	exmdb_client->autoreply_tsupdate(user_home, rcpt);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
}

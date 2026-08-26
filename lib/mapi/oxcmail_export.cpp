// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cstring>
#include <string>
#include <utility>
#include <fmt/core.h>
#include <libHX/ctype_helper.h>
#include <libHX/scope.hpp>
#include <vmime/addressList.hpp>
#include <vmime/contentTypeField.hpp>
#include <vmime/dateTime.hpp>
#include <vmime/header.hpp>
#include <vmime/mailboxList.hpp>
#include <vmime/messageIdSequence.hpp>
#include <vmime/stringContentHandler.hpp>
#include <vmime/text.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/ical.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tnef.hpp>
#include <gromox/usercvt.hpp>
#include <gromox/vcard.hpp>
#include "oxcmail_int.hpp"
#define AWUR __attribute__((warn_unused_result))

using namespace std::string_literals;
using namespace gromox;
using namespace oxcmail;

static const vmime::mediaType mt_plain(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_PLAIN);
static const vmime::mediaType mt_octet(vmime::mediaTypes::APPLICATION, vmime::mediaTypes::APPLICATION_OCTET_STREAM);
static constexpr addr_tags tags_self = {
	PR_DISPLAY_NAME, PR_ADDRTYPE, PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS,
	PR_ENTRYID,
};
static constexpr addr_tags tags_sender = {
	PR_SENDER_NAME, PR_SENDER_ADDRTYPE, PR_SENDER_EMAIL_ADDRESS,
	PR_SENDER_SMTP_ADDRESS, PR_SENDER_ENTRYID,
};
static constexpr addr_tags tags_sent_repr = {
	PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_ADDRTYPE,
	PR_SENT_REPRESENTING_EMAIL_ADDRESS, PR_SENT_REPRESENTING_SMTP_ADDRESS,
	PR_SENT_REPRESENTING_ENTRYID,
};
static constexpr addr_tags tags_read_rcpt = {
	PidTagReadReceiptName, PidTagReadReceiptAddressType,
	PidTagReadReceiptEmailAddress, PidTagReadReceiptSmtpAddress,
	PR_READ_RECEIPT_ENTRYID,
};

/**
 * Obtain SMTP address for a sender/recipient.
 *
 * @props:    MAPI proplist to search in
 *            (can come from a MAPI_MESSAGE or a MAPI_MAILUSER object).
 * @ptags:    Tag set that indicates which props to read
 *            (sender/from/recipient).
 * @username: Output placeholder.
 *
 * When any part of the input could not be converted (e.g. garbage input, user
 * not found, etc.) and thus produced no output, ecNullObject is returned.
 */
static AWUR ec_error_t omv_get_smtp_address(const TPROPVAL_ARRAY &props,
    const addr_tags *ptags, const char *org, cvt_id2user id2user,
    std::string &username)
{
	const auto &tags = ptags != nullptr ? *ptags : tags_self;
	auto s = props.get<const char>(tags.pr_smtpaddr);
	if (s != nullptr) {
		username = s;
		return ecSuccess;
	}
	auto addrtype = props.get<const char>(tags.pr_addrtype);
	auto emaddr   = props.get<const char>(tags.pr_emaddr);
	if (addrtype != nullptr) {
		auto err = cvt_genaddr_to_smtpaddr(addrtype, emaddr, org,
		           id2user, username);
		if (err == ecSuccess)
			return ecSuccess;
		else if (err != ecNullObject)
			return err;
	}
	return cvt_entryid_to_smtpaddr(props.get<const BINARY>(tags.pr_entryid),
	       org, std::move(id2user), username);
}

/**
 * Produce a vmime address object from a MAPI object.
 *
 * @mct:      Input MAPI object
 * @ptags:    Tag set that indicates which props to read
 *            (sender/from/recipient).
 * @mb:       Output placeholder.
 */
static AWUR ec_error_t omv_export_address(const message_content &mct,
    const addr_tags &tags, vmime::mailbox &mb)
{
	auto val = mct.proplist.get<char>(tags.pr_name);
	if (val != nullptr && *val != '\0')
		mb.setName(vmime::text(val, vmime::charsets::UTF_8));
	std::string addr;
	auto err = omv_get_smtp_address(mct.proplist, &tags, g_oxcmail_org_name,
	           oxcmail_get_username, addr);
	if (err == ecSuccess)
		mb.setEmail(addr);
	return err;
	/*
	 * RFC 5322 §3.4's ABNF mandates an address at all times. If we only
	 * emitted "Display Name", parsers can preferentially treat that as the
	 * email address. (vmime ensures that won't happen.)
	 */
}

/**
 * Turn a recipient list into a mailboxList.
 *
 * address-list (RFC5322) is like a mailbox-list, but also groups (e.g.
 * "undisclosed-recipients: ;"). We do not use this group feature. But some callers
 * need to convert mblist going forward.
 */
static AWUR ec_error_t omv_export_addresses(const tarray_set &rcpt_list,
    uint32_t rcpt_type, vmime::mailboxList &mblist)
{
	for (const auto &rcpt : rcpt_list) {
		auto typ = rcpt.get<uint32_t>(PR_RECIPIENT_TYPE);
		if (typ == nullptr || *typ != rcpt_type)
			continue;
		auto mb = vmime::make_shared<vmime::mailbox>("");
		auto dispname = rcpt.get<char>(PR_DISPLAY_NAME);
		if (dispname != nullptr)
			mb->setName(vmime::text(dispname, vmime::charsets::UTF_8));
		std::string username;
		if (oxcmail_get_smtp_address(rcpt, &tags_self,
		    g_oxcmail_org_name, oxcmail_get_username, username))
			mb->setEmail(username);
		mblist.appendMailbox(mb);
	}
	return mblist.getMailboxCount() > 0 ? ecSuccess : ecNullObject;
}

/**
 * Set a Sender field in the vmime object based on the MAPI object.
 * @mct:   Input MAPI object
 * @vhead: Output vmime object
 * @sched: Selects the logic for a MAPI scheduling object.
 */
static AWUR ec_error_t omv_export_sender(const message_content &mct,
    vmime::header &vhead, bool sched)
{
	if (sched)
		return ecSuccess;
	auto str  = mct.proplist.get<const char>(PR_SENDER_SMTP_ADDRESS);
	auto str1 = mct.proplist.get<const char>(PR_SENT_REPRESENTING_SMTP_ADDRESS);
	if (str != nullptr && str1 != nullptr) {
		if (strcasecmp(str, str1) == 0)
			return ecSuccess; /* field not needed */
		auto mb = vmime::make_shared<vmime::mailbox>("");
		auto err = omv_export_address(mct, tags_sender, *mb);
		if (err == ecSuccess)
			vhead.Sender()->setValue(std::move(mb));
		return err;
	}
	str  = mct.proplist.get<char>(PR_SENDER_ADDRTYPE);
	str1 = mct.proplist.get<char>(PR_SENT_REPRESENTING_ADDRTYPE);
	/* XXX: allow EX? */
	if (str == nullptr || str1 == nullptr || strcasecmp(str, "SMTP") != 0 ||
	    strcasecmp(str1, "SMTP") != 0)
		return ecSuccess;
	/*
	 * When MAPI Sender is the same as MAPI From, omit the MIME Sender field
	 * for redundancy.
	 */
	str  = mct.proplist.get<char>(PR_SENDER_EMAIL_ADDRESS);
	str1 = mct.proplist.get<char>(PR_SENT_REPRESENTING_EMAIL_ADDRESS);
	if (str == nullptr || str1 == nullptr || strcasecmp(str, str1) == 0)
		return ecSuccess;
	auto mb  = vmime::make_shared<vmime::mailbox>("");
	auto err = omv_export_address(mct, tags_sender, *mb);
	if (err == ecSuccess)
		vhead.Sender()->setValue(std::move(mb));
	return err;
}

/**
 * Set a From/Sender field in the vmime object based on the MAPI object.
 * @mct:   Input MAPI object
 * @vhead: Output vmime object
 * @sched: Selects the logic for a MAPI scheduling object.
 */
static AWUR ec_error_t omv_export_fromsender(const message_content &mct,
    vmime::header &vhead, bool sched)
{
	auto mb = vmime::make_shared<vmime::mailbox>("");
	if (sched) {
		auto err = omv_export_address(mct, tags_sender, *mb);
		if (err == ecSuccess)
			vhead.From()->setValue(std::move(mb));
		return err;
	}
	/* XXX: trace nullo/dstnull */
	auto err = omv_export_address(mct, tags_sent_repr, *mb);
	if (err == ecSuccess) {
		vhead.From()->setValue(std::move(mb));
		return ecSuccess;
	} else if (err == ecNullObject) {
	} else {
		return err;
	}
	err = omv_export_address(mct, tags_sender, *mb);
	if (err == ecSuccess)
		vhead.Sender()->setValue(std::move(mb));
	return err;
}

static AWUR ec_error_t genentryid_to_smtpaddr(const BINARY &bin,
    std::string &dispname, std::string &emaddr)
{
	EXT_PULL ep;
	EMSAB_ENTRYID ems;
	ep.init(bin.pb, bin.cb, malloc, EXT_FLAG_UTF16);
	if (ep.g_abk_eid(&ems) == pack_result::ok &&
	    cvt_essdn_to_username(ems.x500dn.c_str(), g_oxcmail_org_name,
	    oxcmail_get_username, emaddr) == ecSuccess)
		return ecSuccess;

	ONEOFF_ENTRYID oo;
	ep.init(bin.pb, bin.cb, malloc, EXT_FLAG_UTF16);
	if (ep.g_oneoff_eid(&oo) == pack_result::ok) {
		dispname = std::move(oo.pdisplay_name);
		if (cvt_genaddr_to_smtpaddr(oo.paddress_type.c_str(),
		    oo.pmail_address.c_str(), g_oxcmail_org_name,
		    oxcmail_get_username, emaddr) == ecSuccess)
			return ecSuccess;
	}

	mlog(LV_WARN, "W-1964: skipping unrecognized PR_REPLY_RECIPIENTS_TO entry %s",
		bin2hex(std::string_view(bin)).c_str());
	return ecNullObject;
}

static AWUR ec_error_t omv_convert_reply_to(const message_content &mct,
    vmime::header &vhead)
{
	EXT_PULL ext_pull;
	BINARY_ARRAY address_array{};
	auto cl_0 = HX::make_scope_exit([&]() {
		for (unsigned int i = 0; i < address_array.count; ++i)
			free(address_array.pbin[i].pb);
		free(address_array.pbin);
	});

	auto bin = mct.proplist.get<BINARY>(PR_REPLY_RECIPIENT_ENTRIES);
	if (bin == nullptr)
		return ecNullObject;
	/*
	 * PR_REPLY_RECIPIENT_NAMES is semicolon-separated, but there is no way
	 * to distinguish between semicolon as a separator and semicolon as
	 * part of a name. So we ignore that property altogether.
	 */
	ext_pull.init(bin->pb, bin->cb, malloc, EXT_FLAG_WCOUNT);
	if (ext_pull.g_flatentry_a(&address_array) != pack_result::ok)
		return ecNullObject;

	vmime::addressList adrlist;
	for (size_t i = 0; i < address_array.count; ++i) {
		std::string dispname, emaddr;
		auto err = genentryid_to_smtpaddr(address_array.pbin[i],
		           dispname, emaddr);
		if (err == ecNullObject)
			continue;
		if (err != ecSuccess)
			return err;
		auto mb = vmime::make_shared<vmime::mailbox>("");
		if (!emaddr.empty()) {
			mb->setEmail(std::move(emaddr));
			if (!dispname.empty())
				mb->setName(vmime::text(std::move(dispname), vmime::charsets::UTF_8));
		}
		adrlist.appendAddress(mb);
	}
	if (adrlist.getAddressCount() == 0)
		return ecNullObject;
	vhead.ReplyTo()->setValue(std::move(adrlist));
	return ecSuccess;
}

static AWUR ec_error_t omv_export_rrt(const message_content &mct,
    vmime::header &vhead, bool sched)
{
	auto flag = mct.proplist.get<uint8_t>(PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return ecSuccess;
	auto mb = vmime::make_shared<vmime::mailbox>("");
	auto err = omv_export_address(mct, tags_read_rcpt, *mb);
	if (err == ecNullObject)
		err = omv_export_address(mct, tags_sender, *mb);
	if (err == ecNullObject && sched)
		err = omv_export_address(mct, tags_sent_repr, *mb);
	if (err == ecSuccess)
		vhead.getField("Return-Receipt-To")->setValue(std::move(mb));
	return err;
}

static AWUR ec_error_t omv_export_mdnflag(const message_content &mct,
    vmime::header &vhead, bool sched)
{
	auto flag = mct.proplist.get<uint8_t>(PR_READ_RECEIPT_REQUESTED);
	if (flag == nullptr || *flag == 0)
		return ecSuccess;
	auto mb = vmime::make_shared<vmime::mailbox>("");
	auto err = omv_export_address(mct, tags_read_rcpt, *mb);
	if (err == ecNullObject)
		err = omv_export_address(mct, tags_sender, *mb);
	if (err == ecNullObject && !sched)
		err = omv_export_address(mct, tags_sent_repr, *mb);
	if (err == ecSuccess) {
		auto mblist = vmime::make_shared<vmime::mailboxList>();
		mblist->appendMailbox(std::move(mb));
		vhead.DispositionNotificationTo()->setValue(std::move(mblist));
	}
	return err;
}

static AWUR ec_error_t omv_export_tocc(const message_content &mct,
    const mime_skeleton &skel, vmime::header &vhead)
{
	if (mct.children.prcpts == nullptr)
		return ecNullObject;
	vmime::mailboxList mblist;
	auto err = omv_export_addresses(*mct.children.prcpts, MAPI_TO, mblist);
	if (err == ecSuccess)
		vhead.To()->setValue(std::move(mblist).toAddressList());
	else if (err != ecNullObject)
		return err;

	mblist.removeAllMailboxes();
	err = omv_export_addresses(*mct.children.prcpts, MAPI_CC, mblist);
	if (err == ecSuccess)
		vhead.Cc()->setValue(std::move(mblist).toAddressList());
	else if (err != ecNullObject)
		return err;

	if (class_match_prefix(skel.pmessage_class, "IPM.Schedule.Meeting") == 0 ||
	    class_match_prefix(skel.pmessage_class, "IPM.Task") == 0)
		return ecSuccess;

	mblist.removeAllMailboxes();
	err = omv_export_addresses(*mct.children.prcpts, MAPI_BCC, mblist);
	if (err == ecSuccess)
		vhead.Bcc()->setValue(std::move(mblist).toAddressList());
	else if (err != ecNullObject)
		return err;

	return ecSuccess;
}

static std::string omv_export_content_class_1(const char *cls)
{
	if (class_match_prefix(cls, "IPM.Note.Microsoft.Fax") == 0)
		return "fax";
	else if (class_match_prefix(cls, "IPM.Note.Microsoft.Fax.CA") == 0)
		return "fax-ca";
	else if (class_match_prefix(cls, "IPM.Note.Microsoft.Missed.Voice") == 0)
		return "missedcall";
	else if (class_match_prefix(cls, "IPM.Note.Microsoft.Conversation.Voice") == 0)
		return "voice-uc";
	else if (class_match_prefix(cls, "IPM.Note.Microsoft.Voicemail.UM.CA") == 0)
		return "voice-ca";
	else if (class_match_prefix(cls, "IPM.Note.Microsoft.Voicemail.UM") == 0)
		return "voice";
	else if (strncasecmp(cls, "IPM.Note.Custom.", 16) == 0)
		return "urn:content-class:custom."s + cls;
	return {};
}

static std::string omv_export_content_class(const message_content &mct,
    const char *cls, proptag_t infopath_tag)
{
	auto out = omv_export_content_class_1(cls);
	if (out.size() > 0)
		return out;
	if (infopath_tag == 0)
		return out;
	if (strncasecmp(cls, "IPM.InfoPathForm.", 17) != 0)
		return out;
	cls = mct.proplist.get<char>(PROP_TAG(PT_UNICODE, infopath_tag));
	if (cls == nullptr)
		return out;
	auto dot = strrchr(cls, '.');
	if (dot != nullptr)
		cls = &dot[1];
	return "InfoPathForm."s + cls;
}

static const char *importance_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case IMPORTANCE_LOW: return "Low";
	case IMPORTANCE_NORMAL: return "Normal";
	case IMPORTANCE_HIGH: return "High";
	default: return nullptr;
	}
}

static const char *sensitivity_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case SENSITIVITY_NONE: return "Normal";
	case SENSITIVITY_PERSONAL: return "Personal";
	case SENSITIVITY_PRIVATE: return "Private";
	case SENSITIVITY_COMPANY_CONFIDENTIAL: return "Company-Confidential";
	default: return nullptr;
	}
}

static const char *sender_id_to_text(const uint32_t *v)
{
	if (v == nullptr)
		return nullptr;
	switch (*v) {
	case SENDER_ID_NEUTRAL: return "Neutral";
	case SENDER_ID_PASS: return "Pass";
	case SENDER_ID_FAIL: return "Fail";
	case SENDER_ID_SOFT_FAIL: return "SoftFail";
	case SENDER_ID_NONE: return "None";
	case SENDER_ID_TEMP_ERROR: return "TempError";
	case SENDER_ID_PERM_ERROR: return "PermError";
	default: return nullptr;
	}
}

static constexpr char
	PidNameContentClass[] = "Content-Class",
	PidNameKeywords[] = "Keywords";

template<typename T> static vmime::text text8(T &&s)
{
	return vmime::text(std::forward<T>(s), vmime::charsets::UTF_8);
}

/**
 * Transform PR_TNEF_CORRELATION_KEY to a vmime::text.
 *
 * TNEFCK is usually an ASCIZ string, <message-id@domain>\0 and emitted to RFC
 * 5322 as a normal ASCII message-id. But, if there is unexpected data, deal
 * with it.
 */
static std::string tnef_correl_to_vtext(std::string_view sv)
{
	if (sv.size() >= 1 && sv.back() == '\0' &&
	    std::all_of(sv.begin(), std::prev(sv.end()), HX_isprint))
		return std::string(sv.begin(), sv.end());
	else if (std::all_of(sv.begin(), sv.end(), HX_isprint))
		return std::string(sv);
	else
		return base64_encode(sv);
}

static AWUR ec_error_t omv_export_mail_head(const message_content &mct,
    const mime_skeleton &skel, EXT_BUFFER_ALLOC alloc,
    GET_PROPIDS get_propids, GET_PROPNAME get_propname, vmime::header &vhead)
{
	auto sched = skel.mail_type == oxcmail_type::calendar;
	vhead.getField("MIME-Version")->setValue("1.0");
	auto err = omv_export_sender(mct, vhead, sched);
	if (err != ecSuccess && err != ecNullObject)
		return err;
	err = omv_export_fromsender(mct, vhead, sched);
	if (err != ecSuccess && err != ecNullObject)
		return err;
	err = omv_export_rrt(mct, vhead, sched);
	if (err != ecSuccess && err != ecNullObject)
		return err;
	err = omv_export_mdnflag(mct, vhead, sched);
	if (err != ecSuccess && err != ecNullObject)
		return err;
	err = omv_export_tocc(mct, skel, vhead);
	if (err != ecSuccess && err != ecNullObject)
		return err;
	err = omv_convert_reply_to(mct, vhead);
	if (err != ecSuccess && err != ecNullObject)
		return err;

	const PROPERTY_NAME namequeries[] = {
		{MNID_ID, PSETID_Common, PidLidInfoPathFromName},
		{MNID_STRING, PS_PUBLIC_STRINGS, 0, deconst(PidNameKeywords)},
		{MNID_ID, PSETID_Common, PidLidClassified},
		{MNID_ID, PSETID_Common, PidLidClassification},
		{MNID_ID, PSETID_Common, PidLidClassificationKeep},
		{MNID_ID, PSETID_Common, PidLidClassificationDescription},
		{MNID_ID, PSETID_Common, PidLidClassificationGuid},
		{MNID_ID, PSETID_Common, PidLidFlagRequest},
	};
	enum {
		l_infopath = 0, l_keywords, l_classified, l_classification,
		l_classkeep, l_classdesc, l_classguid, l_flagreq,
	};
	static_assert(l_flagreq + 1 == std::size(namequeries));
	const PROPNAME_ARRAY propnames = {std::size(namequeries), deconst(namequeries)};
	PROPID_ARRAY propids;
	if (!get_propids(&propnames, &propids) || propids.size() != propnames.size())
		return ecRpcFailed;

	auto ostr = omv_export_content_class(mct, skel.pmessage_class, propids[l_infopath]);
	if (!ostr.empty())
		vhead.getField("Content-Class")->setValue(text8(std::move(ostr)));

	auto str = mct.proplist.get<const char>(PR_SENDER_TELEPHONE_NUMBER);
	if (str != nullptr)
		vhead.getField("X-CallingTelephoneNumber")->setValue(text8(str));
	auto num = mct.proplist.get<const uint32_t>(PidTagVoiceMessageDuration);
	if (num != nullptr)
		vhead.getField("X-VoiceMessageDuration")->setValue(std::to_string(*num));
	str = mct.proplist.get<char>(PidTagVoiceMessageSenderName);
	if (str != nullptr)
		vhead.getField("X-VoiceMessageSenderName")->setValue(text8(str));
	num = mct.proplist.get<uint32_t>(PidTagFaxNumberOfPages);
	if (num != nullptr)
		vhead.getField("X-FaxNumberOfPages")->setValue(std::to_string(*num));
	str = mct.proplist.get<char>(PidTagVoiceMessageAttachmentOrder);
	if (str != nullptr)
		vhead.getField("X-AttachmentOrder")->setValue(text8(str));
	str = mct.proplist.get<char>(PidTagCallId);
	if (str != nullptr)
		vhead.getField("X-CallID")->setValue(text8(str));
	str = importance_to_text(mct.proplist.get<const uint32_t>(PR_IMPORTANCE));
	if (str != nullptr)
		vhead.getField("Importance")->setValue(text8(str));
	str = sensitivity_to_text(mct.proplist.get<const uint32_t>(PR_SENSITIVITY));
	if (str != nullptr)
		vhead.getField("Sensitivity")->setValue(text8(str));

	auto lnum = mct.proplist.get<const uint64_t>(PR_CLIENT_SUBMIT_TIME);
	auto le_time = lnum == nullptr ? time(nullptr) : rop_util_nttime_to_unix(*lnum);
	vhead.Date()->setValue(vmime::datetime(le_time));

	str = mct.proplist.get<char>(PR_SUBJECT_PREFIX);
	auto str1 = mct.proplist.get<const char>(PR_NORMALIZED_SUBJECT);
	if (str != nullptr && str1 != nullptr) {
		vhead.Subject()->setValue(text8(std::string(str) + str1));
	} else {
		str = mct.proplist.get<char>(PR_SUBJECT);
		if (str != nullptr)
			vhead.Subject()->setValue(text8(str));
	}
	str = mct.proplist.get<char>(PR_CONVERSATION_TOPIC);
	if (str != nullptr && *str != '\0')
		vhead.getField("Thread-Topic")->setValue(text8(str));
	auto bv = mct.proplist.get<BINARY>(PR_CONVERSATION_INDEX);
	if (bv != nullptr)
		vhead.getField("Thread-Index")->setValue(base64_encode(*bv));
	str = mct.proplist.get<char>(PR_INTERNET_MESSAGE_ID); /* already has <> */
	if (str != nullptr)
		vhead.MessageId()->setValue(vmime::messageId(str));
	str = mct.proplist.get<char>(PR_INTERNET_REFERENCES); /* already has <> */
	if (str != nullptr) {
		vmime::messageIdSequence idlist;
		idlist.parse(str);
		vhead.References()->setValue(std::move(idlist));
	}
	auto sa = mct.proplist.get<STRING_ARRAY>(PROP_TAG(PT_MV_UNICODE, propids[l_keywords]));
	if (sa != nullptr) {
		ostr.clear();
		for (size_t i = 0; i < sa->count; ++i) {
			if (sa->ppstr[i] == nullptr)
				continue;
			if (!ostr.empty())
				ostr += ", ";
			ostr += sa->ppstr[i];
		}
		vhead.getField("Keywords")->setValue(text8(std::move(ostr)));
	}
	str = mct.proplist.get<char>(PR_IN_REPLY_TO_ID); /* already has <> */
	if (str != nullptr) {
		vmime::messageIdSequence idlist;
		idlist.parse(str);
		vhead.InReplyTo()->setValue(std::move(idlist));
	}
	str = mct.proplist.get<char>(PR_LIST_HELP);
	if (str != nullptr)
		vhead.getField("List-Help")->setValue(text8(str));
	str = mct.proplist.get<char>(PR_LIST_SUBSCRIBE);
	if (str != nullptr)
		vhead.getField("List-Subscribe")->setValue(text8(str));
	str = mct.proplist.get<char>(PR_LIST_UNSUBSCRIBE);
	if (str != nullptr)
		vhead.getField("List-Unsubscribe")->setValue(text8(str));
	num = mct.proplist.get<uint32_t>(PR_MESSAGE_LOCALE_ID);
	if (num != nullptr) {
		auto cstr = lcid_to_ltag(*num);
		if (cstr != nullptr)
			vhead.getField("Content-Language")->setValue(text8(cstr));
	}
	auto flag = mct.proplist.get<const uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_classified]));
	if (flag != nullptr && *flag != 0)
		vhead.getField("X-Microsoft-Classified")->setValue("true");
	flag = mct.proplist.get<uint8_t>(PROP_TAG(PT_BOOLEAN, propids[l_classkeep]));
	if (flag != nullptr && *flag != 0)
		vhead.getField("X-Microsoft-ClassKeep")->setValue("true");
	str = mct.proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classification]));
	if (str != nullptr)
		vhead.getField("X-Microsoft-Classification")->setValue(text8(str));
	str = mct.proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classdesc]));
	if (str != nullptr)
		vhead.getField("X-Microsoft-ClassDesc")->setValue(text8(str));
	str = mct.proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_classguid]));
	if (str != nullptr)
		vhead.getField("X-Microsoft-ClassID")->setValue(text8(str));

	if ((mct.children.pattachments != nullptr && mct.children.pattachments->count) > 0 ||
	    (skel.pattachments != nullptr && skel.pattachments->count > 0))
		vhead.getField("X-MS-Has-Attach")->setValue("yes");

	num = mct.proplist.get<uint32_t>(PR_AUTO_RESPONSE_SUPPRESS);
	if (num != nullptr && *num != 0) {
		if (*num == UINT32_MAX) {
			vhead.getField("X-Auto-Response-Suppress")->setValue("ALL");
		} else {
			ostr.clear();
			if (*num & AUTO_RESPONSE_SUPPRESS_DR)
				ostr += "DR";
			if (*num & AUTO_RESPONSE_SUPPRESS_NDR)
				ostr += ostr.empty() ? "NDR" : ",NDR";
			if (*num & AUTO_RESPONSE_SUPPRESS_RN)
				ostr += ostr.empty() ? "RN" : ",RN";
			if (*num & AUTO_RESPONSE_SUPPRESS_NRN)
				ostr += ostr.empty() ? "NRN" : ",NRN";
			if (*num & AUTO_RESPONSE_SUPPRESS_OOF)
				ostr += ostr.empty() ? "OOF" : ",OOF";
			if (*num & AUTO_RESPONSE_SUPPRESS_AUTOREPLY)
				ostr += ostr.empty() ? "AutoReply" : ",AutoReply";
			if (ostr.size() > 0)
				vhead.getField("X-Auto-Response-Suppress")->setValue(std::move(ostr));
		}
	}

	flag = mct.proplist.get<uint8_t>(PR_AUTO_FORWARDED);
	if (flag != nullptr && *flag != 0)
		vhead.getField("X-MS-Exchange-Organization-AutoForwarded")->setValue("true");
	str = sender_id_to_text(mct.proplist.get<const uint32_t>(PR_SENDER_ID_STATUS));
	if (str != nullptr)
		vhead.getField("X-MS-Exchange-Organization-SenderIdResult")->setValue(text8(str));
	str = mct.proplist.get<char>(PR_PURPORTED_SENDER_DOMAIN);
	if (str != nullptr)
		vhead.getField("X-MS-Exchange-Organization-PRD")->setValue(text8(str));

	auto inum = mct.proplist.get<const int32_t>(PR_CONTENT_FILTER_SCL);
	if (inum != nullptr)
		vhead.getField("X-MS-Exchange-Organization-SCL")->setValue(std::to_string(*inum));

	str = mct.proplist.get<char>(PROP_TAG(PT_UNICODE, propids[l_flagreq]));
	if (str != nullptr && *str != '\0') {
		vhead.getField("X-Message-Flag")->setValue(text8(str));
		lnum = mct.proplist.get<uint64_t>(PR_REPLY_TIME);
		if (lnum != nullptr)
			vhead.getField("Reply-By")->setValue(vmime::datetime(rop_util_nttime_to_unix(*lnum)));
	}

	if (skel.mail_type == oxcmail_type::tnef) {
		ostr.clear();
		bv = mct.proplist.get<BINARY>(PR_TNEF_CORRELATION_KEY);
		if (bv != nullptr) {
			vhead.getField("X-MS-TNEF-Correlator")->setValue(text8(tnef_correl_to_vtext(*bv)));
		} else {
			str = mct.proplist.get<char>(PR_INTERNET_MESSAGE_ID); /* already has <> */
			if (str != nullptr)
				vhead.getField("X-MS-TNEF-Correlator")->setValue(text8(str));
		}
	}

	str = mct.proplist.get<char>(PR_BODY_CONTENT_ID);
	if (str != nullptr)
		vhead.ContentId()->setValue(vmime::messageId("<"s + str + ">"));
	str = mct.proplist.get<char>(PR_BODY_CONTENT_LOCATION);
	if (str != nullptr)
		vhead.ContentLocation()->setValue(text8(str));

	vhead.getField("X-Mailer")->setValue("gromox-oxcmail " PACKAGE_VERSION);
	auto guid = PS_INTERNET_HEADERS;
	for (size_t i = 0; i < mct.proplist.count; ++i) {
		auto proptag = mct.proplist.ppropval[i].proptag;
		if (!is_nameprop_id(PROP_ID(proptag)))
			continue;
		if (PROP_TYPE(proptag) != PT_STRING8 &&
		    PROP_TYPE(proptag) != PT_UNICODE)
			continue;
		PROPERTY_NAME *ppropname = nullptr;
		if (!get_propname(PROP_ID(proptag), &ppropname))
			return ecRpcFailed;
		if (ppropname->guid != guid)
			continue;
		if (ppropname->kind != MNID_STRING ||
		    strcasecmp(ppropname->pname, "Content-Type") == 0)
			continue;
		auto str = static_cast<const char *>(mct.proplist.ppropval[i].pvalue);
		/*
		 * Do not use text8 here: for header names vmime has a
		 * registered value class for (Received, Return-Path, ...),
		 * setValue(text) throws bad_field_value_type at runtime. The
		 * string overload parses into whatever type the field wants,
		 * like the MAIL exporter's untyped set_field did.
		 */
		vhead.getField(ppropname->pname)->setValue(std::string(str));
	}
	return ecSuccess;
}

static void omv_set_bodytext(vmime::bodyPart &bp, std::string_view text,
    vmime::mediaType mtype = mt_plain, vmime::charset cset = vmime::charsets::UTF_8)
{
	auto cth = vmime::make_shared<vmime::stringContentHandler>(std::string(text));
	auto enc = vmime::encoding::decide(cth, vmime::charsets::UTF_8, vmime::encoding::USAGE_TEXT);
	bp.getBody()->setContents(std::move(cth), mtype, cset, std::move(enc));
}

/**
 * @vmsg: VMIME object to unravel @blob into
 * @blob: A RFC5322 message that ought to be multipart/signed
 */
static AWUR ec_error_t omv_smime_signed_fold(vmime::bodyPart &vmsg,
    std::string &&blob)
{
	vmime::message dec_blob;
	dec_blob.parse(blob);
	if (dec_blob.getBody()->getContentType() !=
	    vmime::mediaType(vmime::mediaTypes::MULTIPART, "signed")) {
		omv_set_bodytext(vmsg, "[Message is not a valid OXOSMIME message. "
			"The attachment object is not of type multipart/signed.]");
		return ecSuccess;
	}

	/* Move all headers */
	auto vhdr = vmsg.getHeader();
	for (auto &&f : dec_blob.getHeader()->getFieldList()) {
		auto exfield = vhdr->findField(f->getName());
		if (exfield == nullptr)
			vhdr->appendField(std::move(f));
		else
			*exfield = std::move(*f);
	}
	vmsg.setBody(std::move(dec_blob.getBody()));
	return ecSuccess;
}

/**
 * The Outlook action "Send as business card" produces a file attachment which
 * contains a vCard 2.0 header and which is marked as text/vcard.
 *
 * The OL action "Send as Outlook contact" produces an embedded message.
 * oxcmail will convert this to vCard 4.0 and mark it as text/directory.
 */
static bool mct_is_outlook_contact(const message_content *mct)
{
	if (mct == nullptr)
		return false;
	auto s = mct->proplist.get<const char>(PR_MESSAGE_CLASS);
	return s != nullptr && class_match_prefix(s, "IPM.Contact") == 0;
}

static bool att_is_mtg_exception(const attachment_content &atc)
{
	if (atc.pembedded == nullptr)
		return false;
	auto s = atc.pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
	return s != nullptr && strcasecmp(s, IPM_Appointment_Exception) == 0;
}

static bool att_is_inline(const attachment_content &atc)
{
	if (atc.pembedded != nullptr)
		return false;
	auto num = atc.proplist.get<uint32_t>(PR_ATTACH_FLAGS);
	if (num == nullptr || !(*num & ATT_MHTML_REF))
		return false;
	return atc.proplist.has(PR_ATTACH_CONTENT_ID) ||
	       atc.proplist.has(PR_ATTACH_CONTENT_LOCATION);
}

static vmime::mediaType att_mediatype(const TPROPVAL_ARRAY &props)
{
	auto str = props.get<const char>(PR_ATTACH_MIME_TAG);
	if (str == nullptr) {
		str = props.get<const char>(PR_ATTACH_EXTENSION);
		if (str == nullptr)
			;
		else if (*str == '.')
			str = extension_to_mime(&str[1]);
		else if (*str != '\0')
			str = extension_to_mime(str);
	}
	if (str == nullptr)
		return mt_octet;
	vmime::mediaType mtype(str);
	if (mtype.getType() == vmime::mediaTypes::MULTIPART)
		mtype = mt_octet;
	return mtype;
}

/**
 * Convert a MAPI attachment into a vmime object.
 * @atc:       source attachment
 * @is_inline: 
 */
ec_error_t oxcmail_converter::export_attachment(const attachment_content &atc,
    bool is_inline, const mime_skeleton &skel,
    vmime::shared_ptr<vmime::bodyPart> vpart, unsigned int mail_depth)
{
	auto is_contact = mct_is_outlook_contact(atc.pembedded);
	const char *file_name = atc.proplist.get<char>(PR_ATTACH_LONG_FILENAME);
	if (file_name == nullptr)
		file_name = atc.proplist.get<char>(PR_ATTACH_FILENAME);

	vmime::mediaType mtype;
	if (atc.pembedded == nullptr) {
		mtype = att_mediatype(atc.proplist);
	} else if (is_contact) {
		mtype = vmime::mediaType(vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_DIRECTORY);
	} else {
		mtype = vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_RFC822);
		file_name = nullptr;
	}
	
	auto &vhdr = *vpart->getHeader();
	auto str = atc.proplist.get<const char>(PR_DISPLAY_NAME);
	if (str != nullptr && *str != '\0')
		vhdr.getField("Content-Description")->setValue(text8(str));
	
	vhdr.ContentDisposition()->setValue(is_inline ?
		vmime::contentDispositionTypes::INLINE :
		vmime::contentDispositionTypes::ATTACHMENT);
	auto &phf = *vmime::dynamicCast<vmime::parameterizedHeaderField>(vhdr.ContentDisposition());
	if (file_name != nullptr)
		/* Plain strings would be interpreted in the current locale */
		*phf.getParameter("filename") = vmime::parameter("filename",
			vmime::word(file_name, vmime::charsets::UTF_8));
	if (auto ctime = atc.proplist.get<uint64_t>(PR_CREATION_TIME);
	    ctime != nullptr)
		*phf.getParameter("creation-date") = vmime::parameter("creation-date",
			vmime::datetime(rop_util_nttime_to_unix(*ctime)).generate());
	if (auto mtime = atc.proplist.get<uint64_t>(PR_LAST_MODIFICATION_TIME);
	    mtime != nullptr)
		*phf.getParameter("modification-date") = vmime::parameter("modification-date",
			vmime::datetime(rop_util_nttime_to_unix(*mtime)).generate());

	str = atc.proplist.get<char>(PR_ATTACH_CONTENT_ID);
	if (str != nullptr)
		vhdr.ContentId()->setValue(vmime::messageId("<"s + str + ">"));
	str = atc.proplist.get<char>(PR_ATTACH_CONTENT_LOCATION);
	if (str != nullptr)
		vhdr.ContentLocation()->setValue(str);
	str = atc.proplist.get<char>(PR_ATTACH_CONTENT_BASE);
	if (str != nullptr)
		vhdr.getField("Content-Base")->setValue(str);
	
	if (is_contact) {
		oxvcard_converter vc_cvt;
		vc_cvt.log_id = log_id;
		vc_cvt.get_propids = get_propids;
		vcard vcard_obj;
		if (vc_cvt.mapi_to_vcard(*atc.pembedded, vcard_obj)) {
			std::string vcout;
			if (vcard_obj.serialize(vcout)) {
				vpart->getBody()->setContents(
					vmime::make_shared<vmime::stringContentHandler>(std::move(vcout)),
					mtype, vmime::charsets::UTF_8);
				auto &chf = *vmime::dynamicCast<vmime::contentTypeField>(vhdr.ContentType());
				*chf.getParameter("profile") = vmime::parameter("profile", "vCard");
				return ecSuccess;
			}
		}
	}
	
	if (atc.pembedded != nullptr && mail_depth >= m_max_attach_depth) {
		auto str = fmt::format("This embedded attachment was suppressed upon sending "
		           "because it is nested too deeply (maximum {})\n",
		           m_max_attach_depth);
		vpart->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(std::move(str)),
			mt_plain, vmime::charsets::UTF_8);
		return ecSuccess;
	}

	if (atc.pembedded != nullptr)
		return do_export(*atc.pembedded, skel.mail_type == oxcmail_type::tnef,
		       vpart, mail_depth + 1);

	auto bv = atc.proplist.get<const BINARY>(PR_ATTACH_DATA_BIN);
	if (bv != nullptr) {
		vpart->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(std::string(bv->pc, bv->cb)),
			mtype);
		vpart->getBody()->setEncoding(vmime::encoding(vmime::encodingTypes::BASE64));
	}
	return ecSuccess;
}

ec_error_t oxcmail_converter::export_attachments(const message_content &mct,
    const mime_skeleton &skel, vmime::shared_ptr<vmime::bodyPart> vrelated,
    vmime::shared_ptr<vmime::bodyPart> vmixed, unsigned int mail_depth)
{
	if (mct.children.pattachments == nullptr)
		return ecSuccess;
	auto &atxlist = *mct.children.pattachments;
	if (atxlist.count == 0)
		return ecSuccess;
	for (const auto &at : atxlist) {
		if (att_is_mtg_exception(at))
			continue;
		/*
		 * Inline images are lumped together with the body section
		 * (technically, those images are subject to getting
		 * potentially dropped as a MIME reader processes
		 * multipart/alternative.
		 */
		auto is_inline = att_is_inline(at);
		auto &container = is_inline ? vrelated : vmixed;
		if (container == nullptr) {
			mlog(LV_DEBUG, "D-2359: programming error, %s needs a multipart/%s container",
				__func__, is_inline ? "related" : "mixed");
			return ecInvalidParam;
		}
		auto new_part = vmime::make_shared<vmime::bodyPart>();
		container->getBody()->appendPart(new_part);
		auto err = export_attachment(at, is_inline, skel, new_part, mail_depth);
		if (err != ecSuccess)
			return err;
	}
	return ecSuccess;
}

ec_error_t oxcmail_converter::export_tnef_body(const mime_skeleton &skel,
    vmime::shared_ptr<vmime::bodyPart> vrelated, unsigned int mail_depth)
{
	if (skel.pattachments == nullptr)
		return ecSuccess;
	auto &atxlist = *skel.pattachments;
	if (atxlist.count == 0)
		return ecSuccess;
	if (vrelated == nullptr) {
		mlog(LV_DEBUG, "D-2358: programming error, %s needs a multipart/related container", __func__);
		return ecInvalidParam;
	}
	for (const auto &at : atxlist) {
		auto new_part = vmime::make_shared<vmime::bodyPart>();
		vrelated->getBody()->appendPart(new_part);
		auto err = export_attachment(at, true, skel, new_part, mail_depth);
		if (err != ecSuccess)
			return err;
	}
	return ecSuccess;
}

static std::string ical_get_method(const ical &ic)
{
	auto line = ic.get_line("METHOD");
	if (line == nullptr)
		return {};
	auto str = deconst(line->get_first_subvalue());
	return str != nullptr ? str : std::string();
}

ec_error_t oxcmail_converter::do_export(const message_content &mct,
    bool b_tnef, vmime::shared_ptr<vmime::bodyPart> vmsg, unsigned int mail_depth)
{
	static const vmime::mediaType mt_report(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_REPORT);
	static const vmime::mediaType mt_mixed (vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_MIXED);
	static const vmime::mediaType mt_alt   (vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_ALTERNATIVE);
	static const vmime::mediaType mt_rel   (vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_RELATED);
	static const vmime::mediaType mt_plain (vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_PLAIN);
	static const vmime::mediaType mt_html  (vmime::mediaTypes::TEXT, vmime::mediaTypes::TEXT_HTML);
	static const vmime::mediaType mt_cal   (vmime::mediaTypes::TEXT, "calendar");

	mime_skeleton skel;
	const char *charset = nullptr;
	auto num = mct.proplist.get<uint32_t>(PR_INTERNET_CPID);
	if (num != nullptr && *num != CP_UTF16)
		charset = cpid_to_cset(static_cast<cpid_t>(*num));
	if (charset == nullptr)
		charset = "utf-8";
	if (!load_mime_skeleton(&mct, charset, b_tnef, body_type, &skel))
		return ecError;

	*vmsg = {};
	auto pmime = vmsg;
	decltype(vmsg) pmixed, pplain, phtml, prelated, pcalendar;
	auto vhead = pmime->getHeader();

	switch (skel.mail_type) {
	case oxcmail_type::normal:
	case oxcmail_type::calendar:
	case oxcmail_type::dsn:
	case oxcmail_type::mdn:
		if (skel.mail_type == oxcmail_type::dsn) {
			pmixed = pmime;
			auto ctf = vmime::dynamicCast<vmime::contentTypeField>(vhead->ContentType());
			ctf->setValue(mt_report);
			ctf->setReportType(vmime::mediaTypes::MESSAGE_DELIVERY_STATUS);
			auto bp = vmime::make_shared<vmime::bodyPart>();
			pmime->getBody()->appendPart(bp);
			pmime = std::move(bp);
		} else if (skel.mail_type == oxcmail_type::mdn) {
			pmixed = pmime;
			auto ctf = vmime::dynamicCast<vmime::contentTypeField>(vhead->ContentType());
			ctf->setValue(mt_report);
			ctf->setReportType(vmime::mediaTypes::MESSAGE_DISPOSITION_NOTIFICATION);
			auto bp = vmime::make_shared<vmime::bodyPart>();
			pmime->getBody()->appendPart(bp);
			pmime = std::move(bp);
		} else if (skel.b_attachment) {
			pmixed = pmime;
			pmime->getBody()->setContentType(mt_mixed);
			auto bp = vmime::make_shared<vmime::bodyPart>();
			pmime->getBody()->appendPart(bp);
			pmime = std::move(bp);
		}
		if (skel.b_inline) {
			prelated = pmime;
			pmime->getBody()->setContentType(mt_rel);
			auto bp = vmime::make_shared<vmime::bodyPart>();
			pmime->getBody()->appendPart(bp);
			pmime = std::move(bp);
		}
		if (skel.body_type == oxcmail_body::plain_and_html &&
		    skel.pplain != nullptr && skel.phtml != nullptr) {
			pmime->getBody()->setContentType(mt_alt);
			pplain = vmime::make_shared<vmime::bodyPart>();
			phtml = vmime::make_shared<vmime::bodyPart>();
			pmime->getBody()->appendPart(pplain);
			pmime->getBody()->appendPart(phtml);
			if (skel.mail_type == oxcmail_type::calendar) {
				pcalendar = vmime::make_shared<vmime::bodyPart>();
				pmime->getBody()->appendPart(pcalendar);
			}
		} else if (skel.body_type == oxcmail_body::plain_only &&
		    skel.pplain != nullptr) {
 PLAIN_ONLY:
			if (skel.mail_type != oxcmail_type::calendar) {
				pplain = pmime;
			} else {
				pmime->getBody()->setContentType(mt_alt);
				pplain = vmime::make_shared<vmime::bodyPart>();
				pcalendar = vmime::make_shared<vmime::bodyPart>();
				pmime->getBody()->appendPart(pplain);
				pmime->getBody()->appendPart(pcalendar);
			}
		} else if (skel.body_type == oxcmail_body::html_only &&
		    skel.phtml != nullptr) {
 HTML_ONLY:
			if (skel.mail_type != oxcmail_type::calendar) {
				phtml = pmime;
			} else {
				pmime->getBody()->setContentType(mt_alt);
				phtml = vmime::make_shared<vmime::bodyPart>();
				pcalendar = vmime::make_shared<vmime::bodyPart>();
				pmime->getBody()->appendPart(phtml);
				pmime->getBody()->appendPart(pcalendar);
			}
		} else if (skel.phtml != nullptr) {
			skel.body_type = oxcmail_body::html_only;
			goto HTML_ONLY;
		} else {
			skel.body_type = oxcmail_body::plain_only;
			goto PLAIN_ONLY;
		}
		break;
	case oxcmail_type::tnef:
		pmime->getBody()->setContentType(mt_mixed);
		pplain = vmime::make_shared<vmime::bodyPart>();
		pmime->getBody()->appendPart(pplain);
		break;
	case oxcmail_type::xsigned:
	case oxcmail_type::encrypted:
		break;
	}

	auto err = omv_export_mail_head(mct, skel, alloc, get_propids,
	           get_propname, *vhead);
	if (err != ecSuccess)
		return err;

	if (skel.mail_type == oxcmail_type::encrypted ||
	    skel.mail_type == oxcmail_type::xsigned) {
		vmime::mediaType mt_pkcs(vmime::mediaTypes::APPLICATION, "pkcs7-mime");
		auto a = mct.children.pattachments;
		if (a == nullptr || a->count != 1) {
			auto s = fmt::format("[Message is not a valid OXOSMIME message. "
			         "Found {} attachment objects, but exactly one is required.]",
			         a != nullptr ? a->count : 0);
			pmime->getBody()->setContents(vmime::make_shared<vmime::stringContentHandler>(std::move(s)), mt_plain, vmime::charsets::UTF_8);
			return ecSuccess;
		}
		auto bin = a->pplist[0]->proplist.get<BINARY>(PR_ATTACH_DATA_BIN);
		if (bin == nullptr)
			return ecSuccess;
		if (skel.mail_type != oxcmail_type::encrypted)
			return omv_smime_signed_fold(*pmime, std::string(bin->pc, bin->cb));
		pmime->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(std::string(bin->pc, bin->cb)),
			mt_pkcs);
		pmime->getBody()->setEncoding(vmime::encoding(vmime::encodingTypes::BASE64));
		return ecSuccess;
	}

	if (pplain != nullptr && skel.pplain != nullptr)
		omv_set_bodytext(*pplain, skel.pplain, mt_plain);

	if (skel.mail_type == oxcmail_type::tnef) {
		auto bp = vmime::make_shared<vmime::bodyPart>();
		pmime->getBody()->appendPart(bp);
		pmime = std::move(bp);
		auto bin = tnef_serialize(&mct, log_id, alloc, get_propname);
		if (bin == nullptr)
			return ecError;
		auto cl_0 = HX::make_scope_exit([&]() { rop_util_free_binary(bin); });
		pmime->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(std::string(bin->pc, bin->cb)),
			vmime::mediaType(vmime::mediaTypes::APPLICATION, "ms-tnef"));
		pmime->getBody()->setEncoding(vmime::encoding(vmime::encodingTypes::BASE64));
		auto hdr = pmime->getHeader();
		auto phf = vmime::dynamicCast<vmime::parameterizedHeaderField>(hdr->ContentType());
		*phf->getParameter("name") = vmime::parameter("name", "winmail.dat");
		hdr->ContentDisposition()->setValue(vmime::contentDispositionTypes::ATTACHMENT);
		phf = vmime::dynamicCast<vmime::parameterizedHeaderField>(hdr->ContentDisposition());
		*phf->getParameter("filename") = vmime::parameter("filename", "winmail.dat");
		return ecSuccess;
	}

	if (phtml != nullptr && skel.phtml != nullptr)
		omv_set_bodytext(*phtml, *skel.phtml, mt_html, skel.charset);

	if (pcalendar != nullptr) {
		oxcical_converter cvt;
		cvt.log_id = log_id;
		cvt.org_name = g_oxcmail_org_name;
		cvt.alloc = alloc;
		cvt.get_propids = get_propids;
		cvt.id2user = oxcmail_get_username;

		ical ical;
		if (!cvt.mapi_to_ical(mct, ical)) {
			mlog(LV_WARN, "W-2186: oxcical_export %s failed (unspecified reason)", log_id);
			return ecError;
		}
		std::string tmp_buff;
		auto err = ical.serialize(tmp_buff);
		if (err != ecSuccess) {
			mlog(LV_ERR, "E-2361: %s", mapi_strerror(err));
			return err;
		}
		auto method = ical_get_method(ical);
		omv_set_bodytext(*pcalendar, tmp_buff, mt_cal);
		if (!method.empty()) {
			auto hdr = pcalendar->getHeader();
			auto ctf = vmime::dynamicCast<vmime::contentTypeField>(hdr->ContentType());
			*ctf->getParameter("method") = vmime::parameter("method", std::move(method));
		}
	}

	if (skel.mail_type == oxcmail_type::dsn) {
		std::string content;
		if (!oxcmail_export_dsn(&mct, skel.charset, skel.pmessage_class,
		    g_oxcmail_org_name, oxcmail_get_username, content))
			return ecError;

		auto bp = vmime::make_shared<vmime::bodyPart>();
		pmixed->getBody()->appendPart(bp);
		bp->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(content),
			vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_DELIVERY_STATUS));
	} else if (skel.mail_type == oxcmail_type::mdn) {
		std::string content;
		if (!oxcmail_export_mdn(&mct, skel.charset, skel.pmessage_class,
		    content))
			return ecError;

		auto bp = vmime::make_shared<vmime::bodyPart>();
		pmixed->getBody()->appendPart(bp);
		bp->getBody()->setContents(
			vmime::make_shared<vmime::stringContentHandler>(content),
			vmime::mediaType(vmime::mediaTypes::MESSAGE, vmime::mediaTypes::MESSAGE_DISPOSITION_NOTIFICATION));
	}

	err = export_tnef_body(skel, prelated, mail_depth);
	if (err != ecSuccess) {
		mlog(LV_ERR, "E-2941: %s", mapi_strerror(err));
		return err;
	}
	err = export_attachments(mct, skel, prelated, pmixed, mail_depth);
	if (err != ecSuccess) {
		mlog(LV_ERR, "E-2940: %s", mapi_strerror(err));
		return err;
	}
	return ecSuccess;
}

ec_error_t oxcmail_converter::mapi_to_inet(const message_content &mct,
    vmime::shared_ptr<vmime::message> out) try
{
	return do_export(mct, false, out, 0);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecMAPIOOM;
} catch (const vmime::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
	return ecError;
} catch (const std::exception &e) {
	mlog(LV_ERR, "%s: %s", __func__, e.what());
	return ecError;
} catch (...) {
	mlog(LV_ERR, "%s: ecError", __func__);
	return ecError;
}

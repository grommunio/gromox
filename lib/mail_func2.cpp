// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <memory>
#include <string>
#include <json/value.h>
#include <libHX/string.h>
#include <vmime/contentDispositionField.hpp>
#include <vmime/contentTypeField.hpp>
#include <vmime/generationContext.hpp>
#include <vmime/utility/outputStreamStringAdapter.hpp>
#include <gromox/fileio.h>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapierr.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/util.hpp>

using namespace gromox;

/**
 * Render HTML document as plaintext.
 *
 * @inbuf:  input data
 * @cpid:   character set of input data (overriding any <meta> tag
 *          inside the data); use %CP_OEMCP to indicate "guess".
 * @outbuf: result variable for caller
 *
 * Returns %CP_UTF8 to indicate conversion to UTF-8 happened.
 * Returns @cpid to indicate no charset conversion happened.
 * Thus it is possible for %CP_OEMCP to be returned again if the input cpid was
 * %CP_OEMCP, which creates a situation where html_to_plain's caller may need
 * to postprocess the output.
 * Returns a negative number on error.
 */
int html_to_plain(std::string_view inbuf, cpid_t cpid, std::string &outbuf)
{
	auto cset = cpid_to_cset(cpid);
	auto s = getenv("GROMOX_HTMLTOPLAIN"); /* for testing */
	if (s == nullptr) {
		/*
		 * Automatic mode. Prefer Chawan because it handles <p
		 * align="right"> and produces the nicest <ul> lists.
		 */
		auto ret = convert_doc_with_program(inbuf, cset, outbuf, REND_CHAWAN);
		if (ret >= 0)
			return CP_UTF8;
		ret = convert_doc_with_program(inbuf, cset, outbuf, REND_PANDOC_HTP);
		if (ret >= 0)
			return CP_UTF8;
		ret = convert_doc_with_program(inbuf, cset, outbuf, REND_W3M);
		if (ret >= 0)
			return CP_UTF8;
		/*
		 * LibreOffice works in principle but has plenty of undesirable
		 * characteristics: underdocumented, quirky to invoke, slower
		 * than pandoc, produces non-wrapped text (unacceptable).
		 *
		 * lowriter
		 *     -env:UserInstallation=file://some/ephemeral/path
		 *  or --nolockcheck
		 * --convert-to txt:Text 1.html
		 */
	} else if (strcasecmp(s, "chawan") == 0) {
		return convert_doc_with_program(inbuf, cset, outbuf, REND_CHAWAN) >= 0 ? CP_UTF8 : -1;
	} else if (strcasecmp(s, "pandoc") == 0) {
		return convert_doc_with_program(inbuf, cset, outbuf, REND_PANDOC_HTP) >= 0 ? CP_UTF8 : -1;
	} else if (strcasecmp(s, "w3m") == 0) {
		return convert_doc_with_program(inbuf, cset, outbuf, REND_W3M) >= 0 ? CP_UTF8 : -1;
	}
	auto ret = html_to_plain_boring(inbuf, outbuf);
	return ret >= 0 ? cpid : ret;
}

/**
 * @rbuf: input buffer; must be UTF-8
 *        (this is normally the case, since props.get<char>(PR_BODY) is UTF-8)
 * @out:  output buffer; will be filled with UTF-8
 *        (caller may need to set PR_INTERNET_CPID=65001 [CP_UTF8] if not
 *        already done).
 *
 * It is allowed for @rbuf to point to the same object as @out.
 */
ec_error_t plain_to_html(const char *rbuf, std::string &out) try
{
	static constexpr char head[] =
		"<html><head><meta name=\"Generator\" content=\"gromox-texttohtml"
		"\">\r\n</head>\r\n<body>\r\n<pre>";
	static constexpr char footer[] = "</pre>\r\n</body>\r\n</html>";

	/*
	 * pandoc does not have any conversion from plain -> anything, we
	 * really need to do this ourselves.
	 */
	std::unique_ptr<char[], stdlib_delete> body(HX_strquote(rbuf, HXQUOTE_HTML, nullptr));
	if (body == nullptr)
		return ecMAPIOOM;
	out = std::string(head) + body.get() + footer;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecMAPIOOM;
}

bool mime_string_to_utf8(std::string_view in, std::string &out) try
{
	auto vpctx = vmail_default_parsectx();
	vmime::text t;
	t.parse(vpctx, std::string(in));
	out = t.getConvertedText(vmime::charsets::UTF_8);
	return true;
} catch (const std::bad_alloc &) {
	return false;
} catch (const vmime::exception &) {
	/* e.g. charset_conv_error for unconvertible charsets */
	return false;
}

namespace gromox {

vmime::parsingContext vmail_default_parsectx()
{
	vmime::parsingContext c;
	c.setInternationalizedEmailSupport(true); /* RFC 6532 */
	return c;
}

vmime::generationContext vmail_default_genctx()
{
	vmime::generationContext c;
	/* Outlook is unable to read RFC 2184/2231. */
	c.setEncodedParameterValueMode(vmime::generationContext::EncodedParameterValueModes::PARAMETER_VALUE_RFC2231_AND_RFC2047);
	/* Outlook is also unable to parse Content-ID:\n id... */
	c.setWrapMessageId(false);
	return c;
}

std::string vmail_to_string(const vmime::message &msg)
{
	std::string ss;
	vmime::utility::outputStreamStringAdapter adap(ss);
	msg.generate(vmail_default_genctx(), adap);
	return ss;
}

std::string vmail_to_string(const vmime::header &msg)
{
	std::string ss;
	vmime::utility::outputStreamStringAdapter adap(ss);
	msg.generate(vmail_default_genctx(), adap);
	return ss;
}

static int vmail_to_struct_digest_1(std::string_view omsg, vmime::bodyPart &part, std::string_view part_id, Json::Value &dsarray);

/**
 * @omsg:    pointer to complete original message byte stream
 * @vmsg:    broken-down representation
 * @part_id: part identifer, or empty if it's the top-level object
 * @dsarray: output
 *
 * Iterate over the set of children and analyze them recursively.
 * @vmsg is supposed to be a multipart/ container.
 */
static int vmail_to_struct_digest_C(std::string_view omsg,
    vmime::bodyPart &vmsg, std::string_view base_id,
    Json::Value &dsarray) try
{
	unsigned int part_ctr = 0;

	for (auto child : vmsg.getBody()->getChildComponents()) {
		auto part = vmime::dynamicCast<vmime::bodyPart>(child);
		if (part == nullptr)
			continue;

		std::string part_id;
		++part_ctr;
		if (base_id.empty())
			part_id = std::to_string(part_ctr);
		else
			part_id = std::string(base_id) + "." + std::to_string(part_ctr);

		auto ret = vmail_to_struct_digest_1(omsg, *part, part_id, dsarray);
		if (ret < 0)
			return ret;
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return -1;
}

/**
 * @omsg:    pointer to complete original message byte stream
 * @vmsg:    broken-down representation of message or mpart
 * @part_id: part identifer, or empty if it's the top-level object
 * @dsarray: output
 */
static int vmail_to_struct_digest_1(std::string_view omsg, vmime::bodyPart &part,
    std::string_view part_id, Json::Value &dsarray) try
{
	auto &body = *part.getBody();
	if (body.getPartCount() == 0)
		return 0;

	/* only look at multipart/… objects */
	auto &entry = dsarray.append(Json::objectValue);
	entry["id"] = std::string(part_id);
	auto &hdr = *part.getHeader();
	if (auto ctf = hdr.findField<vmime::contentTypeField>(vmime::fields::CONTENT_TYPE);
	    ctf != nullptr)
		entry["ctype"] = ctf->getValue()->generate();

	/*
	 * @vmsg has no direct references/pointers into @omsg,
	 * but the offsets are in relation to what is in @omsg.
	 */
	entry["head"]   = Json::Value::Int64(hdr.getParsedOffset());
	entry["begin"]  = Json::Value::Int64(body.getParsedOffset());
	entry["length"] = Json::Value::Int64(body.getParsedLength());
	return vmail_to_struct_digest_C(omsg, part, part_id, dsarray);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return -1;
}

/**
 * @omsg:    pointer to complete original message byte stream
 * @part:    broken-down representation of message or mpart
 * @part_id: part identifer, or empty if it's the top-level object
 * @dsarray: output
 *
 * Containers are descended into; every leaf (including a message that
 * consists of just one part) gets an entry.
 */
static int vmail_to_mimes_digest(std::string_view omsg, vmime::bodyPart &part,
    std::string_view part_id, Json::Value &dsarray) try
{
	auto &body = *part.getBody();
	if (body.getPartCount() > 0) {
		unsigned int part_ctr = 0;
		for (auto child : body.getChildComponents()) {
			auto sub = vmime::dynamicCast<vmime::bodyPart>(child);
			if (sub == nullptr)
				continue;
			++part_ctr;
			auto sub_id = part_id.empty() ? std::to_string(part_ctr) :
			              std::string(part_id) + "." + std::to_string(part_ctr);
			auto ret = vmail_to_mimes_digest(omsg, *sub, sub_id, dsarray);
			if (ret < 0)
				return ret;
		}
		return 0;
	}

	auto &entry = dsarray.append(Json::objectValue);
	entry["id"] = std::string(part_id);
	auto &hdr = *part.getHeader();
	auto ctf = hdr.findField<vmime::contentTypeField>(vmime::fields::CONTENT_TYPE);
	if (ctf != nullptr) {
		entry["ctype"] = ctf->getValue()->generate();
	} else {
		/* RFC 2046 §5.1.5 */
		auto parent = part.getParentPart();
		auto pctf = parent != nullptr ? parent->getHeader()->findField<vmime::contentTypeField>(vmime::fields::CONTENT_TYPE) : nullptr;
		entry["ctype"] = pctf != nullptr && *pctf->getValue<vmime::mediaType>() ==
		                 vmime::mediaType(vmime::mediaTypes::MULTIPART, vmime::mediaTypes::MULTIPART_DIGEST) ?
		                 "message/rfc822" : "text/plain";
	}
	if (auto charset = ctf != nullptr ? ctf->findParameter("charset") : nullptr; charset != nullptr) {
		auto cs = charset->getValue().generate();
		if (!cs.empty())
			entry["charset"] = std::move(cs);
	}

	entry["head"]   = Json::Value::Int64(hdr.getParsedOffset());
	auto body_start = body.getParsedOffset(), body_len = body.getParsedLength();
	entry["begin"]  = Json::Value::Int64(body_start);
	entry["length"] = Json::Value::Int64(body_len);
	entry["lines"]  = body_start + body_len <= omsg.size() ?
	                  std::count(omsg.data() + body_start, omsg.data() + body_start + body_len, '\n') :
	                  0;
	auto fld = hdr.findField(vmime::fields::CONTENT_TRANSFER_ENCODING);
	/* RFC 2045 §6.1: absent Content-Transfer-Encoding means 7bit. */
	entry["encoding"] = fld != nullptr ? fld->getValue()->generate() : "7bit";
	auto ctd = hdr.findField<vmime::contentDispositionField>(vmime::fields::CONTENT_DISPOSITION);
	if (ctd != nullptr)
		entry["cntdspn"] = ctd->getValue()->generate();
	if (ctd != nullptr && ctd->hasFilename())
		entry["filename"] = base64_encode(ctd->getFilename().getConvertedText(vmime::charsets::UTF_8));
	else if (auto name = ctf != nullptr ? ctf->findParameter("name") : nullptr; name != nullptr)
		/* RFC 1341 (obsoleted by RFC 2183) */
		entry["filename"] = base64_encode(name->getValue().getConvertedText(vmime::charsets::UTF_8));
	fld = hdr.findField(vmime::fields::CONTENT_ID);
	if (fld != nullptr)
		entry["cid"] = base64_encode(fld->getValue()->generate());
	fld = hdr.findField(vmime::fields::CONTENT_LOCATION);
	if (fld != nullptr)
		entry["cntl"] = base64_encode(fld->getValue()->generate());
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return -1;
}

static void vmail_digest_smime_flags(vmime::bodyPart &part, Json::Value &digest)
{
	auto ctf = part.getHeader()->findField<vmime::contentTypeField>(vmime::fields::CONTENT_TYPE);
	if (ctf != nullptr) {
		if (*ctf->getValue<vmime::mediaType>() == vmime::mediaType(vmime::mediaTypes::MULTIPART, "signed"))
			digest["signed"] = 1;
		if (ctf->findParameter("smime-type") != nullptr)
			digest["encrypt"] = 1;
	}
	for (auto child : part.getBody()->getChildComponents()) {
		auto sub = vmime::dynamicCast<vmime::bodyPart>(child);
		if (sub != nullptr)
			vmail_digest_smime_flags(*sub, digest);
	}
}

int vmail_to_digest(std::string_view omsg, vmime::bodyPart &vmsg, Json::Value &digest) try
{
	auto &vhdr = *vmsg.getHeader();
	digest = Json::objectValue;

	if (auto hf = vhdr.findField(vmime::fields::MESSAGE_ID))
		digest["msgid"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::DATE))
		digest["date"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::FROM))
		digest["from"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::SENDER)) {
		auto s = hf->getValue()->generate();
		if (!s.empty())
			digest["sender"] = base64_encode(s);
	}
	if (auto hf = vhdr.findField(vmime::fields::REPLY_TO)) {
		auto s = hf->getValue()->generate();
		if (!s.empty())
			digest["reply"] = base64_encode(s);
	}
	if (auto hf = vhdr.findField(vmime::fields::TO))
		digest["to"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::CC))
		digest["cc"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::BCC))
		digest["bcc"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::IN_REPLY_TO)) {
		auto s = hf->getValue()->generate();
		if (!s.empty())
			digest["inreply"] = base64_encode(s);
	}

	unsigned int priority = 3;
	if (auto hf = vhdr.findField("X-Priority")) {
		auto v = strtol(hf->getValue()->generate().c_str(), nullptr, 0);
		priority = v > 0 && v <= 5 ? v : 3;
	}
	digest["priority"] = Json::Value::UInt64(priority);

	if (auto hf = vhdr.findField(vmime::fields::SUBJECT))
		digest["subject"] = base64_encode(hf->getValue()->generate());

	if (auto hf = vhdr.findField(vmime::fields::RECEIVED)) {
		/* Find date */
		auto str = hf->getValue()->generate();
		auto ptr = strrchr(str.c_str(), ';');
		if (NULL == ptr) {
			digest["received"] = digest["date"];
		} else {
			ptr ++;
			while (*ptr == ' ' || *ptr == '\t')
				ptr ++;
			digest["received"] = base64_encode(ptr);
		}
	} else {
		digest["received"] = digest["date"];
	}

	digest["uid"]       = 0;
	digest["recent"]    = 1;
	digest["read"]      = 0;
	digest["replied"]   = 0;
	digest["unsent"]    = 0;
	digest["forwarded"] = 0;
	digest["flag"]      = 0;
	if (auto hf = vhdr.findField(vmime::fields::DISPOSITION_NOTIFICATION_TO))
		digest["notification"] = base64_encode(hf->getValue()->generate());
	if (auto hf = vhdr.findField(vmime::fields::REFERENCES))
		digest["ref"] = base64_encode(hf->getValue()->generate());

	vmail_digest_smime_flags(vmsg, digest);

	Json::Value dsarray = Json::arrayValue;
	if (vmail_to_struct_digest_1(omsg, vmsg, {}, dsarray) < 0)
		return -1;
	digest["structure"] = std::move(dsarray);

	dsarray = Json::arrayValue;
	if (vmail_to_mimes_digest(omsg, vmsg, {}, dsarray) < 0)
		return -1;
	digest["mimes"] = std::move(dsarray);
	digest["size"] = vmsg.getParsedLength();
	return 1;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return -1;
}

}

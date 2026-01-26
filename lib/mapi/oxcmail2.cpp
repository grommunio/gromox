// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2026 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <libHX/ctype_helper.h>
#include <libHX/libxml_helper.h>
#include <libHX/string.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <vmime/generationContext.hpp>
#include <vmime/utility/outputStreamStringAdapter.hpp>
#include <gromox/element_data.hpp>
#include <gromox/mail.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mime.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "oxcmail_int.hpp"

using namespace std::string_literals;
using namespace gromox;
using namespace oxcmail;

namespace oxcmail {

struct xmlfree {
	void operator()(xmlDoc *d) const { xmlFreeDoc(d); }
	void operator()(xmlChar *s) const { xmlFree(s); }
};

using xmldocptr = std::unique_ptr<xmlDoc, xmlfree>;

/**
 * @part:  MIME part to analyze (including its children)
 * @info:  Result structure
 * @level: how often to recurse into multiparts.
 *         If level==0, a top-level multipart/ will not be analyzed.
 * Returns: indicator if something usable was found
 *
 * Recursively go through MIME parts and select parts to use for
 * populating PR_BODY, PR_HTML, PR_RTF_COMPRESSED.
 */
void select_parts(const MIME *part, MIME_ENUM_PARAM &info, unsigned int level) try
{
	char dispo[32];
	if (part->get_field("Content-Disposition", dispo, std::size(dispo)) &&
	    strncasecmp(dispo, "attachment", 10) == 0 &&
	    (dispo[10] == '\0' || dispo[10] == ';'))
		return;
	if (part->mime_type == mime_type::single) {
		if (strcasecmp(part->content_type, "text/plain") == 0) {
			info.pplain = part;
			info.hjoin.push_back(part);
		} else if (strcasecmp(part->content_type, "text/html") == 0) {
			info.htmls.push_back(part);
			info.hjoin.push_back(part);
		} else if (strcasecmp(part->content_type, "text/enriched") == 0) {
			info.penriched = part;
		} else if (strcasecmp(part->content_type, "text/calendar") == 0) {
			info.pcalendar = part;
		} else if (strncasecmp(part->content_type, "image/", 6) == 0) {
			info.hjoin.push_back(part);
		}
		return;
	}
	/*
	 * At level 0, we are inspecting the root (the mail itself, only one of
	 * these tests will succeed)
	 */
	if (level >= MAXIMUM_SEARCHING_DEPTH)
		return;
	++level;
	bool alt = strcasecmp(part->content_type, "multipart/alternative") == 0;
	bool hjoin_enabled = false;
	size_t child_idx = 0;

	for (auto child = part->get_child(); child != nullptr;
	     (child = child->get_sibling()), ++child_idx) {
		MIME_ENUM_PARAM cld_info{info.phash};
		select_parts(child, cld_info, level);
		if (alt) {
			if (cld_info.pplain != nullptr)
				info.pplain = cld_info.pplain;
			if (cld_info.htmls.size() > 0) {
				info.htmls = std::move(cld_info.htmls);
				info.hjoin = std::move(cld_info.hjoin);
			}
			if (cld_info.penriched != nullptr)
				info.penriched = cld_info.penriched;
			if (cld_info.pcalendar != nullptr)
				info.pcalendar = cld_info.pcalendar;
			continue;
		}

		if (child_idx == 0 && cld_info.htmls.size() > 0)
			hjoin_enabled = true;
		if (cld_info.pplain != nullptr && info.pplain == nullptr)
			info.pplain = std::move(cld_info.pplain);
		if (hjoin_enabled) {
			info.htmls.insert(info.htmls.end(), std::make_move_iterator(cld_info.htmls.begin()), std::make_move_iterator(cld_info.htmls.end()));
			info.hjoin.insert(info.hjoin.end(), std::make_move_iterator(cld_info.hjoin.begin()), std::make_move_iterator(cld_info.hjoin.end()));
		}
		if (cld_info.penriched != nullptr && info.penriched == nullptr)
			info.penriched = std::move(cld_info.penriched);
		if (cld_info.pcalendar != nullptr && info.pcalendar == nullptr)
			info.pcalendar = std::move(cld_info.pcalendar);
	}
} catch (const std::bad_alloc &) {
	return;
}

ec_error_t bodyset_html(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset)
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err != ecSuccess)
		return err;
	BINARY bin;
	bin.cb = std::min(rawbody.size(), static_cast<size_t>(UINT32_MAX));
	bin.pc = rawbody.data();
	return props.set(PR_HTML, &bin);
}

ec_error_t bodyset_plain(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset) try
{
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	TAGGED_PROPVAL pv;
	/*
	 * string_mb_to_utf8() may or may not(!) call iconv. Thus, we have
	 * an unconditional utf8_filter call in case the message
	 * declared charset=utf-8 and still included garbage.
	 */
	if (string_mb_to_utf8(charset, rawbody.c_str(),
	    utfbody.data(), utfbody.size() + 1)) {
		utf8_filter(utfbody.data());
		pv.proptag = PR_BODY;
		pv.pvalue  = utfbody.data();
	} else {
		pv.proptag = PR_BODY_A;
		pv.pvalue  = rawbody.data();
	}
	return props.set(pv);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

ec_error_t bodyset_enriched(TPROPVAL_ARRAY &props,
    std::string &&rawbody, const char *charset) try
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err != ecSuccess)
		return err;
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	enriched_to_html(rawbody.c_str(), utfbody.data(), utfbody.size() + 1);
	BINARY bin;
	bin.cb = utfbody.size();
	bin.pc = utfbody.data();
	return props.set(PR_HTML, &bin);
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

static xmlNode *find_element(xmlNode *node, const char *elem)
{
	for (node = xmlFirstElementChild(node); node != nullptr;
	     node = xmlNextElementSibling(node))
		if (xml_strcasecmp(node->name, elem) == 0)
			return node;
	return nullptr;
}

static xmlNode *find_element(xmlDoc *doc, const char *elem)
{
	if (doc == nullptr)
		return nullptr;
	auto node = xmlDocGetRootElement(doc);
	if (node == nullptr)
		return nullptr;
	return find_element(node, elem);
}

static bool multibody_supported_img(const char *t)
{
	if (strncasecmp(t, "image/", 6) != 0)
		return false;
	t += 6;
	return strcasecmp(t, "jpeg") == 0 || strcasecmp(t, "png") == 0 ||
	       strcasecmp(t, "gif") == 0 || strcasecmp(t, "bmp") == 0;
}

static ec_error_t multibody_plain(std::string &&utfbody, xmldocptr &ag_doc) try
{
	auto ag_body = find_element(ag_doc.get(), "body");
	if (ag_body == nullptr)
		return ecInvalidParam;
	/*
	 * EXC2019: <div class="BodyFragment"><font size="2">
	 * <span style="font-size: 10pt;"><div class="PlainText">
	 */
	auto body = xmlNewDocNode(ag_doc.get(), nullptr,
		    reinterpret_cast<const xmlChar *>("pre"), nullptr);
	if (body == nullptr)
		return ecServerOOM;
	xmlAddChild(ag_body, body);
	auto content = xmlNewDocTextLen(ag_doc.get(),
		       reinterpret_cast<const xmlChar *>(utfbody.c_str()),
		       utfbody.size());
	if (content == nullptr)
		return ecServerOOM;
	xmlAddChild(body, content);
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

static void filter_meta(xmlNode *root)
{
	for (auto child = xmlFirstElementChild(root); child != nullptr; ) {
		filter_meta(child);
		auto curr = child;
		child = xmlNextElementSibling(curr);
		if (curr->type != XML_ELEMENT_NODE ||
		    xml_strcasecmp(curr->name, "meta") != 0)
			continue;
		auto val = xml_getprop(curr, "http-equiv");
		if (val == nullptr || strcasecmp(val, "Content-Type") != 0)
			continue;
		xmlUnlinkNode(curr);
		xmlFreeNode(curr);
	}
}

static ec_error_t multibody_html(std::string &&utfbody, xmldocptr &ag_doc) try
{
	std::unique_ptr<xmlDoc, xmlfree> doc(htmlReadMemory(utfbody.c_str(),
		utfbody.size(), nullptr, "utf-8",
		HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET));
	if (doc == nullptr)
		return ecServerOOM;
	utfbody.clear();
	utfbody.shrink_to_fit();

	/* Add basic structure if MIME part is kinda blank */
	auto root = xmlDocGetRootElement(doc.get());
	if (root == nullptr) {
		root = xmlNewDocNode(doc.get(), nullptr,
		       reinterpret_cast<const xmlChar *>("html"), nullptr);
		if (root == nullptr)
			return ecServerOOM;
		xmlDocSetRootElement(doc.get(), root);
	} else {
		filter_meta(find_element(root, "head"));
	}
	auto body = find_element(root, "body");
	if (body == nullptr) {
		body = xmlNewDocNode(doc.get(), nullptr,
		       reinterpret_cast<const xmlChar *>("body"), nullptr);
		if (body == nullptr)
			return ecServerOOM;
		xmlAddChild(root, body);
	}
	auto interbody = xmlNewDocNode(doc.get(), nullptr,
			 reinterpret_cast<const xmlChar *>("body"), nullptr);
	if (interbody == nullptr)
		return ecServerOOM;
	xmlUnlinkNode(body);
	xmlAddChild(interbody, body);
	xmlAddChild(root, interbody);
	xmlNodeSetName(body, reinterpret_cast<const xmlChar *>("div"));

	/*
	 * Now insert into possibly existing aggregate document
	 * (which has the same guaranteed structure,
	 * <html><body><div>).
	 */
	if (ag_doc == nullptr) {
		ag_doc = std::move(doc);
	} else {
		interbody = find_element(ag_doc.get(), "body");
		if (interbody == nullptr)
			return ecInvalidParam;
		xmlUnlinkNode(body);
		xmlAddChild(interbody, body);
	}
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

/**
 * @mime: may set new Content-ID
 */
static ec_error_t multibody_image(MIME_ENUM_PARAM &epar, const MIME *mime,
    xmldocptr &ag_doc) try
{
	std::string ctid;
	char ctid_raw[128];
	if (!mime->get_field("Content-ID", ctid_raw, std::size(ctid_raw))) {
		GUID::random_new().to_str(&ctid_raw[0], std::size(ctid_raw), 32);
		ctid_raw[32] = '@';
		GUID::random_new().to_str(&ctid_raw[33], std::size(ctid_raw) - 33, 32);
		ctid = "cid:"s + ctid_raw;
		epar.new_ctids.emplace(mime, ctid_raw);
	} else if (ctid_raw[0] == '<') {
		ctid = "cid:"s + &ctid_raw[1];
		if (ctid.size() > 0 && ctid.back() == '>')
			ctid.pop_back();
	} else {
		ctid = "cid:"s + ctid_raw;
	}
	auto ag_body = find_element(ag_doc.get(), "body");
	if (ag_body == nullptr)
		return ecInvalidParam;
	auto body = xmlNewDocNode(ag_doc.get(), nullptr,
		    reinterpret_cast<const xmlChar *>("div"), nullptr);
	if (body == nullptr)
		return ecServerOOM;
	xmlAddChild(ag_body, body);
	auto img = xmlNewDocNode(ag_doc.get(), nullptr,
		   reinterpret_cast<const xmlChar *>("img"), nullptr);
	if (img == nullptr)
		return ecServerOOM;
	xmlAddChild(body, img);
	if (xml_setprop(img, "src", ctid.c_str()) == nullptr)
		return ecServerOOM;
	return ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return ecServerOOM;
}

/**
 * There are some MUAs around that produce HTML mails with multiple text/html
 * parts when an inline image is inserted into the richtext textarea. The
 * bodyset_* family of functions recombines these MIME parts, because MAPI (and
 * thus all of its MUAs) can only deal with at most one PR_HTML.
 *
 * (Since one cannot add inline images to plaintext, plaintext mails are
 * generally not chopped up.)
 *
 * @epar:  input mail and its parts
 * @props: target MAPI message properties
 */
ec_error_t bodyset_multi(MIME_ENUM_PARAM &epar, TPROPVAL_ARRAY &props)
{
	xmldocptr ag_doc;

	for (auto mime : epar.hjoin) {
		auto is_html  = strcasecmp(mime->content_type, "text/html") == 0;
		auto is_plain = strcasecmp(mime->content_type, "text/plain") == 0;
		std::string utfbody;

		if (is_html || is_plain) {
			auto rdlength = mime->get_length();
			if (rdlength < 0) {
				mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
				return ecInvalidParam;
			}
			std::string rawbody;
			rawbody.resize(rdlength);
			size_t length = rdlength;
			if (!mime->read_content(rawbody.data(), &length))
				return ecError;
			rawbody.resize(length);

			std::string mime_charset;
			if (!oxcmail_get_content_param(mime, "charset", mime_charset))
				mime_charset = "us-ascii";
			utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
			if (!string_mb_to_utf8(mime_charset.c_str(), rawbody.c_str(),
			    utfbody.data(), utfbody.size() + 1))
				utfbody = std::move(rawbody);
			utf8_filter(utfbody.data());
			utfbody.resize(strlen(utfbody.c_str()));
		}

		ec_error_t err = ecSuccess;
		if (strcasecmp(mime->content_type, "text/html") == 0)
			err = multibody_html(std::move(utfbody), ag_doc);
		else if (strcasecmp(mime->content_type, "text/plain") == 0)
			err = multibody_plain(std::move(utfbody), ag_doc);
		else if (multibody_supported_img(mime->content_type))
			err = multibody_image(epar, mime, ag_doc);
		if (err != ecSuccess)
			return err;
	}

	std::unique_ptr<xmlChar[], xmlfree> ag_raw;
	int ag_rawsize = 0;
	htmlDocDumpMemoryFormat(ag_doc.get(), &unique_tie(ag_raw), &ag_rawsize, 1);
	ag_doc.reset();
	if (ag_rawsize < 0)
		ag_rawsize = 0;
	if (ag_rawsize == 0)
		return ecSuccess;
	BINARY bin;
	bin.cb = ag_rawsize;
	bin.pb = ag_raw.get();
	auto err = props.set(PR_HTML, &bin);
	if (err != ecSuccess)
		return err;
	uint32_t cpid = CP_UTF8;
	return props.set(PR_INTERNET_CPID, &cpid);
}

static bool att_is_mtg_exception(const attachment_content &at)
{
	if (at.pembedded == nullptr)
		return false;
	auto s = at.pembedded->proplist.get<const char>(PR_MESSAGE_CLASS);
	return s != nullptr && strcasecmp(s, IPM_Appointment_Exception) == 0;
}

bool attachment_is_inline(const attachment_content &at)
{
	if (at.pembedded != nullptr)
		return false;
	auto num = at.proplist.get<uint32_t>(PR_ATTACH_FLAGS);
	if (num == nullptr || !(*num & ATT_MHTML_REF))
		return false;
	return at.proplist.has(PR_ATTACH_CONTENT_ID) ||
	       at.proplist.has(PR_ATTACH_CONTENT_LOCATION);
}

bool parse_keywords(const char *field, propid_t propid,
    TPROPVAL_ARRAY &props) try
{
	proptag_t tag;
	static constexpr size_t tmp_buff_size = MIME_FIELD_LEN;
	auto tmp_buff = std::make_unique<char[]>(tmp_buff_size);

	if (!mime_string_to_utf8("us-ascii", field, tmp_buff.get(), tmp_buff_size)) {
		tag = PROP_TAG(PT_MV_STRING8, propid);
		gx_strlcpy(tmp_buff.get(), field, tmp_buff_size);
	} else {
		tag = PROP_TAG(PT_MV_UNICODE, propid);
	}
	std::vector<char *> vec;
	char *saveptr = nullptr;
	for (auto token = strtok_r(tmp_buff.get(), ",;", &saveptr);
	     token != nullptr;
	     token = strtok_r(nullptr, ",;", &saveptr)) {
		while (HX_isspace(*token))
			++token;
		vec.emplace_back(token);
	}
	if (vec.empty())
		return TRUE;
	STRING_ARRAY sa;
	sa.count = std::min(vec.size(), static_cast<size_t>(UINT32_MAX));
	sa.ppstr = vec.data();
	return props.set(tag, &sa) == ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __PRETTY_FUNCTION__);
	return false;
}

bool parse_response_suppress(const char *raw, TPROPVAL_ARRAY &props) try
{
	std::string field = raw;
	uint32_t v = 0;
	char *saveptr = nullptr;

	for (auto token = strtok_r(field.data(), ",;", &saveptr);
	     token != nullptr;
	     token = strtok_r(nullptr, ",;", &saveptr)) {
		while (HX_isspace(*token))
			++token;
		HX_strrtrim(token);
		if (strcasecmp(token, "ALL") == 0)
			v = ~0U;
		else if (strcasecmp(token, "NONE") == 0)
			v = 0;
		else if (strcasecmp(token, "DR") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_DR;
		else if (strcasecmp(token, "NDR") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_NDR;
		else if (strcasecmp(token, "RN") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_RN;
		else if (strcasecmp(token, "NRN") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_NRN;
		else if (strcasecmp(token, "OOF") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_OOF;
		else if (strcasecmp(token, "AutoReply") == 0)
			v |= AUTO_RESPONSE_SUPPRESS_AUTOREPLY;
	}
	if (v == 0)
		return true;
	return props.set(PR_AUTO_RESPONSE_SUPPRESS, &v) == ecSuccess;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

}

/* For exporting MAPI Attachments as MIME parts */
ec_error_t oxcmail_converter::export_attachments(const message_content &mc,
    const mime_skeleton &skel, MAIL &m_mail, MIME *m_related, MIME *m_mixed,
    unsigned int mail_depth)
{
	if (mc.children.pattachments == nullptr)
		return ecSuccess;
	for (const auto &at : *mc.children.pattachments) {
		if (att_is_mtg_exception(at))
			continue;
		auto b_inline = attachment_is_inline(at);
		auto new_part = m_mail.add_child(b_inline ? m_related : m_mixed, MIME_ADD_LAST);
		if (new_part == nullptr)
			return ecMAPIOOM;
		if (!export_attachment(at, b_inline, skel, *new_part, mail_depth))
			return ecError;
	}
	return ecSuccess;
}

/* Certain MAPI objects can only be expressed in MIME as TNEF */
ec_error_t oxcmail_converter::export_tnef_body(const mime_skeleton &skel,
    MAIL &mail, MIME *m_related, unsigned int mail_depth)
{
	if (skel.pattachments == nullptr)
		return ecSuccess;
	for (const auto &at : *skel.pattachments) {
		auto new_part = mail.add_child(m_related, MIME_ADD_LAST);
		if (new_part == nullptr)
			return ecMAPIOOM;
		if (!export_attachment(at, true, skel, *new_part, mail_depth))
			return ecError;
	}
	return ecSuccess;
}

namespace gromox {

vmime::generationContext vmail_default_genctx()
{
	vmime::generationContext c;
	/* Outlook is unable to read RFC 2231. */
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

bool vmail_to_mail(const vmime::message &in, MAIL &out) try
{
	auto str = vmail_to_string(in);
	auto len = str.size();
	auto buf = std::make_unique<char[]>(len);
	memcpy(buf.get(), str.c_str(), len);
	if (!out.refonly_parse(buf.get(), len))
		return false;
	out.buffer = std::move(buf);
	return true;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "%s: ENOMEM", __func__);
	return false;
}

}

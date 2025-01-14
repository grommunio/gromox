// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <libHX/libxml_helper.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mime.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "oxcmail_int.hpp"

using namespace gromox;
using namespace std::string_literals;

namespace oxcmail {

struct xmlfree {
	void operator()(xmlDoc *d) const { xmlFreeDoc(d); }
	void operator()(xmlChar *s) const { xmlFree(s); }
};

using xmldocptr = std::unique_ptr<xmlDoc, xmlfree>;

/**
 * @level: how often to recurse into multiparts.
 *         If level==0, a top-level multipart/ will not be analyzed.
 * Returns: indicator if something usable was found
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

errno_t bodyset_html(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset)
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err < 0)
		return -err;
	BINARY bin;
	bin.cb = std::min(rawbody.size(), static_cast<size_t>(UINT32_MAX));
	bin.pc = rawbody.data();
	err = props.set(PR_HTML, &bin);
	return err >= 0 ? 0 : -err;
}

errno_t bodyset_plain(TPROPVAL_ARRAY &props, std::string &&rawbody,
    const char *charset) try
{
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	TAGGED_PROPVAL pv;
	/*
	 * string_to_utf8() may or may not(!) call iconv. Thus, we have
	 * an unconditional utf8_filter call in case the message
	 * declared charset=utf-8 and still included garbage.
	 */
	if (string_to_utf8(charset, rawbody.c_str(),
	    utfbody.data(), utfbody.size() + 1)) {
		utf8_filter(utfbody.data());
		pv.proptag = PR_BODY;
		pv.pvalue  = utfbody.data();
	} else {
		pv.proptag = PR_BODY_A;
		pv.pvalue  = rawbody.data();
	}
	auto err = props.set(pv);
	return err >= 0 ? 0 : -err;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1746: ENOMEM");
	return ENOMEM;
}

errno_t bodyset_enriched(TPROPVAL_ARRAY &props,
    std::string &&rawbody, const char *charset) try
{
	uint32_t id = cset_to_cpid(charset);
	auto err = props.set(PR_INTERNET_CPID, &id);
	if (err < 0)
		return -err;
	std::string utfbody;
	utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
	enriched_to_html(rawbody.c_str(), utfbody.data(), utfbody.size() + 1);
	BINARY bin;
	bin.cb = utfbody.size();
	bin.pc = utfbody.data();
	err = props.set(PR_HTML, &bin);
	return err >= 0 ? 0 : -err;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1747: ENOMEM");
	return ENOMEM;
}

#ifndef AVOID_LIBXML
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
#endif

static bool multibody_supported_img(const char *t)
{
	if (strncasecmp(t, "image/", 6) != 0)
		return false;
	t += 6;
	return strcasecmp(t, "jpeg") == 0 || strcasecmp(t, "png") == 0 ||
	       strcasecmp(t, "gif") == 0 || strcasecmp(t, "bmp") == 0;
}

#ifdef AVOID_LIBXML
static errno_t multibody_html(std::string &&utfbody, std::string &ag_doc) try
{
	ag_doc += std::move(utfbody);
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1774: ENOMEM");
	return ENOMEM;
}

static errno_t multibody_plain(std::string &&utfbody, std::string &ag_doc) try
{
	ag_doc += "<pre>"s + std::move(utfbody) + "</pre>";
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1775: ENOMEM");
	return ENOMEM;
}

static errno_t multibody_image(MIME_ENUM_PARAM &epar, const MIME *mime,
    std::string &ag_doc) try
{
	std::string ctid;
	char ctid_raw[128];
	if (!mime->get_field("Content-ID", ctid_raw, std::size(ctid_raw))) {
		GUID::random_new().to_str(&ctid_raw[0], std::size(ctid_raw), 32);
		ctid_raw[32] = '@';
		GUID::random_new().to_str(&ctid_raw[33], std::size(ctid_raw) - 33, 32);
		ctid = ctid_raw;
		epar.new_ctids.emplace(mime, ctid_raw);
	} else if (ctid_raw[0] == '<') {
		ctid = &ctid_raw[1];
		if (ctid.size() > 0 && ctid_raw[0] == '<' && ctid.back() == '>')
			ctid.pop_back();
	} else {
		ctid = ctid_raw;
	}
	ag_doc += "<img src=\"cid:" + ctid + "\">";
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1778: ENOMEM");
	return ENOMEM;
}

#else /* AVOID_LIBXML */

static errno_t multibody_plain(std::string &&utfbody, xmldocptr &ag_doc) try
{
	auto ag_body = find_element(ag_doc.get(), "body");
	if (ag_body == nullptr)
		return EINVAL;
	/*
	 * EXC2019: <div class="BodyFragment"><font size="2">
	 * <span style="font-size: 10pt;"><div class="PlainText">
	 */
	auto body = xmlNewDocNode(ag_doc.get(), nullptr,
		    reinterpret_cast<const xmlChar *>("pre"), nullptr);
	if (body == nullptr)
		return ENOMEM;
	xmlAddChild(ag_body, body);
	auto content = xmlNewDocTextLen(ag_doc.get(),
		       reinterpret_cast<const xmlChar *>(utfbody.c_str()),
		       utfbody.size());
	if (content == nullptr)
		return ENOMEM;
	xmlAddChild(body, content);
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1766: ENOMEM");
	return ENOMEM;
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

static errno_t multibody_html(std::string &&utfbody, xmldocptr &ag_doc) try
{
	std::unique_ptr<xmlDoc, xmlfree> doc(htmlReadMemory(utfbody.c_str(),
		utfbody.size(), nullptr, "utf-8",
		HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING | HTML_PARSE_NONET));
	if (doc == nullptr)
		return ENOMEM;
	utfbody.clear();
	utfbody.shrink_to_fit();

	/* Add basic structure if MIME part is kinda blank */
	auto root = xmlDocGetRootElement(doc.get());
	if (root == nullptr) {
		root = xmlNewDocNode(doc.get(), nullptr,
		       reinterpret_cast<const xmlChar *>("html"), nullptr);
		if (root == nullptr)
			return ENOMEM;
		xmlDocSetRootElement(doc.get(), root);
	} else {
		filter_meta(find_element(root, "head"));
	}
	auto body = find_element(root, "body");
	if (body == nullptr) {
		body = xmlNewDocNode(doc.get(), nullptr,
		       reinterpret_cast<const xmlChar *>("body"), nullptr);
		if (body == nullptr)
			return ENOMEM;
		xmlAddChild(root, body);
	}
	auto interbody = xmlNewDocNode(doc.get(), nullptr,
			 reinterpret_cast<const xmlChar *>("body"), nullptr);
	if (interbody == nullptr)
		return ENOMEM;
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
			return EINVAL;
		xmlUnlinkNode(body);
		xmlAddChild(interbody, body);
	}
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1769: ENOMEM");
	return ENOMEM;
}

/**
 * @mime: may set new Content-ID
 */
static errno_t multibody_image(MIME_ENUM_PARAM &epar, const MIME *mime,
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
		return EINVAL;
	auto body = xmlNewDocNode(ag_doc.get(), nullptr,
		    reinterpret_cast<const xmlChar *>("div"), nullptr);
	if (body == nullptr)
		return ENOMEM;
	xmlAddChild(ag_body, body);
	auto img = xmlNewDocNode(ag_doc.get(), nullptr,
		   reinterpret_cast<const xmlChar *>("img"), nullptr);
	if (img == nullptr)
		return ENOMEM;
	xmlAddChild(body, img);
	if (xml_setprop(img, "src", ctid.c_str()) == nullptr)
		return ENOMEM;
	return 0;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1773: ENOMEM");
	return false;
}
#endif /* AVOID_LIBXML */

errno_t bodyset_multi(MIME_ENUM_PARAM &epar, TPROPVAL_ARRAY &props,
    const char *charset)
{
#ifdef AVOID_LIBXML
	std::string ag_doc;
#else
	xmldocptr ag_doc;
#endif

	for (auto mime : epar.hjoin) {
		auto is_html  = strcasecmp(mime->content_type, "text/html") == 0;
		auto is_plain = strcasecmp(mime->content_type, "text/plain") == 0;
		std::string utfbody;

		if (is_html || is_plain) {
			auto rdlength = mime->get_length();
			if (rdlength < 0) {
				mlog(LV_ERR, "%s:MIME::get_length: unsuccessful", __func__);
				return EINVAL;
			}
			std::string rawbody;
			rawbody.resize(rdlength);
			size_t length = rdlength;
			if (!mime->read_content(rawbody.data(), &length))
				return 0;
			rawbody.resize(length);

			std::string mime_charset;
			if (!oxcmail_get_content_param(mime, "charset", mime_charset))
				mime_charset = utf8_valid(rawbody.c_str()) ?
				               "utf-8" : epar.charset;
			utfbody.resize(mb_to_utf8_xlen(rawbody.size()));
			if (!string_to_utf8(mime_charset.c_str(), rawbody.c_str(),
			    utfbody.data(), utfbody.size() + 1))
				utfbody = std::move(rawbody);
			utf8_filter(utfbody.data());
			utfbody.resize(strlen(utfbody.c_str()));
		}

		int err = 0;
		if (strcasecmp(mime->content_type, "text/html") == 0)
			err = multibody_html(std::move(utfbody), ag_doc);
		else if (strcasecmp(mime->content_type, "text/plain") == 0)
			err = multibody_plain(std::move(utfbody), ag_doc);
		else if (multibody_supported_img(mime->content_type))
			err = multibody_image(epar, mime, ag_doc);
		if (err != 0)
			return err;
	}

#ifdef AVOID_LIBXML
	BINARY bin;
	bin.pc = ag_doc.data();
	bin.cb = ag_doc.size();
#else
	std::unique_ptr<xmlChar[], xmlfree> ag_raw;
	int ag_rawsize = 0;
	htmlDocDumpMemoryFormat(ag_doc.get(), &unique_tie(ag_raw), &ag_rawsize, 1);
	ag_doc.reset();
	if (ag_rawsize < 0)
		ag_rawsize = 0;
	if (ag_rawsize == 0)
		return 0;
	BINARY bin;
	bin.cb = ag_rawsize;
	bin.pb = ag_raw.get();
#endif /* AVOID_LIBXML */
	auto err = props.set(PR_HTML, &bin);
	if (err < 0)
		return -err;
	uint32_t cpid = CP_UTF8;
	err = props.set(PR_INTERNET_CPID, &cpid);
	if (err < 0)
		return -err;
	return 0;
}

}

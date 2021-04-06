// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
#include <json/reader.h>
#include <json/writer.h>
#include <gromox/binrdwr.hpp>
#include <gromox/fileio.h>
#include <gromox/oxoabkt.hpp>
#include <gromox/textmaps.hpp>

using namespace gromox;

enum TRow_ctl_type {
	TRC_LABEL      = 0x0,
	TRC_TEXTCTRL   = 0x1,
	TRC_LISTBOX    = 0x2,
	TRC_CHECKBOX   = 0x5,
	TRC_GROUPBOX   = 0x6,
	TRC_BUTTON     = 0x7,
	TRC_TABPAGE    = 0x8,
	TRC_MVLISTBOX  = 0xb,
	TRC_MVDROPDOWN = 0xc,
	TRC_NONE       = 0xff,
};

enum TRow_ctl_flags {
	TRF_NONE       = 0,
	TRF_MULTILINE  = 1 << 0,
	TRF_EDITABLE   = 1 << 1,
	TRF_MANDATORY  = 1 << 2,
	TRF_IMMEDIATE  = 1 << 3,
	TRF_PASSWORD   = 1 << 4,
	TRF_DOUBLEBYTE = 1 << 5,
	TRF_INDEX      = 1 << 6,
};

namespace {
struct abktaux {
	unsigned int offset = 0;
	std::string data;
};
}

static unsigned int abkt_cttype2int(const char *s)
{
#define E(q, w) do { if (strcmp(s, (q)) == 0) return w; } while (false)
	E("label", TRC_LABEL);
	E("textctrl", TRC_TEXTCTRL);
	E("listbox", TRC_LISTBOX);
	E("checkbox", TRC_CHECKBOX);
	E("groupbox", TRC_GROUPBOX);
	E("button", TRC_BUTTON);
	E("tabpage", TRC_TABPAGE);
	E("mvlistbox", TRC_MVLISTBOX);
	E("mvdropdown", TRC_MVDROPDOWN);
	return TRC_NONE;
#undef E
}

static const char *abkt_cttype2str(unsigned int v)
{
	switch (v) {
	case TRC_LABEL: return "label";
	case TRC_TEXTCTRL: return "textctrl";
	case TRC_LISTBOX: return "listbox";
	case TRC_CHECKBOX: return "checkbox";
	case TRC_GROUPBOX: return "groupbox";
	case TRC_BUTTON: return "button";
	case TRC_TABPAGE: return "tabpage";
	case TRC_MVLISTBOX: return "mvlistbox";
	case TRC_MVDROPDOWN: return "mvdropdown";
	}
	return "invalid";
}

static inline bool cttype_uses_proptag(unsigned int t)
{
	return t == TRC_TEXTCTRL || t == TRC_LISTBOX || t == TRC_CHECKBOX ||
	       t == TRC_BUTTON || t == TRC_MVLISTBOX || t == TRC_MVDROPDOWN;
}

static inline bool cttype_uses_label(unsigned int t)
{
	return t == TRC_LABEL || t == TRC_CHECKBOX || t == TRC_GROUPBOX ||
	       t == TRC_BUTTON || t == TRC_TABPAGE;
}

static inline bool cttype_uses_pattern(unsigned int t)
{
	return t == TRC_TEXTCTRL || t == TRC_LISTBOX || t == TRC_MVLISTBOX;
}

static void abkt_read_row(lb_reader &bin, Json::Value &jrow, unsigned int cpid)
{
	jrow["posx"]  = bin.r4();
	jrow["sizex"] = bin.r4();
	jrow["posy"]  = bin.r4();
	jrow["sizey"] = bin.r4();
	auto ct_type = bin.r4(), flags = bin.r4(), proptag = bin.r4();
	auto maxlen = bin.r4(), stroffset = bin.r4();
	if (ct_type == TRC_TABPAGE)
		flags = 0;
	jrow["ct_type"] = abkt_cttype2str(ct_type);
	jrow["is_multiline"]  = !!(flags & TRF_MULTILINE);
	jrow["is_editable"]   = !!(flags & TRF_EDITABLE);
	jrow["is_mandatory"]  = !!(flags & TRF_MANDATORY);
	jrow["is_password"]   = !!(flags & TRF_PASSWORD);
	jrow["is_doublebyte"] = !!(flags & TRF_DOUBLEBYTE);
	jrow["is_index"]      = !!(flags & TRF_INDEX);
	if (cttype_uses_proptag(ct_type))
		jrow["proptag"] = proptag;
	if (ct_type == TRC_TEXTCTRL)
		jrow["maxlen"] = maxlen;
	std::string text;
	if (cttype_uses_label(ct_type) || cttype_uses_pattern(ct_type)) {
		if (cpid == 0) {
			text = bin.preadustr(stroffset);
		} else {
			text = bin.preadstr(stroffset);
			text = iconvtext(text.data(), text.size(), cpid_to_cset(cpid), "UTF-8");
		}
	}
	if (cttype_uses_label(ct_type))
		jrow["label"] = std::move(text);
	else if (ct_type == TRC_TEXTCTRL)
		jrow["pattern"] = std::move(text);
}

static void abkt_read(lb_reader &bin, Json::Value &tpl, unsigned int cpid)
{
	bin.x4(1);
	auto &rowdata = tpl["rowdata"] = Json::arrayValue;
	auto rows = bin.r4();
	while (rows-- > 0) {
		auto &row = rowdata.append(Json::objectValue);
		abkt_read_row(bin, row, cpid);
	}
}

static void abkt_write_row(Json::Value &jrow, abktaux &aux, lb_writer &bin, unsigned int cpid)
{
	unsigned int ct_type = abkt_cttype2int(jrow["ct_type"].asString().c_str());
	unsigned int flags = 0;
	if (ct_type == TRC_NONE) {
		ct_type = TRC_LABEL;
		jrow["label"] = "";
	} else if (ct_type == TRC_LISTBOX || ct_type == TRC_MVLISTBOX) {
		jrow["pattern"] = "*";
	}
	if (jrow["is_multiline"].asBool())  flags |= TRF_MULTILINE;
	if (jrow["is_editable"].asBool())   flags |= TRF_EDITABLE;
	if (jrow["is_mandatory"].asBool())  flags |= TRF_MANDATORY;
	if (jrow["is_password"].asBool())   flags |= TRF_PASSWORD;
	if (jrow["is_doublebyte"].asBool()) flags |= TRF_DOUBLEBYTE;
	if (jrow["is_index"].asBool())      flags |= TRF_INDEX;

	bin.w4(jrow["posx"].asUInt());
	bin.w4(jrow["sizex"].asUInt());
	bin.w4(jrow["posy"].asUInt());
	bin.w4(jrow["sizey"].asUInt());
	bin.w4(ct_type);
	bin.w4(flags);
	bin.w4(cttype_uses_proptag(ct_type) ? jrow["proptag"].asUInt() : 0);
	bin.w4(ct_type == TRC_TEXTCTRL ? jrow["maxlen"].asUInt() : 0);
	if (!cttype_uses_label(ct_type) && !cttype_uses_pattern(ct_type)) {
		bin.w4(0);
		return;
	}
	auto field = cttype_uses_pattern(ct_type) ? "pattern" : "label";
	std::string text = jrow[field].asString();
	bin.w4(aux.offset);
	if (cpid != 0) {
		text = iconvtext(text.data(), text.size(), "UTF-8", cpid_to_cset(cpid));
		aux.offset += text.size() + 1;
		aux.data += std::move(text);
		aux.data += '\0';
		return;
	}
	text = iconvtext(text.data(), text.size(), "UTF-8", "UTF-16LE");
	aux.offset += text.size() + 2;
	aux.data += std::move(text);
	aux.data += '\0';
	aux.data += '\0';
}

static void abkt_write(Json::Value &tpl, lb_writer &bin,
    unsigned int cpid, bool dogap)
{
	bin.w4(1);
	if (!tpl.isMember("rowdata")) {
		bin.w4(0);
		return;
	}
	auto rows = std::min(tpl["rowdata"].size(), UINT_MAX - 1);
	bin.w4(rows);
	abktaux aux;
	aux.offset = 8 + 36 * rows;
	if (dogap)
		aux.offset += 4;
	for (unsigned int i = 0; i < rows; ++i) {
		auto &row = tpl["rowdata"][i];
		abkt_write_row(row, aux, bin, cpid);
	}
	if (dogap)
		bin.w4(0);
	bin.write(aux.data.data(), aux.data.size());
}

namespace gromox {

std::string abkt_tojson(const std::string &bin, unsigned int codepage)
{
	lb_reader reader(bin.data(), bin.size());
	Json::Value jval;
	abkt_read(reader, jval, codepage);
	return Json::writeString(Json::StreamWriterBuilder(), std::move(jval));
}

std::string abkt_tobinary(const std::string &json, unsigned int codepage, bool dogap)
{
	Json::Value jval;
	std::istringstream sin(json);
	auto valid = Json::parseFromStream(Json::CharReaderBuilder(), sin, &jval, nullptr);
	if (!valid)
		throw lb_reader::invalid();
	lb_writer writer;
	abkt_write(jval, writer, codepage, dogap);
	return std::move(writer.m_data);
}

}

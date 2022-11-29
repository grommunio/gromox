// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <climits>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <json/writer.h>
#include <gromox/binrdwr.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxoabkt.hpp>
#include <gromox/textmaps.hpp>

using namespace gromox;

namespace {
struct abktaux {
	unsigned int offset = 0;
	std::string data;
};
}

static unsigned int abkt_cttype2int(const char *s)
{
#define E(q, w) do { if (strcmp(s, (q)) == 0) return w; } while (false)
	E("label", DTCT_LABEL);
	E("textctrl", DTCT_EDIT);
	E("listbox", DTCT_LBX);
	E("combobox", DTCT_COMBOBOX);
	E("dropdown", DTCT_DDLBX);
	E("checkbox", DTCT_CHECKBOX);
	E("groupbox", DTCT_GROUPBOX);
	E("button", DTCT_BUTTON);
	E("tabpage", DTCT_PAGE);
	E("radiobutton", DTCT_RADIOBUTTON);
	E("mvlistbox", DTCT_MVLISTBOX);
	E("mvdropdown", DTCT_MVDDLBX);
	return _DTCT_NONE;
#undef E
}

static const char *abkt_cttype2str(unsigned int v)
{
	switch (v) {
	case DTCT_LABEL: return "label";
	case DTCT_EDIT: return "textctrl";
	case DTCT_LBX: return "listbox";
	case DTCT_COMBOBOX: return "combobox";
	case DTCT_DDLBX: return "dropdown";
	case DTCT_CHECKBOX: return "checkbox";
	case DTCT_GROUPBOX: return "groupbox";
	case DTCT_BUTTON: return "button";
	case DTCT_PAGE: return "tabpage";
	case DTCT_RADIOBUTTON: return "radiobutton";
	case DTCT_MVLISTBOX: return "mvlistbox";
	case DTCT_MVDDLBX: return "mvdropdown";
	}
	return "invalid";
}

static inline bool cttype_uses_proptag(unsigned int t)
{
	return t == DTCT_EDIT || t == DTCT_LBX || t == DTCT_COMBOBOX ||
	       t == DTCT_DDLBX || t == DTCT_CHECKBOX || t == DTCT_BUTTON ||
	       t == DTCT_RADIOBUTTON || t == DTCT_MVLISTBOX || t == DTCT_MVDDLBX;
}

static inline bool cttype_uses_label(unsigned int t)
{
	return t == DTCT_LABEL || t == DTCT_CHECKBOX || t == DTCT_GROUPBOX ||
	       t == DTCT_BUTTON || t == DTCT_RADIOBUTTON || t == DTCT_PAGE;
}

static inline bool cttype_uses_pattern(unsigned int t)
{
	return t == DTCT_EDIT || t == DTCT_LBX || t == DTCT_DDLBX ||
	       t == DTCT_COMBOBOX || t == DTCT_MVLISTBOX;
}

// DTBLCOMBOBOX has two proptags: ulPRPropertyName [to be PT_TSTRING], ulPRTableName [to be PT_OBJECT]
// DTBLDDLBX has three proptags: ulPRDisplayProperty [to be PT_TSTRING], ulPRSetProperty [PT_*], ulPRTableName [PT_OBJECT].
// DTBLLBX has two proptags: ulPRSetProperty [PT_*], ulPRTableName [PT_OBJECT]

static void abkt_read_row(lb_reader &bin, Json::Value &jrow,
    unsigned int vers, unsigned int cpid)
{
	jrow["posx"]  = bin.r4();
	jrow["sizex"] = bin.r4();
	jrow["posy"]  = bin.r4();
	jrow["sizey"] = bin.r4();
	auto ct_type = bin.r4(), flags = bin.r4();
	uint32_t gxT2Extra = vers == 2 ? bin.r4() : 0;
	auto dwType = bin.r4();
	auto ulSize = bin.r4(), ulString = bin.r4();
	if (ct_type == DTCT_PAGE)
		flags = _DT_NONE;
	jrow["ct_type"] = abkt_cttype2str(ct_type);
	jrow["is_multiline"]  = !!(flags & DT_MULTILINE);
	jrow["is_editable"]   = !!(flags & DT_EDITABLE);
	jrow["is_mandatory"]  = !!(flags & DT_REQUIRED);
	jrow["is_password"]   = !!(flags & DT_PASSWORD_EDIT);
	jrow["is_doublebyte"] = !!(flags & DT_ACCEPT_DBCS);
	jrow["is_index"]      = !!(flags & DT_SET_SELECTION);
	if (cttype_uses_proptag(ct_type))
		jrow["proptag"] = dwType;
	if (ct_type == DTCT_EDIT) {
		jrow["ulSize"] = ulSize;
	} else if (ct_type == DTCT_DDLBX) {
		jrow["proptag2"] = gxT2Extra;
		jrow["proptag3"] = ulSize;
	} else if (ct_type == DTCT_RADIOBUTTON) {
		jrow["num_buttons"] = gxT2Extra;
		jrow["return_value"] = ulSize;
	}
	std::string text;
	if (cttype_uses_label(ct_type) || cttype_uses_pattern(ct_type)) {
		if (cpid == 0) {
			text = bin.preadustr(ulString);
		} else {
			text = bin.preadstr(ulString);
			auto cset = cpid_to_cset(cpid);
			if (cset != nullptr)
				text = iconvtext(text.data(), text.size(), cset, "UTF-8");
		}
	}
	if (cttype_uses_label(ct_type))
		jrow["label"] = std::move(text);
	else if (cttype_uses_pattern(ct_type))
		jrow["pattern"] = std::move(text);
}

static void abkt_read(lb_reader &bin, Json::Value &tpl, unsigned int cpid)
{
	auto vers = bin.r4();
	if (vers != 1 && vers != 2)
		throw lb_reader::invalid();
	auto &rowdata = tpl["rowdata"] = Json::arrayValue;
	auto rows = bin.r4();
	while (rows-- > 0) {
		auto &row = rowdata.append(Json::objectValue);
		abkt_read_row(bin, row, vers, cpid);
	}
}

static void abkt_write_row(Json::Value &jrow, abktaux &aux, lb_writer &bin, unsigned int cpid)
{
	unsigned int ct_type = abkt_cttype2int(jrow["ct_type"].asString().c_str());
	unsigned int flags = _DT_NONE;
	if (ct_type == _DTCT_NONE) {
		ct_type = DTCT_LABEL;
		jrow["label"] = "";
	} else if (ct_type == DTCT_LBX || ct_type == DTCT_MVLISTBOX) {
		jrow["pattern"] = "*";
	}
	if (jrow["is_multiline"].asBool())  flags |= DT_MULTILINE;
	if (jrow["is_editable"].asBool())   flags |= DT_EDITABLE;
	if (jrow["is_mandatory"].asBool())  flags |= DT_REQUIRED;
	if (jrow["is_password"].asBool())   flags |= DT_PASSWORD_EDIT;
	if (jrow["is_doublebyte"].asBool()) flags |= DT_ACCEPT_DBCS;
	if (jrow["is_index"].asBool())      flags |= DT_SET_SELECTION;

	bin.w4(jrow["posx"].asUInt());
	bin.w4(jrow["sizex"].asUInt());
	bin.w4(jrow["posy"].asUInt());
	bin.w4(jrow["sizey"].asUInt());
	bin.w4(ct_type);
	bin.w4(flags);
	bin.w4(cttype_uses_proptag(ct_type) ? jrow["proptag"].asUInt() : 0);
	bin.w4(ct_type == DTCT_EDIT ? jrow["maxlen"].asUInt() : 0);
	if (!cttype_uses_label(ct_type) && !cttype_uses_pattern(ct_type)) {
		bin.w4(0);
		return;
	}
	auto field = cttype_uses_pattern(ct_type) ? "pattern" : "label";
	std::string text = jrow[field].asString();
	bin.w4(aux.offset);
	if (cpid != 0) {
		auto cset = cpid_to_cset(cpid);
		if (cset != nullptr)
			text = iconvtext(text.data(), text.size(), "UTF-8", cset);
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

std::string abkt_tojson(std::string_view bin, unsigned int codepage)
{
	lb_reader reader(bin.data(), bin.size());
	Json::Value jval;
	abkt_read(reader, jval, codepage);
	return Json::writeString(Json::StreamWriterBuilder(), std::move(jval));
}

std::string abkt_tobinary(std::string_view json, unsigned int codepage, bool dogap)
{
	Json::Value jval;
	if (!json_from_str(std::move(json), jval))
		throw lb_reader::invalid();
	lb_writer writer;
	abkt_write(jval, writer, codepage, dogap);
	return std::move(writer.m_data);
}

}

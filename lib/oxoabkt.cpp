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
#include <gromox/ext_buffer.hpp>
#include <gromox/fileio.h>
#include <gromox/json.hpp>
#include <gromox/mapidefs.h>
#include <gromox/oxoabkt.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#define TRY(expr) do { pack_result klfdv{expr}; if (klfdv != pack_result::success) return klfdv; } while (false)

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

static pack_result abkt_read_row(EXT_PULL &bin, Json::Value &jrow,
    unsigned int vers, cpid_t cpid)
{
	uint32_t v, ct_type, flags, gxT2Extra = 0, dwType, ulSize, ulString;
	TRY(bin.g_uint32(&v)); jrow["posx"]  = v;
	TRY(bin.g_uint32(&v)); jrow["sizex"] = v;
	TRY(bin.g_uint32(&v)); jrow["posy"]  = v;
	TRY(bin.g_uint32(&v)); jrow["sizey"] = v;
	TRY(bin.g_uint32(&ct_type));
	TRY(bin.g_uint32(&flags));
	if (vers == 2)
		TRY(bin.g_uint32(&gxT2Extra));
	TRY(bin.g_uint32(&dwType));
	TRY(bin.g_uint32(&ulSize));
	TRY(bin.g_uint32(&ulString));
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
		jrow["maxlen"] = ulSize;
	} else if (ct_type == DTCT_DDLBX) {
		jrow["proptag2"] = gxT2Extra;
		jrow["proptag3"] = ulSize;
	} else if (ct_type == DTCT_RADIOBUTTON) {
		jrow["num_buttons"] = gxT2Extra;
		jrow["return_value"] = ulSize;
	}
	std::string text;
	if (cttype_uses_label(ct_type) || cttype_uses_pattern(ct_type)) {
		std::unique_ptr<char[], stdlib_delete> raw;
		auto saved_offset = bin.m_offset;
		bin.m_offset = ulString;
		if (cpid == CP_ACP) {
			TRY(bin.g_wstr(&unique_tie(raw)));
			text = raw.get();
		} else {
			TRY(bin.g_str(&unique_tie(raw)));
			auto cset = cpid_to_cset(cpid);
			if (cset != nullptr)
				text = iconvtext(raw.get(), strlen(raw.get()), cset, "UTF-8");
		}
		bin.m_offset = saved_offset;
	}
	if (cttype_uses_label(ct_type))
		jrow["label"] = std::move(text);
	else if (cttype_uses_pattern(ct_type))
		jrow["pattern"] = std::move(text);
	return pack_result::success;
}

static pack_result abkt_read(EXT_PULL &bin, Json::Value &tpl, cpid_t cpid)
{
	uint32_t vers, rows;
	TRY(bin.g_uint32(&vers));
	if (vers != 1 && vers != 2)
		return pack_result::format;
	auto &rowdata = tpl["rowdata"] = Json::arrayValue;
	TRY(bin.g_uint32(&rows));
	while (rows-- > 0) {
		auto &row = rowdata.append(Json::objectValue);
		abkt_read_row(bin, row, vers, cpid);
	}
	return pack_result::success;
}

static void abkt_write_row(Json::Value &jrow, abktaux &aux, lb_writer &bin, cpid_t cpid)
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
	if (cpid != CP_ACP) {
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
    cpid_t cpid, bool dogap)
{
	bin.w4(1);
	if (tpl.type() != Json::ValueType::objectValue ||
	    !tpl.isMember("rowdata")) {
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

std::string abkt_tojson(std::string_view bin, cpid_t codepage)
{
	EXT_PULL reader;
	reader.init(bin.data(), bin.size(), malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	Json::Value jval;
	auto ret = abkt_read(reader, jval, codepage);
	if (ret != pack_result::success)
		throw std::runtime_error("parsing ended with error " +
		      std::to_string(static_cast<int>(ret)) + " at pos " +
		      std::to_string(reader.m_offset));
	return Json::writeString(Json::StreamWriterBuilder(), std::move(jval));
}

std::string abkt_tobinary(std::string_view json, cpid_t codepage, bool dogap)
{
	Json::Value jval;
	if (!json_from_str(std::move(json), jval))
		throw lb_reader::invalid();
	lb_writer writer;
	abkt_write(jval, writer, codepage, dogap);
	return std::move(writer.m_data);
}

}

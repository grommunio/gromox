// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <libolecf.h>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>
#include <fmt/core.h>
#include <libHX/endian.h>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/defs.h>
#include <gromox/element_data.hpp>
#include <gromox/ext_buffer.hpp>
#include <gromox/paths.h>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>
#include "genimport.hpp"
#include "staticnpmap.cpp"

using namespace gromox;
using namespace gi_dump;
using message_ptr = std::unique_ptr<MESSAGE_CONTENT, mc_delete>;

namespace {

/**
 * "proptag entry" - Same size as the structure on-disk, but in host-byte order.
 */
struct pte {
	proptag_t proptag;
	uint32_t flags;
	union {
		char data[8];
		uint16_t v_ui2;
		uint32_t v_ui4;
		uint64_t v_ui8;
		float v_flt;
		double v_dbl;
	};
};
static_assert(sizeof(pte) == 16);

struct olecf_error_del { void operator()(libolecf_error_t *x) const { libolecf_error_free(&x); } };
struct olecf_file_del { void operator()(libolecf_file_t *x) const { libolecf_file_free(&x, nullptr); } };
struct olecf_item_del { void operator()(libolecf_item_t *x) const { libolecf_item_free(&x, nullptr); } };
struct bin_del { void operator()(BINARY *x) const { rop_util_free_binary(x); } };

using oxm_error_ptr = std::unique_ptr<libolecf_error_t, olecf_error_del>;
using oxm_file_ptr  = std::unique_ptr<libolecf_file_t, olecf_file_del>;
using oxm_item_ptr  = std::unique_ptr<libolecf_item_t, olecf_item_del>;
using bin_ptr       = std::unique_ptr<BINARY, bin_del>;

}

static unsigned int g_attach_decap, g_mlog_level = MLOG_DEFAULT_LEVEL;

static constexpr HXoption g_options_table[] = {
	{nullptr, 'p', HXTYPE_NONE | HXOPT_INC, &g_show_props, nullptr, nullptr, 0, "Show properties in detail (if -t)"},
	{nullptr, 't', HXTYPE_NONE, &g_show_tree, nullptr, nullptr, 0, "Show tree-based analysis of the archive"},
	{"decap", 0, HXTYPE_UINT, &g_attach_decap, {}, {}, {}, "Decapsulate embedded message (1-based index)", "IDX"},
	{"loglevel", 0, HXTYPE_UINT, &g_mlog_level, {}, {}, {}, "Basic loglevel of the program", "N"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static constexpr char
	S_PROPFILE[]   = "__properties_version1.0",
	S_NP_BASE[]    = "__nameid_version1.0",
	S_NP_GUIDS[]   = "__substg1.0_00020102",
	S_NP_ENTRIES[] = "__substg1.0_00030102",
	S_NP_STRINGS[] = "__substg1.0_00040102";

static errno_t do_message(libolecf_item_t *, MESSAGE_CONTENT &, mapi_object_type);

static YError az_error(const char *prefix, const oxm_error_ptr &err)
{
	char buf[160];
	buf[0] = '\0';
	libolecf_error_sprint(err.get(), buf, std::size(buf));
	return YError(std::string(prefix) + ": " + buf);
}

static bin_ptr slurp_stream(libolecf_item_t *stream)
{
	oxm_error_ptr err;
	uint32_t strm_size = 0;

	if (libolecf_item_get_size(stream, &strm_size, &unique_tie(err)) < 1)
		throw az_error("PO-1009", err);
	bin_ptr buf(me_alloc<BINARY>());
	if (buf == nullptr)
		throw std::bad_alloc();
	buf->cb = strm_size;
	buf->pb = me_alloc<uint8_t>(strm_size);
	if (buf->cb > 0 && buf->pb == nullptr)
		throw std::bad_alloc();
	for (size_t ofs = 0; ofs < strm_size; ) {
		auto ret = libolecf_stream_read_buffer(stream, &buf->pb[ofs],
		           strm_size - ofs, &~unique_tie(err));
		if (ret < 0)
			throw az_error("PO-1010", err);
		else if (ret == 0)
			break;
		ofs += ret;
	}
	return buf;
}

static bin_ptr slurp_stream(libolecf_item_t *dir, const char *file)
{
	oxm_error_ptr err;
	oxm_item_ptr propstrm;

	if (libolecf_item_get_sub_item_by_utf8_path(dir,
	    reinterpret_cast<const uint8_t *>(file), strlen(file),
	    &unique_tie(propstrm), &unique_tie(err)) < 1)
		throw az_error("PO-1007", err);
	return slurp_stream(propstrm.get());
}

static pack_result read_pte(EXT_PULL &ep, struct pte &pte)
{
	if (ep.m_offset + 16 > ep.m_data_size)
		/*
		 * read_pte won't always read the entire 16 bytes, so perform a
		 * check now.
		 */
		return pack_result::format;
	auto ret = ep.g_uint32(&pte.proptag);
	if (ret != pack_result::ok)
		return ret;
	ret = ep.g_uint32(&pte.flags);
	if (ret != pack_result::ok)
		return ret;
	auto pos = ep.m_offset;
	switch (PROP_TYPE(pte.proptag)) {
	/*
	 * MS-OXMSG §2.1.2: Small fixed-size types are represented as immediates (and
	 * will stay the same way with our struct pte).
	 */
	case PT_SHORT: ret = ep.g_uint16(&pte.v_ui2); break;
	case PT_LONG: ret = ep.g_uint32(&pte.v_ui4); break;
	case PT_FLOAT: ret = ep.g_float(&pte.v_flt); break;
	case PT_DOUBLE:
	case PT_APPTIME: ret = ep.g_double(&pte.v_dbl); break;
	case PT_CURRENCY:
	case PT_SYSTIME:
	case PT_I8: ret = ep.g_uint64(&pte.v_ui8); break;
	case PT_BOOLEAN: ret = ep.g_uint32(&pte.v_ui4); break;
	/* For almost everything else, it indicates the size of the indirect block. */
	default: ret = ep.g_uint32(&pte.v_ui4); break;
	}
	if (ret == pack_result::ok)
		ep.m_offset = pos + 8;
	return ret;
}

/* PTE simple-value to property conversion */
static int ptesv_to_prop(const struct pte &pte, const char *cset,
    libolecf_item_t *dir, TPROPVAL_ARRAY &proplist)
{
	auto blob = slurp_stream(dir, fmt::format("__substg1.0_{:08X}", pte.proptag).c_str());
	switch (PROP_TYPE(pte.proptag)) {
	case PT_STRING8: {
		if (pte.v_ui4 != blob->cb + 1)
			return -EIO;
		auto s = iconvtext(blob->pc, blob->cb, cset, "UTF-8");
		return ece2nerrno(proplist.set(pte.proptag, s.data()));
	}
	case PT_UNICODE: {
		if (pte.v_ui4 != blob->cb + 2)
			return -EIO;
		auto s = iconvtext(blob->pc, blob->cb, "UTF-16", "UTF-8");
		if (errno != 0)
			return -errno;
		return ece2nerrno(proplist.set(pte.proptag, s.data()));
	}
	case PT_BINARY:
		return ece2nerrno(proplist.set(pte.proptag, blob.get()));
	case PT_CLSID:
		if (blob->cb < sizeof(GUID))
			return -EIO;
		return ece2nerrno(proplist.set(pte.proptag, blob->pv));
	case PT_OBJECT:
		if (pte.v_ui4 != 0xffffffff)
			throw YError(fmt::format("Unsupported PTE with proptag {:08x}", pte.proptag));
		return ece2nerrno(proplist.set(pte.proptag, blob.get()));
	default:
		if (pte.v_ui4 != blob->cb)
			return -EIO;
		throw YError(fmt::format("Unsupported proptag {:08x}", pte.proptag));
	}
	return 0;
}

/* PTE multi-value [array of X, X!=string] to property conversion */
static int ptemv_to_prop(const struct pte &pte, const char *cset,
    libolecf_item_t *dir, TPROPVAL_ARRAY &proplist)
{
	uint8_t unitsize;
	switch (PROP_TYPE(pte.proptag)) {
	case PT_MV_SHORT: unitsize = 2; break;
	case PT_MV_LONG:
	case PT_MV_FLOAT: unitsize = 4; break;
	case PT_MV_APPTIME:
	case PT_MV_DOUBLE:
	case PT_MV_CURRENCY:
	case PT_MV_SYSTIME:
	case PT_MV_I8: unitsize = 8; break;
	case PT_MV_CLSID: unitsize = 16; break;
	case PT_MV_BINARY: unitsize = 0; break;
	default: throw YError(fmt::format("PO-1008: ptemv_to_prop does not implement proptag {:08x}", pte.proptag));
	}
	auto file = fmt::format("__substg1.0_{:08X}", pte.proptag);
	auto blob = slurp_stream(dir, file.c_str());
	if (blob == nullptr) {
		fprintf(stderr, "Storage object \"%s\" not found in file. Ask a developer to use olecfexport for further analysis.\n", file.c_str());
		return -EIO;
	}
	if (unitsize != 0) {
		GEN_ARRAY mv{pte.v_ui4 / unitsize, {blob->pv}};
		return ece2nerrno(proplist.set(pte.proptag, &mv));
	}
	if (pte.v_ui4 != blob->cb)
		return -EIO;
	std::vector<bin_ptr> bdata(pte.v_ui4 / 8);
	std::vector<BINARY> bvec(bdata.size());
	for (uint32_t i = 0; i < bvec.size(); ++i) {
		file = fmt::format("__substg1.0_{:08X}-{:08X}", pte.proptag, i);
		bdata[i] = slurp_stream(dir, file.c_str());
		if (bdata[i] == nullptr) {
			fprintf(stderr, "Storage object \"%s\" not found in file. Ask a developer to use olecfexport for further analysis.\n", file.c_str());
			return -EIO;
		}
		bvec[i] = *bdata[i];
	}
	GEN_ARRAY mv{static_cast<uint32_t>(bvec.size()), {bvec.data()}};
	return ece2nerrno(proplist.set(pte.proptag, &mv));
}

/* PTE multi-value string [array of strings] to property conversion */
static int ptemvs_to_prop(const struct pte &pte, const char *cset,
    libolecf_item_t *dir, TPROPVAL_ARRAY &proplist)
{
	std::vector<std::string> strs;
	std::vector<char *> strp;
	STRING_ARRAY sa;
	sa.count = pte.v_ui4 / 4;
	strs.resize(sa.count);
	strp.resize(sa.count);

	for (uint32_t i = 0; i < sa.count; ++i) {
		auto file = fmt::format("__substg1.0_{:08X}-{:08X}", pte.proptag, i);
		oxm_error_ptr err;
		oxm_item_ptr strm;
		uint32_t strm_size = 0;

		if (libolecf_item_get_sub_item_by_utf8_path(dir,
		    reinterpret_cast<const uint8_t *>(file.c_str()),
		    file.size(), &unique_tie(strm), &unique_tie(err)) < 1)
			throw az_error("PO-1014", err);
		if (libolecf_item_get_size(strm.get(), &strm_size,
		    &~unique_tie(err)) < 1)
			throw az_error("PO-1015", err);

		std::string rdbuf;
		rdbuf.resize(strm_size);
		auto ret = libolecf_stream_read_buffer(strm.get(),
		           reinterpret_cast<uint8_t *>(rdbuf.data()), strm_size,
		           &~unique_tie(err));
		if (ret < 0)
			throw az_error("PO-1016", err);
		else if (static_cast<unsigned int>(ret) != strm_size)
			throw YError("PO-1017");

		if (PROP_TYPE(pte.proptag) == PT_MV_STRING8)
			rdbuf = iconvtext(rdbuf.c_str(), strm_size, cset, "UTF-8");
		else
			rdbuf = iconvtext(rdbuf.c_str(), strm_size, "UTF-16", "UTF-8");
		if (errno != 0)
			return -errno;
		strs[i] = std::move(rdbuf);
	}
	for (uint32_t i = 0; i < sa.count; ++i)
		strp[i] = strs[i].data();
	sa.ppstr = strp.data();
	return ece2nerrno(proplist.set(pte.proptag, &sa));
}

static int pte_to_prop(const struct pte &pte, const char *cset,
    libolecf_item_t *dir, TPROPVAL_ARRAY &proplist)
{
	switch (PROP_TYPE(pte.proptag)) {
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_APPTIME:
	case PT_CURRENCY:
	case PT_SYSTIME:
	case PT_I8:
		/* Because of the union, the pointer for v_ui2, v_ui4, v_ui8 is the same. */
		return ece2nerrno(proplist.set(pte.proptag, &pte.v_ui8));
	case PT_BOOLEAN: {
		BOOL w = !!pte.v_ui4;
		return ece2nerrno(proplist.set(pte.proptag, &w));
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		return ptemvs_to_prop(pte, cset, dir, proplist);
	}
	if (pte.proptag & MV_FLAG)
		return ptemv_to_prop(pte, cset, dir, proplist);
	return ptesv_to_prop(pte, cset, dir, proplist);
}

static errno_t parse_propstrm(EXT_PULL &ep, const char *cset,
    libolecf_item_t *dir, TPROPVAL_ARRAY &proplist)
{
	while (ep.m_offset < ep.m_data_size) {
		struct pte pte;
		auto st = read_pte(ep, pte);
		if (st != pack_result::ok)
			return -EIO;
		auto ret = pte_to_prop(pte, cset, dir, proplist);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int parse_propstrm_to_cpid(const EXT_PULL &ep1)
{
	auto ep = ep1;
	while (ep.m_offset < ep.m_data_size) {
		struct pte pte;
		auto ret = read_pte(ep, pte);
		if (ret != pack_result::ok)
			return -EIO;
		if (pte.proptag == PR_MESSAGE_CODEPAGE)
			return pte.v_ui4;
	}
	return 0;
}

static int do_recips(libolecf_item_t *msg_dir, unsigned int nrecips,
    const char *cset, tarray_set &rcpts)
{
	for (size_t i = 0; i < nrecips; ++i) {
		auto file = fmt::format("__recip_version1.0_#{:08X}", i);
		oxm_error_ptr err;
		oxm_item_ptr rcpt_dir;

		if (libolecf_item_get_sub_item_by_utf8_path(msg_dir,
		    reinterpret_cast<const uint8_t *>(file.c_str()), file.size(),
		    &unique_tie(rcpt_dir), &unique_tie(err)) < 1)
			throw az_error("PO-1020", err);
		auto propstrm = slurp_stream(rcpt_dir.get(), S_PROPFILE);
		EXT_PULL ep;
		ep.init(propstrm->pv, propstrm->cb, malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
		if (ep.advance(8) != pack_result::ok)
			return EIO;
		tpropval_array_ptr props(tpropval_array_init());
		if (props == nullptr)
			throw std::bad_alloc();
		auto ret = parse_propstrm(ep, cset, rcpt_dir.get(), *props);
		if (ret < 0)
			return -ret;
		if (rcpts.append_move(std::move(props)) == ENOMEM)
			throw std::bad_alloc();
	}
	return 0;
}

static int do_attachs(libolecf_item_t *msg_dir, unsigned int natx,
    const char *cset, ATTACHMENT_LIST &atxlist)
{
	for (size_t i = 0; i < natx; ++i) {
		auto file = fmt::format("__attach_version1.0_#{:08X}", i);
		oxm_error_ptr err;
		oxm_item_ptr atx_dir;

		if (libolecf_item_get_sub_item_by_utf8_path(msg_dir,
		    reinterpret_cast<const uint8_t *>(file.c_str()), file.size(),
		    &unique_tie(atx_dir), &unique_tie(err)) < 1)
			throw az_error("PO-1020", err);
		auto propstrm = slurp_stream(atx_dir.get(), S_PROPFILE);
		EXT_PULL ep;
		ep.init(propstrm->pv, propstrm->cb, malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
		if (ep.advance(8) != pack_result::ok)
			return EIO;
		tpropval_array_ptr props(tpropval_array_init());
		if (props == nullptr)
			throw std::bad_alloc();
		auto ret = parse_propstrm(ep, cset, atx_dir.get(), *props);
		if (ret < 0)
			return -ret;
		attachment_content_ptr atc(attachment_content_init());
		std::swap(atc->proplist.count, props->count);
		std::swap(atc->proplist.ppropval, props->ppropval);
		if (atc->proplist.has(PR_ATTACH_DATA_OBJ)) {
			atc->proplist.erase(PR_ATTACH_DATA_OBJ);
			file = "__substg1.0_3701000D";
			oxm_item_ptr msg_item;
			if (libolecf_item_get_sub_item_by_utf8_path(atx_dir.get(),
			    reinterpret_cast<const uint8_t *>(file.c_str()), file.size(),
			    &unique_tie(msg_item), &unique_tie(err)) < 1)
				throw az_error("PO-1021", err);
			std::unique_ptr<message_content, mc_delete> ctnt(message_content_init());
			if (ctnt == nullptr)
				throw std::bad_alloc();
			ctnt->children.pattachments = attachment_list_init();
			if (ctnt->children.pattachments == nullptr)
				throw std::bad_alloc();
			ctnt->children.prcpts = tarray_set_init();
			if (ctnt->children.prcpts == nullptr)
				throw std::bad_alloc();
			ret = do_message(msg_item.get(), *ctnt, MAPI_MESSAGE);
			if (ret != 0)
				return ret;
			atc->pembedded = ctnt.release();
		}
		if (!atxlist.append_internal(atc.get()))
			throw std::bad_alloc();
		atc.release();
	}
	return 0;
}

static errno_t do_message(libolecf_item_t *msg_dir, MESSAGE_CONTENT &ctnt, mapi_object_type parent_type)
{
	/* MS-OXMSG v16 §2.4 */
	auto propstrm = slurp_stream(msg_dir, S_PROPFILE);
	EXT_PULL ep;
	ep.init(propstrm->pv, propstrm->cb, malloc, EXT_FLAG_UTF16 | EXT_FLAG_WCOUNT);
	if (ep.advance(16) != pack_result::ok)
		return EIO;
	uint32_t recip_count = 0, atx_count = 0;
	if (ep.g_uint32(&recip_count) != pack_result::ok)
		return EIO;
	if (ep.g_uint32(&atx_count) != pack_result::ok)
		return EIO;
	if (parent_type == MAPI_FOLDER && ep.advance(8) != pack_result::ok)
		return EIO;
	auto cpid = parse_propstrm_to_cpid(ep);
	if (cpid < 0)
		return EIO;
	auto cset = cpid_to_cset(static_cast<cpid_t>(cpid));
	if (cset == nullptr)
		cset = "ascii";
	auto ret = parse_propstrm(ep, cset, msg_dir, ctnt.proplist);
	if (ret < 0)
		return -ret;
	ret = do_recips(msg_dir, recip_count, cset, *ctnt.children.prcpts);
	if (ret < 0)
		return -ret;
	ret = do_attachs(msg_dir, atx_count, cset, *ctnt.children.pattachments);
	if (ret < 0)
		return -ret;
	return 0;
}

static int npg_read(libolecf_item_t *root)
{
	oxm_error_ptr err;
	oxm_item_ptr nvdir;

	auto ret = libolecf_item_get_sub_item_by_utf8_path(root,
	           reinterpret_cast<const uint8_t *>(S_NP_BASE),
	           strlen(S_NP_BASE), &unique_tie(nvdir),
	           &unique_tie(err));
	if (ret < 0)
		return -EIO;
	else if (ret == 0)
		return 0;

	auto guidpool = slurp_stream(nvdir.get(), S_NP_GUIDS);
	auto tblpool = slurp_stream(nvdir.get(), S_NP_ENTRIES);
	auto strpool = slurp_stream(nvdir.get(), S_NP_STRINGS);
	EXT_PULL ep;
	ep.init(tblpool->pv, tblpool->cb, malloc, 0);
	for (uint16_t current_np = 0; ep.m_offset < ep.m_data_size; ++current_np) {
		uint32_t niso = 0, iki = 0;
		if (ep.g_uint32(&niso) != pack_result::success ||
		    ep.g_uint32(&iki) != pack_result::success)
			return -EIO;
		uint16_t propidx = (iki >> 16) & 0xFFFF;
		uint16_t guididx = (iki >> 1) & 0x7FF;
		PROPERTY_XNAME pn_req;
		pn_req.kind = (iki & 0x1) ? MNID_STRING : MNID_ID;
		if (pn_req.kind == MNID_ID) {
			pn_req.lid = niso;
		} else {
			EXT_PULL sp;
			uint32_t len = 0;
			sp.init(strpool->pv, strpool->cb, malloc, 0);
			if (sp.advance(niso) != pack_result::ok)
				return -EIO;
			if (sp.g_uint32(&len) != pack_result::ok)
				return -EIO;
			if (len > 510)
				len = 510;
			std::string wbuf;
			wbuf.resize(len);
			if (sp.g_bytes(wbuf.data(), len) != pack_result::ok)
				return -EIO;
			pn_req.name = iconvtext(wbuf.data(), len, "UTF-16", "UTF-8");
			if (errno != 0)
				return -errno;
		}
		if (guididx == 1) {
			pn_req.guid = PS_MAPI;
		} else if (guididx == 2) {
			pn_req.guid = PS_PUBLIC_STRINGS;
		} else if (guididx >= 3) {
			uint32_t ofs = (guididx - 3) * sizeof(GUID);
			if (guidpool->cb < ofs + sizeof(GUID))
				return -EIO;
			EXT_PULL gp;
			gp.init(&guidpool->pb[ofs], sizeof(GUID), malloc, 0);
			if (gp.g_guid(&pn_req.guid) != pack_result::ok)
				return -EIO;
		}
		if (propidx != current_np) {
			fprintf(stderr, "[NP propidx mismatch %04xh != %04xh\n", propidx, current_np);
			return -EIO;
		}
		static_namedprop_map.emplace(0, std::move(pn_req));
	}
	return 0;
}

static errno_t do_file(const char *filename) try
{
	oxm_error_ptr err;
	oxm_file_ptr file;
	if (libolecf_file_initialize(&unique_tie(file), &unique_tie(err)) < 1) {
		fprintf(stderr, "%s\n", az_error("PO-1004", err).what());
		return EIO;
	}
	fprintf(stderr, "oxm2mt: Reading %s...\n", filename);
	errno = 0;
	if (libolecf_file_open(file.get(), filename,
	    LIBOLECF_OPEN_READ, &unique_tie(err)) < 1) {
		if (errno != 0)
			fprintf(stderr, "cfb: Could not open \"%s\": %s\n",
			        filename, strerror(errno));
		else
			fprintf(stderr, "cfb: \"%s\" not recognized as CFBF (CDFV2)\n", filename);
		return ECANCELED;
	}
	oxm_item_ptr root;
	if (libolecf_file_get_root_item(file.get(), &unique_tie(root),
	    &~unique_tie(err)) < 1)
		throw az_error("PO-1001", err);
	std::unique_ptr<MESSAGE_CONTENT, mc_delete> ctnt(message_content_init());
	if (ctnt == nullptr)
		throw std::bad_alloc();
	ctnt->children.pattachments = attachment_list_init();
	if (ctnt->children.pattachments == nullptr)
		throw std::bad_alloc();
	ctnt->children.prcpts = tarray_set_init();
	if (ctnt->children.prcpts == nullptr)
		throw std::bad_alloc();
	auto ret = do_message(root.get(), *ctnt, MAPI_FOLDER);
	if (ret != 0)
		return ret;
	if (g_attach_decap > 0) {
		ret = gi_decapsulate_attachment(ctnt, g_attach_decap - 1);
		if (ret == ENOENT)
			fprintf(stderr, "Attachment #%u is not an embedded message\n", g_attach_decap);
		if (ret != 0)
			return ret;
	}

	if (HXio_fullwrite(STDOUT_FILENO, "GXMT0004", 8) < 0)
		throw YError("PG-1014: %s", strerror(errno));
	uint8_t flag = false;
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* splice flag */
		throw YError("PG-1015: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, &flag, sizeof(flag)) < 0) /* public store flag */
		throw YError("PG-1016: %s", strerror(errno));
	gi_folder_map_write({});

	ret = npg_read(root.get());
	if (ret < 0) {
		fprintf(stderr, "Error reading nameids\n");
		return EXIT_FAILURE;
	}
	gi_dump_name_map(static_namedprop_map.fwd);
	gi_name_map_write(static_namedprop_map.fwd);

	auto parent = parent_desc::as_folder(MAILBOX_FID_UNANCHORED);
	if (g_show_tree)
		gi_print(0, *ctnt, ee_get_propname);
	EXT_PUSH ep;
	if (!ep.init(nullptr, 0, EXT_FLAG_WCOUNT)) {
		fprintf(stderr, "E-2012: ENOMEM\n");
		return EXIT_FAILURE;
	}
	if (ep.p_uint32(static_cast<uint32_t>(MAPI_MESSAGE)) != pack_result::ok ||
	    ep.p_uint32(1) != pack_result::ok ||
	    ep.p_uint32(static_cast<uint32_t>(parent.type)) != pack_result::ok ||
	    ep.p_uint64(parent.folder_id) != pack_result::ok ||
	    ep.p_msgctnt(*ctnt) != pack_result::ok ||
	    ep.p_str("") != pack_result::ok ||
	    ep.p_str("") != pack_result::ok) {
		fprintf(stderr, "E-2006\n");
		return EXIT_FAILURE;
	}
	uint64_t xsize = cpu_to_le64(ep.m_offset);
	if (HXio_fullwrite(STDOUT_FILENO, &xsize, sizeof(xsize)) < 0)
		throw YError("PG-1017: %s", strerror(errno));
	if (HXio_fullwrite(STDOUT_FILENO, ep.m_vdata, ep.m_offset) < 0)
		throw YError("PG-1018: %s", strerror(errno));
	return 0;
} catch (const char *e) {
	fprintf(stderr, "oxm: Exception: %s\n", e);
	return ECANCELED;
} catch (const std::string &e) {
	fprintf(stderr, "oxm: Exception: %s\n", e.c_str());
	return ECANCELED;
} catch (const std::exception &e) {
	fprintf(stderr, "oxm: Exception: %s\n", e.what());
	return ECANCELED;
}

static void terse_help()
{
	fprintf(stderr, "Usage: gromox-oxm2mt input.msg | gromox-mt2.... \n");
	fprintf(stderr, "Option overview: gromox-oxm2mt -?\n");
	fprintf(stderr, "Documentation: man gromox-oxm2mt\n");
}

int main(int argc, char **argv)
{
	HXopt6_auto_result argp;
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_ARGS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (argp.nargs != 1) {
		terse_help();
		return EXIT_FAILURE;
	}
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to output the binary Mailbox Transfer Data Stream to a terminal.\n"
			"You probably wanted to redirect output into a file or pipe.\n");
		return EXIT_FAILURE;
	}
	mlog_init(nullptr, nullptr, g_mlog_level, nullptr);
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);

	auto ret = do_file(argp.uarg[0]);
	if (ret != 0) {
		fprintf(stderr, "oxm2mt: Import unsuccessful.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

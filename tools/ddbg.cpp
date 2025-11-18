// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024–2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <string_view>
#include <libHX/io.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <gromox/element_data.hpp>
#include <gromox/lzxpress.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/paths.h>
#include <gromox/rop_util.hpp>
#include <gromox/textmaps.hpp>
#include <gromox/tie.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using LLD = long long;
using LLU = unsigned long long;

enum {
	CM_NONE, CM_DEC_ACTION, CM_DEC_ANYTHING, CM_DEC_ENTRYID, CM_DEC_GUID,
	CM_DEC_NTTIME, CM_DEC_RESTRICT, CM_DEC_UNIXTIME,
	CM_LZXDEC, CM_LZXENC, CM_HTMLTORTF,
	CM_HTMLTOTEXT, CM_RTFCP, CM_RTFTOHTML, CM_TEXTTOHTML, CM_UNRTFCP,
};
static unsigned int g_dowhat, g_hex2bin;
static constexpr struct HXoption g_options_table[] = {
	{"decode", 'd', HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_ANYTHING, "Try all decoders"},
	{"decode-action", 'A', HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_ACTION, "Decode rule action blob"},
	{"decode-entryid", 'e', HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_ENTRYID, "Decode entryid"},
	{"decode-guid", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_GUID, "Decode GUID"},
	{"decode-nttime", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_NTTIME, "Decode NT timestamps to unixtime/calendar"},
	{"decode-restrict", 'r', HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_RESTRICT, "Decode restriction blob (e.g. rule condition)"},
	{"decode-unixtime", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_DEC_UNIXTIME, "Decode Unix timestamp to nttime/calendar"},
	{"htmltortf", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_HTMLTORTF, "Convert HTML to RTF"},
	{"htmltotext", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_HTMLTOTEXT, "Convert HTML to plaintext"},
	{"lzxdec", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_LZXDEC, "LZX decompression"},
	{"lzxenc", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_LZXENC, "LZX compression"},
	{"pack", 'p', HXTYPE_NONE, &g_hex2bin, {}, {}, 0, "Employ hex2bin before main action"},
	{"rtfcp", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_RTFCP, "Convert RTF to uncompressed RTFCP"},
	{"unrtfcp", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_UNRTFCP, "Decompress RTFCP (all forms) to RTF"},
	{"rtftohtml", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_RTFTOHTML, "Convert RTF to HTML"},
	{"texttohtml", 0, HXTYPE_VAL, &g_dowhat, {}, {}, CM_TEXTTOHTML, "Convert plaintext to HTML"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

static void try_entryid(const std::string_view s, unsigned int ind = 0);

static unsigned int lead(unsigned int level)
{
	return 4 * level;
}

static void print_guid(const FLATUID le)
{
	GUID he = le;
	char txt[39];
	he.to_str(txt, std::size(txt), 38);
	printf("%s", txt);
	auto name = guid2name(le);
	if (!name.empty())
		printf(" <<%s>>", name.c_str());
}

static void try_guid(const std::string_view s, unsigned int ind = 0)
{
	if (s.size() == sizeof(FLATUID))
		print_guid(*reinterpret_cast<const FLATUID *>(s.data()));
}

static void try_emsab(const std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT);
	EMSAB_ENTRYID eid;
	if (ep.g_abk_eid(&eid) != pack_result::success)
		return;
	printf("%-*sEX address entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags   = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*stype    = 0x%08x\n", lead(ind), "", eid.type);
	printf("%-*sx500dn  = %s\n", lead(ind), "", eid.x500dn.c_str());
}

static void try_contab(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT);

	uint32_t flags, version, type;
	GUID muid;
	if (ep.g_uint32(&flags) != pack_result::ok ||
	    ep.advance(16) != pack_result::ok ||
	    ep.g_uint32(&version) != pack_result::ok ||
	    ep.g_uint32(&type) != pack_result::ok ||
	    ep.g_guid(&muid) != pack_result::ok)
		return;

	printf("%-*sContact Address Book entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags   = 0x%08x\n", lead(ind), "", flags);
	printf("%-*stype    = 0x%08x\n", lead(ind), "", type);
	printf("%-*smuid    = ", lead(ind), "");
	print_guid(muid);
	printf("\n");
	printf("%-*sEntryid = \n", lead(ind), "");
	s.remove_prefix(ep.m_offset);
	try_entryid(s, ind + 1);
}

static void try_storewrap(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	STORE_ENTRYID eid;
	if (ep.g_store_eid(&eid) != pack_result::success)
		return;
	auto cl_0 = HX::make_scope_exit([&]() {
		free(eid.pserver_name);
		free(eid.pmailbox_dn);
	});
	printf("%-*sMAPI Message Store Entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags   = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*sversion = 0x%02x\n", lead(ind), "", eid.version);
	printf("%-*sivflag  = 0x%02x\n", lead(ind), "", eid.ivflag);
	printf("%-*swflags  = 0x%08x\n", lead(ind), "", eid.wrapped_flags);
	printf("%-*swuid    = ", lead(ind), "");
	print_guid(eid.wrapped_provider_uid);
	printf("\n%-*swtype   = 0x%08x <<", lead(ind), "", eid.wrapped_type);
#define E(f) if (eid.wrapped_type & (f)) printf(" " #f);
	E(OPENSTORE_USE_ADMIN_PRIVILEGE);
	E(OPENSTORE_PUBLIC);
	E(OPENSTORE_HOME_LOGON);
	E(OPENSTORE_TAKE_OWNERSHIP);
	E(OPENSTORE_OVERRIDE_HOME_MDB);
	E(OPENSTORE_TRANSPORT);
	E(OPENSTORE_REMOTE_TRANSPORT);
	E(OPENSTORE_INTERNET_ANONYMOUS);
	E(OPENSTORE_ALTERNATE_SERVER);
	E(OPENSTORE_IGNORE_HOME_MDB);
	E(OPENSTORE_NO_MAIL);
	E(OPENSTORE_OVERRIDE_LAST_MODIFIER);
	E(OPENSTORE_CALLBACK_LOGON);
	E(OPENSTORE_LOCAL);
	E(OPENSTORE_FAIL_IF_NO_MAILBOX);
	E(OPENSTORE_CACHE_EXCHANGE);
	E(OPENSTORE_CLI_WITH_NAMEDPROP_FIX);
	E(OPENSTORE_ENABLE_LAZY_LOGGING);
	E(OPENSTORE_CLI_WITH_REPLID_GUID_MAPPING_FIX);
	E(OPENSTORE_NO_LOCALIZATION);
	E(OPENSTORE_RESTORE_DATABASE);
	E(OPENSTORE_XFOREST_MOVE);
#undef E
	printf(">>\n%-*sserver  = %s\n", lead(ind), "", znul(eid.pserver_name));
	printf("%-*sdn      = %s\n", lead(ind), "", znul(eid.pmailbox_dn));
	s.remove_prefix(ep.m_offset);
	if (s.size() < 16)
		return;
	static constexpr uint32_t MDB_STORE_EID_V3_MAGIC = 0xf43246e9;
	uint32_t v, size;
	char *smtp = nullptr;
	auto cl_1 = HX::make_scope_exit([&]() { free(smtp); });
	if (ep.g_uint32(&v) != pack_result::ok || v != MDB_STORE_EID_V3_MAGIC ||
	    ep.g_uint32(&size) != pack_result::ok ||
	    ep.g_uint32(&v) != pack_result::ok || v != 2 ||
	    ep.g_uint32(&v) != pack_result::ok ||
	    ep.g_wstr(&smtp) != pack_result::ok)
		return;
	printf("%-*sMDB_STORE_EID_V3_MAGIC\n%-*ssmtp    = %s\n", lead(ind), "", lead(ind), "", znul(smtp));
}

static void try_shared_cal1(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	uint32_t vd, dnbytes, smtpbytes;
	GUID w;
	std::string str;

	if (ep.g_uint32(&vd) != pack_result::ok ||
	    ep.g_guid(&w) != pack_result::ok ||
	    ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sCalendar index         = #%u\n", lead(ind), "", vd);
	// 0x38 is the size from w to Inner EID
	if (ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sHeader size(?)         = 0x%xh // expected 0x38\n", lead(ind), "",  vd);
	if (ep.g_uint32(&dnbytes) != pack_result::ok)
		return;
	printf("%-*sDisplayName field size = %u bytes\n", lead(ind), "",  dnbytes);
	if (ep.g_uint32(&smtpbytes) != pack_result::ok)
		return;
	printf("%-*sSMTP field size        = %u bytes\n", lead(ind), "",  smtpbytes);
	if (ep.g_guid(&w) != pack_result::ok)
		return;
	printf("%-*sInner provider UID     = ", lead(ind), ""); print_guid(w); printf("\n");
	if (ep.g_guid(&w) != pack_result::ok)
		return;
	printf("%-*s(something)            = ", lead(ind), ""); print_guid(w); printf("\n");
	printf("%-*s                         // ↑ random with EXC2019, somewhat orderly with Gromox\n", lead(ind), "");
	if (ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sInner EID size         = %u bytes\n", lead(ind), "",  vd);
	{
		std::string_view sub = s;
		sub.remove_prefix(ep.m_offset);
		if (sub.size() > vd)
			sub = {sub.data(), vd};
		try_entryid(sub, ind + 1);
	}
	if (ep.advance(vd) != pack_result::ok)
		return;

	auto next_offset = ep.m_offset + dnbytes;
	if (ep.g_wstr(&str) != pack_result::ok)
		return;
	printf("%-*sDisplay name = %s\n", lead(ind), "", str.c_str());
	if (ep.m_offset < next_offset)
		printf("%-*s           + %zu unparsed/garbage bytes\n", lead(ind + 1), "",
			static_cast<size_t>(next_offset - ep.m_offset));
	ep.m_offset = next_offset;

	next_offset = ep.m_offset + smtpbytes;
	if (ep.g_wstr(&str) != pack_result::ok)
		return;
	printf("%-*sSMTP address = %s\n", lead(ind), "", str.c_str());
	if (ep.m_offset < next_offset)
		printf("%-*s           + %zu unparsed/garbage bytes\n", lead(ind + 1), "",
			static_cast<size_t>(next_offset - ep.m_offset));
	ep.m_offset = next_offset;
	if (ep.m_offset != ep.m_data_size)
		printf("%-*s+ %zu unparsed/garbage bytes\n", lead(ind), "",
			static_cast<size_t>(ep.m_data_size - ep.m_offset));
}

static void try_shared_cal2(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	uint32_t vd;
	GUID w;

	if (ep.g_uint32(&vd) != pack_result::ok ||
	    ep.g_guid(&w) != pack_result::ok ||
	    ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sField 1.1         = %08xh\n", lead(ind), "",  vd);
	if (ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sField 1.2         = %08xh\n", lead(ind), "",  vd);
	if (ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sType or something = %u\n", lead(ind), "",  vd);
	if (ep.g_uint32(&vd) != pack_result::ok)
		return;
	printf("%-*sInner EID size    = %u\n", lead(ind), "",  vd);
	{
		std::string_view sub = s;
		sub.remove_prefix(ep.m_offset);
		if (sub.size() > vd)
			sub = {sub.data(), vd};
		try_entryid(sub, ind + 1);
	}
	/* Always leaves room for a MESSAGE_ENTRYID even if not present. */
	if (vd < 70 && ep.advance(70) != pack_result::ok)
		return;
	if (ep.m_offset != ep.m_data_size)
		printf("%-*s+ %zu unparsed/garbage bytes\n", lead(ind), "",
			static_cast<size_t>(ep.m_data_size - ep.m_offset));
}

static const char *objecttypename(unsigned int i)
{
	switch (i) {
	case EITLT_PRIVATE_FOLDER:  return "eitLTPrivateFolder";
	case EITLT_PUBLIC_FOLDER:   return "eitLTPublicFolder";
	case EITLT_PRIVATE_MESSAGE: return "eitLTPrivateMessage";
	case EITLT_PUBLIC_MESSAGE:  return "eitLTPublicMessage";
	default:                    return "?";
	}
}

static void try_shortterm_eid(const std::string_view s, unsigned int ind)
{
	if (s.size() != 34 && s.size() != 42)
		return;

	EXT_PULL ep;
	ep.init(s.data(), s.size(), nullptr, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);

	uint64_t instid;
	uint32_t flags, q2;
	uint16_t folder_type;
	GUID provider;
	if (ep.g_uint32(&flags) != pack_result::ok)
		return;
	if (flags != (MAPI_SHORTTERM | MAPI_NOTRECIP | MAPI_THISSESSION | MAPI_NOTRESERVED | 0x0f))
		return;
	if (ep.g_guid(&provider) != pack_result::ok ||
	    ep.g_uint16(&folder_type) != pack_result::ok ||
	    ep.g_uint32(&q2) != pack_result::ok ||
	    ep.g_uint64(&instid) != pack_result::ok)
		return;

	printf("%-*sShortterm folder entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags  = 0x%08x\n", lead(ind), "", flags);
	printf("%-*stype   = 0x%02x <<%s>>\n", lead(ind), "", folder_type, objecttypename(folder_type));
	printf("%-*s?      = 0x%08x\n", lead(ind), "", q2);
	printf("%-*sinstid = 0x%llx\n", lead(ind), "", LLU{rop_util_get_gc_value(instid)});

	if (ep.g_uint64(&instid) == pack_result::ok)
		printf("%-*sinstid = 0x%llx\n", lead(ind), "", LLU{rop_util_get_gc_value(instid)});
}

static void try_folder_eid(const std::string_view s, unsigned int ind)
{
	if (s.size() != 46)
		return;
	EXT_PULL ep;
	FOLDER_ENTRYID eid;
	ep.init(s.data(), s.size(), nullptr, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	if (ep.g_folder_eid(&eid) != pack_result::ok)
		return;
	printf("%-*sEX folder entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags  = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*stype   = 0x%02x <<%s>>\n", lead(ind), "", eid.eid_type, objecttypename(eid.eid_type));
	printf("%-*sdbguid = ", lead(ind), "");
	print_guid(eid.folder_dbguid);
	printf("\n%-*sfidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.folder_gc)});
	printf("%-*sreplid = %u\n", lead(ind), "", (eid.pad1[0] << 8) | eid.pad1[1]);
}

static void try_message_eid(const std::string_view s, unsigned int ind)
{
	if (s.size() != 70)
		return;
	EXT_PULL ep;
	MESSAGE_ENTRYID eid;
	ep.init(s.data(), s.size(), nullptr, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	if (ep.g_msg_eid(&eid) != pack_result::ok)
		return;
	printf("%-*sEX message entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags  = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*stype   = 0x%04x\n", lead(ind), "", eid.eid_type);
	printf("%-*sfdguid = ", lead(ind), "");
	print_guid(eid.folder_dbguid);
	printf("\n%-*sfidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.folder_gc)});
	printf("%-*sreplid = 0x%x\n", lead(ind), "", (eid.pad1[0] << 8) | eid.pad1[1]);
	printf("%-*smdguid = ", lead(ind), "");
	print_guid(eid.message_dbguid);
	printf("\n%-*smidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.message_gc)});
	printf("%-*sreplid = 0x%x\n", lead(ind), "", (eid.pad2[0] << 8) | eid.pad2[1]);
}

static void try_object_eid(const std::string_view s, unsigned int ind)
{
	try_shortterm_eid(s, ind);
	try_folder_eid(s, ind);
	try_message_eid(s, ind);
}

static void try_entryid(const std::string_view s, unsigned int ind)
{
	if (s.size() < 4)
		return;
	printf("%-*sEntryid flags:", lead(ind), "");
	if (s[0] & MAPI_SHORTTERM)   printf(" MAPI_SHORTTERM");
	if (s[0] & MAPI_NOTRECIP)    printf(" MAPI_NOTRECIP");
	if (s[0] & MAPI_THISSESSION) printf(" MAPI_THISSESSION");
	if (s[0] & MAPI_NOW)         printf(" MAPI_NOW");
	if (s[0] & MAPI_NOTRESERVED) printf(" MAPI_NOTRESERVED");
	if (s[1] & MAPI_COMPOUND)    printf(" MAPI_COMPOUND");
	printf("\n");
	if (s.size() < 20)
		return;
	printf("%-*sProvider UID: ", lead(ind), "");
	FLATUID le;
	memcpy(le.ab, &s[4], sizeof(le));
	print_guid(le);
	printf("\n");
	if (le == muidEMSAB)
		try_emsab(s, ind);
	else if (le == muidContabDLL)
		try_contab(s, ind);
	else if (le == muidStoreWrap)
		try_storewrap(s, ind);
	else if (le == shared_calendar_store_guid)
		try_shared_cal1(s, ind);
	else if (le == shared_calendar_provider_guid)
		try_shared_cal2(s, ind);
	else
		try_object_eid(s, ind);
}

static int print_action(std::string_view data)
{
	RULE_ACTIONS ra{};
	EXT_PULL ep;
	ep.init(data.data(), data.size(), zalloc, 0);
	if (ep.g_rule_actions(&ra) != pack_result::ok)
		return -1;
	printf("%s\n", ra.repr().c_str());
	return 0;
}

static int print_restrict(std::string_view data)
{
	RESTRICTION rs{};
	EXT_PULL ep;
	ep.init(data.data(), data.size(), zalloc, 0);
	if (ep.g_restriction(&rs) != pack_result::ok)
		return -1;
	printf("%s\n", rs.repr().c_str());
	return 0;
}

static void print_nttime(const char *str)
{
	auto nt = strtoll(str, nullptr, 0);
	auto ut = rop_util_nttime_to_unix(nt);
	printf("%lld ... is unixtime %lld\n", LLD{nt}, LLD{ut});
	char buf[64];
	auto tm = localtime(&ut);
	strftime(buf, std::size(buf), "%FT%T", tm);
	printf("%lld ... is calendar %s\n", LLD{nt}, buf);
}

static void print_unixtime(const char *str)
{
	time_t ut = strtoll(str, nullptr, 0);
	auto nt = rop_util_unix_to_nttime(ut);
	printf("%lld ... is nttime %lld\n", LLD{ut}, LLU{nt});
	char buf[64];
	auto tm = localtime(&ut);
	strftime(buf, std::size(buf), "%FT%T", tm);
	printf("%lld ... is calendar %s\n", LLD{ut}, buf);
}

static int do_lzx(std::string_view data, bool enc)
{
	/*
	 * The API of that lzxpress implementation does not expose streamed
	 * decompression; it's just one-shot. Just allocate a huge chunk and
	 * hope.
	 */
	size_t osize = data.size() * 10;
	auto outbuf = std::make_unique<char[]>(osize);
	auto ret = enc ? lzxpress_compress(data.data(), data.size(), outbuf.get(), osize) :
	           lzxpress_decompress(data.data(), data.size(), outbuf.get(), osize);
	if (ret < 0) {
		fprintf(stderr, "Something went wrong\n");
		return -1;
	} else if (HXio_fullwrite(STDOUT_FILENO, outbuf.get(), ret) < 0) {
		perror("write");
		return -1;
	}
	return 0;
}

static int do_process_2(std::string_view &&data, const char *str)
{
	switch (g_dowhat) {
	case CM_DEC_ANYTHING: {
		try_entryid(data);
		try_guid(data);
		return 0;
	}
	case CM_DEC_ACTION:
		return print_action(data);
	case CM_DEC_ENTRYID: {
		try_entryid(data, 0);
		return 0;
	}
	case CM_DEC_GUID: {
		try_guid(data, 0);
		return 0;
	}
	case CM_DEC_NTTIME:
		print_nttime(str);
		return 0;
	case CM_DEC_RESTRICT:
		return print_restrict(data);
	case CM_DEC_UNIXTIME:
		print_unixtime(str);
		return 0;
	case CM_HTMLTORTF: {
		std::string out;
		auto err = html_to_rtf(data, CP_UTF8, out);
		if (err != ecSuccess) {
			fprintf(stderr, "html_to_rtf: %s", mapi_strerror(err));
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return -1;
		}
		return 0;
	}
	case CM_HTMLTOTEXT: {
		std::string out;
		if (html_to_plain(data, CP_OEMCP, out) < 0) {
			fprintf(stderr, "html_to_plain failed\n");
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return 01;
		}
		return 0;
	}
	case CM_LZXDEC:
		return do_lzx(data, 0);
	case CM_LZXENC:
		return do_lzx(data, 1);
	case CM_RTFCP: {
		std::string out;
		auto err = rtfcp_encode(data, out);
		if (err != ecSuccess) {
			fprintf(stderr, "rtfcp_compress: %s\n", mapi_strerror(err));
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return -1;
		}
		return 0;
	}
	case CM_RTFTOHTML: {
		auto at = attachment_list_init();
		std::string out;
		auto err = rtf_to_html(data, "utf-8", out, at);
		if (err != ecSuccess) {
			fprintf(stderr, "rtf_to_html: %s\n", mapi_strerror(err));
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return -1;
		}
		return 0;
	}
	case CM_TEXTTOHTML: {
		std::string out;
		auto err = plain_to_html(str, out);
		if (err != ecSuccess) {
			fprintf(stderr, "plain_to_html: %s\n", mapi_strerror(err));
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return -1;
		}
		return 0;
	}
	case CM_UNRTFCP: {
		auto unc_size = rtfcp_uncompressed_size(data);
		if (unc_size == -1) {
			fprintf(stderr, "Bad header magic, or data stream is shorter than the header says it should be.\n");
			return -1;
		} else if (unc_size == 0) {
			return 0;
		}
		std::string out;
		auto err = rtfcp_uncompress(data, out);
		if (err != ecSuccess) {
			fprintf(stderr, "rtfcp_uncompress: %s\n", mapi_strerror(err));
			return -1;
		} else if (HXio_fullwrite(STDOUT_FILENO, out.data(), out.size()) < 0) {
			perror("write");
			return -1;
		}
		return 0;
	}
	default:
		return -1;
	}
}

static int do_process_1(std::string_view &&data, const char *str)
{
	return do_process_2(g_hex2bin ? hex2bin(data, HEX2BIN_SKIP) : std::move(data), str);
}

int main(int argc, char **argv)
{
	HXopt6_auto_result argp;
	if (HX_getopt6(g_options_table, argc, argv, &argp,
	    HXOPT_USAGEONERR | HXOPT_ITER_ARGS) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;

	if (g_dowhat == CM_NONE) {
		fprintf(stderr, "No command selected\n");
		return EXIT_FAILURE;
	}
	if (iconv_validate() != 0)
		return EXIT_FAILURE;
	textmaps_init(PKGDATADIR);
	if (argp.nargs == 0) {
		size_t slurp_len = 0;
		std::unique_ptr<char[], stdlib_delete> slurp_data(HX_slurp_fd(STDIN_FILENO, &slurp_len));
		if (slurp_data == nullptr)
			return EXIT_FAILURE;
		return do_process_1(std::string_view(slurp_data.get(), slurp_len), slurp_data.get());
	}

	int combined_ret = EXIT_SUCCESS;
	for (int i = 0; i < argp.nargs; ++i) {
		int ret = do_process_1(argp.uarg[i], argp.uarg[i]);
		if (ret != 0)
			combined_ret = EXIT_FAILURE;
	}
	return combined_ret;
}

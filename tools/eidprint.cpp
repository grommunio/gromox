// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <string_view>
#include <libHX/scope.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using LLU = unsigned long long;

static void try_entryid(const std::string_view s, unsigned int ind);

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

static void try_guid(const std::string_view s, unsigned int ind)
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
	auto cl_0 = HX::make_scope_exit([&]() {
		free(eid.px500dn);
	});
	printf("%-*sEX address entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags   = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*stype    = 0x%08x\n", lead(ind), "", eid.type);
	printf("%-*sx500dn  = %s\n", lead(ind), "", znul(eid.px500dn));
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

static void try_shared_cal(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	uint32_t vd, dnbytes, smtpbytes;
	GUID w;
	std::string str;

	ep.g_uint32(&vd);
	ep.g_guid(&w);
	ep.g_uint32(&vd); printf("%-*sCalendar index         = #%u\n", lead(ind), "", vd);
	// 0x38 is the size from w to Inner EID
	ep.g_uint32(&vd); printf("%-*sHeader size(?)         = 0x%xh // expected 0x38\n", lead(ind), "",  vd);
	ep.g_uint32(&dnbytes);
	printf("%-*sDisplayName field size = %u bytes\n", lead(ind), "",  dnbytes);
	ep.g_uint32(&smtpbytes);
	printf("%-*sSMTP field size        = %u bytes\n", lead(ind), "",  smtpbytes);
	ep.g_guid(&w);
	printf("%-*sInner provider UID     = ", lead(ind), ""); print_guid(w); printf("\n");
	ep.g_guid(&w);
	printf("%-*s(something)            = ", lead(ind), ""); print_guid(w); printf("\n");
	printf("%-*s                         // ↑ random with EXC2019, somewhat orderly with Gromox\n", lead(ind), "");
	ep.g_uint32(&vd);
	printf("%-*sInner EID size         = %u bytes\n", lead(ind), "",  vd);
	{
		std::string_view sub = s;
		sub.remove_prefix(ep.m_offset);
		if (sub.size() > vd)
			sub = {sub.data(), vd};
		try_entryid(sub, ind + 1);
	}
	ep.advance(vd);

	auto next_offset = ep.m_offset + dnbytes;
	ep.g_wstr(&str); printf("%-*sDisplay name = %s\n", lead(ind), "", str.c_str());
	if (ep.m_offset < next_offset)
		printf("%-*s           + %zu unparsed/garbage bytes\n", lead(ind + 1), "",
			static_cast<size_t>(next_offset - ep.m_offset));
	ep.m_offset = next_offset;

	next_offset = ep.m_offset + smtpbytes;
	ep.g_wstr(&str);  printf("%-*sSMTP address = %s\n", lead(ind), "", str.c_str());
	if (ep.m_offset < next_offset)
		printf("%-*s           + %zu unparsed/garbage bytes\n", lead(ind + 1), "",
			static_cast<size_t>(next_offset - ep.m_offset));
	ep.m_offset = next_offset;
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
	ep.g_uint32(&flags);
	if (flags != (MAPI_SHORTTERM | MAPI_NOTRECIP | MAPI_THISSESSION | MAPI_NOTRESERVED | 0x0f))
		return;
	ep.g_guid(&provider);
	ep.g_uint16(&folder_type);
	ep.g_uint32(&q2);
	ep.g_uint64(&instid);

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
	printf("%-*stype   = 0x%02x <<%s>>\n", lead(ind), "", eid.folder_type, objecttypename(eid.folder_type));
	printf("%-*sdbguid = ", lead(ind), "");
	print_guid(eid.database_guid);
	printf("\n%-*sfidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.global_counter)});
	printf("%-*sreplid = %u\n", lead(ind), "", (eid.pad[0] << 8) | eid.pad[1]);
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
	printf("%-*stype   = 0x%04x\n", lead(ind), "", eid.message_type);
	printf("%-*sfdguid = ", lead(ind), "");
	print_guid(eid.folder_database_guid);
	printf("\n%-*sfidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.folder_global_counter)});
	printf("%-*sreplid = 0x%x\n", lead(ind), "", (eid.pad1[0] << 8) | eid.pad1[1]);
	printf("%-*smdguid = ", lead(ind), "");
	print_guid(eid.message_database_guid);
	printf("\n%-*smidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.message_global_counter)});
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
	else if (le == shared_calendar_provider_guid)
		try_shared_cal(s, ind);
	else
		try_object_eid(s, ind);
}

static void parse(const char *hex)
{
	printf("===== %s:\n", hex);
	auto bin = hex2bin(hex);
	unsigned int i = 0;
	try_guid(bin, i);
	try_entryid(bin, i);
	printf("\n");
}

int main(int argc, char **argv)
{
	while (*++argv != nullptr)
		parse(*argv);
	return EXIT_SUCCESS;
}

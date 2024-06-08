// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <string_view>
#include <gromox/mapidefs.h>
#include <gromox/mapi_types.hpp>
#include <gromox/rop_util.hpp>
#include <gromox/scope.hpp>
#include <gromox/util.hpp>

using namespace gromox;
using LLU = unsigned long long;

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
#define FN(v) if (memcmp(le.ab, &v, sizeof(le.ab)) == 0) printf(" <<" #v ">>");
#define GN(v) if (he == v) printf(" <<" #v ">>");
	FN(muidStoreWrap);
	FN(muidEMSAB);
	FN(pbLongTermNonPrivateGuid);
	FN(g_muidStorePrivate);
	FN(g_muidStorePublic);
	FN(muidOOP);
	FN(muidECSAB);
	FN(muidZCSAB);
	FN(EncodedGlobalId);
	FN(IID_IStorage);
	FN(IID_IStream);
	FN(IID_IMessage);
	FN(IID_IExchangeExportChanges);
	FN(IID_IExchangeImportContentsChanges);
	FN(IID_IExchangeImportHierarchyChanges);
	GN(GUID_NULL);
	GN(PSETID_ADDRESS);
	GN(PSETID_APPOINTMENT);
	GN(PSETID_BUSINESSCARDVIEW);
	GN(PSETID_CALENDARASSISTANT);
	GN(PSETID_COMMON);
	GN(PSETID_GROMOX);
	GN(PSETID_KC);
	GN(PSETID_KCARCHIVE);
	GN(PSETID_LOG);
	GN(PSETID_MEETING);
	GN(PSETID_NOTE);
	GN(PSETID_REMOTE);
        GN(PSETID_REPORT);
        GN(PSETID_SHARING);
        GN(PSETID_TASK);
        GN(PSETID_UNIFIEDMESSAGING);
        GN(PS_INTERNET_HEADERS);
        GN(PS_MAPI);
        GN(PS_PUBLIC_STRINGS);
        GN(gx_dbguid_store_private);
        GN(gx_dbguid_store_public);
#undef FN
#undef GN
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
	auto cl_0 = make_scope_exit([&]() {
		free(eid.px500dn);
	});
	printf("%-*sEX address entry ID\n", lead(ind), "");
	++ind;
	printf("%-*sflags   = 0x%08x\n", lead(ind), "", eid.flags);
	printf("%-*stype    = 0x%08x\n", lead(ind), "", eid.type);
	printf("%-*sx500dn  = %s\n", lead(ind), "", znul(eid.px500dn));
}

static void try_storewrap(std::string_view s, unsigned int ind)
{
	EXT_PULL ep;
	ep.init(s.data(), s.size(), malloc, EXT_FLAG_WCOUNT | EXT_FLAG_UTF16);
	STORE_ENTRYID eid;
	if (ep.g_store_eid(&eid) != pack_result::success)
		return;
	auto cl_0 = make_scope_exit([&]() {
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
	auto cl_1 = make_scope_exit([&]() { free(smtp); });
	if (ep.g_uint32(&v) != pack_result::ok || v != MDB_STORE_EID_V3_MAGIC ||
	    ep.g_uint32(&size) != pack_result::ok ||
	    ep.g_uint32(&v) != pack_result::ok || v != 2 ||
	    ep.g_uint32(&v) != pack_result::ok ||
	    ep.g_wstr(&smtp) != pack_result::ok)
		return;
	printf("%-*sMDB_STORE_EID_V3_MAGIC\n%-*ssmtp    = %s\n", lead(ind), "", lead(ind), "", znul(smtp));
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
	print_guid(*reinterpret_cast<const FLATUID *>(&s[offsetof(FOLDER_ENTRYID, database_guid)]));
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
	printf("%-*stype   = 0x%02x\n", lead(ind), "", eid.message_type);
	printf("%-*sfdguid = ", lead(ind), "");
	print_guid(*reinterpret_cast<const FLATUID *>(&s[offsetof(MESSAGE_ENTRYID, folder_database_guid)]));
	printf("\n%-*sfidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.folder_global_counter)});
	printf("%-*sreplid = 0x%x\n", lead(ind), "", (eid.pad1[0] << 8) | eid.pad1[1]);
	printf("%-*smdguid = ", lead(ind), "");
	print_guid(*reinterpret_cast<const FLATUID *>(&s[offsetof(MESSAGE_ENTRYID, message_database_guid)]));
	printf("\n%-*smidgcv = 0x%llx\n", lead(ind), "", LLU{rop_util_gc_to_value(eid.message_global_counter)});
	printf("%-*sreplid = 0x%x\n", lead(ind), "", (eid.pad2[0] << 8) | eid.pad2[1]);
}

static void try_object_eid(const std::string_view s, unsigned int ind)
{
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
	else if (le == muidStoreWrap)
		try_storewrap(s, ind);
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

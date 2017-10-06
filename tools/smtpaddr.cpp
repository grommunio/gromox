/*
 *	Copyright 2017 Jan Engelhardt
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation; either
 *	version 3 or (at your option) any later version.
 */
#include <memory>
#include <stdexcept>
#include <cstdio>
#include <mapix.h>
#include <mapiutil.h>
#ifdef _WIN32
#	include <tchar.h>
#	define HRFORMAT_X "x%lx"
#	define HRFORMAT_U "%lu"
typedef unsigned int uint32_t; /* VS9 (VS2008) */
#endif
#ifdef M4L
#	include <cstdint>
#	define HRFORMAT_X "x%x"
#	define HRFORMAT_U "%u"
#	define _tprintf printf
#	include "CommonUtil.h"
#	include "ECLogger.h"
#endif
#define INITGUID
#include <initguid.h>
DEFINE_GUID(globalps,
0xc8b0db13, 0x5aa, 0x1a10, 0x9b, 0xb0, 0x00, 0xaa, 0x00, 0x2f, 0xc4, 0x5a);

static uint32_t PR_PROFILE_USER_SMTP_EMAIL_ADDRESS   = PROP_TAG(PT_TSTRING, 0x6641);
static uint32_t PR_PROFILE_USER_SMTP_EMAIL_ADDRESS_A = PROP_TAG(PT_STRING8, 0x6641);
static uint32_t PR_PROFILE_USER_SMTP_EMAIL_ADDRESS_W = PROP_TAG(PT_UNICODE, 0x6641);
static const char *set_profile = "*", *set_email = NULL;
static unsigned int set_level = 1;

class default_delete {
	public:
	void operator()(void *p) const { MAPIFreeBuffer(p); }
	void operator()(SRowSet *p) const { FreeProws(p); }
};

template<typename T, typename _Deleter = default_delete> class memory_ptr {
	private:
	T *m_ptr;
	memory_ptr(const memory_ptr &);
	void operator=(const memory_ptr &);
	public:
	memory_ptr() : m_ptr(NULL) {}
	~memory_ptr() { if (m_ptr != NULL) _Deleter()(m_ptr); }
	void reset()
	{
		if (m_ptr != NULL)
			_Deleter()(m_ptr);
		m_ptr = NULL;
	}
	T **operator&() { reset(); return &m_ptr; }
	T *operator->() const { return m_ptr; }
	operator T *() const { return m_ptr; }
};

template<typename T> class object_ptr {
	private:
	object_ptr(const object_ptr &);
	void operator=(const object_ptr &);
	T *m_ptr;
	public:
	object_ptr() : m_ptr(NULL) {}
	~object_ptr() { if (m_ptr != NULL) m_ptr->Release(); }
	void reset()
	{
		if (m_ptr != NULL)
			m_ptr->Release();
		m_ptr = NULL;
	}
	T **operator&() { reset(); return &m_ptr; }
	T *operator->() const { return m_ptr; }
	operator T *() const { return m_ptr; }
};

static void update_prop(IProfSect *profsect)
{
	if (set_email == NULL) {
		printf("  . Unsetting email_address\n");
		SizedSPropTagArray(1, tags) = {1, {PR_PROFILE_USER_SMTP_EMAIL_ADDRESS_A}};
		profsect->DeleteProps(reinterpret_cast<SPropTagArray *>(&tags), NULL);
		return;
	}

	SPropValue email;
	email.ulPropTag   = PR_PROFILE_USER_SMTP_EMAIL_ADDRESS_A;
	email.Value.lpszA = const_cast<char *>(set_email);
	printf("  . Setting \"%s\"...\n", set_email);
	HRESULT ret = HrSetOneProp(profsect, &email);
	if (ret != hrSuccess)
		printf("failed: " HRFORMAT_X "\n", ret);
	else
		printf("ok\n");
}

static void lookat_svcprov(IProviderAdmin *provadm, SPropValue *provuid)
{
	object_ptr<IProfSect> profsect;
	HRESULT ret = provadm->OpenProfileSection(reinterpret_cast<MAPIUID *>(const_cast<GUID *>(&globalps)),
	              NULL, MAPI_MODIFY, &profsect);
	if (ret != hrSuccess) {
		printf("OpenProfileSection failed: " HRFORMAT_X "\n", ret);
		return;
	} else if (profsect == NULL) {
		printf("OpenProfileSection: no section\n");
		return;
	}

	update_prop(profsect);
}

static void lookat_msgsvc(IMsgServiceAdmin *svcadm, SPropValue *svcuid)
{
	object_ptr<IProfSect> profsect;
	HRESULT ret = svcadm->OpenProfileSection(reinterpret_cast<MAPIUID *>(const_cast<GUID *>(&globalps)),
	              NULL, MAPI_MODIFY, &profsect);
	if (ret != hrSuccess) {
		printf("OpenProfileSection failed: " HRFORMAT_X "\n", ret);
		return;
	} else if (profsect == NULL) {
		printf("OpenProfileSection: no section\n");
		return;
	}

	update_prop(profsect);
	if (set_level < 2)
		return;

	object_ptr<IProviderAdmin> provadm;
	ret = svcadm->AdminProviders(reinterpret_cast<MAPIUID *>(svcuid->Value.bin.lpb), 0, &provadm);
	if (ret != hrSuccess) {
		printf("AdminProviders failed: " HRFORMAT_X "\n", ret);
		return;
	}
	object_ptr<IMAPITable> table;
	ret = svcadm->GetProviderTable(0, &table);
	if (ret != hrSuccess) {
		printf("GetProviderTable failed: " HRFORMAT_X "\n", ret);
		return;
	}

	while (true) {
		memory_ptr<SRowSet> rowset;
		ret = table->QueryRows(1, 0, &rowset);
		if (ret != hrSuccess) {
			printf("QueryRows failed: " HRFORMAT_X "\n", ret);
			return;
		}
		if (rowset->cRows != 1)
			break;

		SRow &r0 = rowset->aRow[0];
		SPropValue *type = PpropFindProp(r0.lpProps, r0.cValues, PR_PROVIDER_DISPLAY_A);
		SPropValue *uid  = PpropFindProp(r0.lpProps, r0.cValues, PR_PROVIDER_UID);
		if (type == NULL || PROP_TYPE(type->ulPropTag) == PT_ERROR) {
			printf("* Provider without type\n");
			continue;
		}
		if (uid == NULL) {
			printf("* Provider \"%s\" without UID\n", type->Value.lpszA);
			continue;
		}

		printf("* Provider \"%s\"\n", type->Value.lpszA);
		if (PROP_TYPE(uid->ulPropTag) == PT_CLSID) {
			printf("* Did not expect to see a CLSID\n");
			continue;
		}
		if (PROP_TYPE(uid->ulPropTag) != PT_BINARY) {
			printf("* Unexpected proptag for UID, " HRFORMAT_X "\n", uid->ulPropTag);
			continue;
		}
		if (uid->Value.bin.cb != sizeof(MAPIUID)) {
			printf("* Unexpected provuid length " HRFORMAT_U "\n", uid->Value.bin.cb);
			continue;
		}
		lookat_svcprov(provadm, uid);
	}
}

static void lookat_profile(IProfAdmin *profadm, TCHAR *profname)
{
	object_ptr<IMsgServiceAdmin> svcadm;
	HRESULT ret = profadm->AdminServices(profname, NULL, 0, 0, &svcadm);
	if (ret != hrSuccess) {
		printf("AdminServices failed: " HRFORMAT_X "\n", ret);
		return;
	}
	object_ptr<IMAPITable> table;
	ret = svcadm->GetMsgServiceTable(0, &table);
	if (ret != hrSuccess) {
		printf("GetMsgServiceTable failed: " HRFORMAT_X "\n", ret);
		return;
	}

	while (true) {
		memory_ptr<SRowSet> rowset;
		ret = table->QueryRows(1, 0, &rowset);
		if (ret != hrSuccess) {
			printf("QueryRows failed: " HRFORMAT_X "\n", ret);
			return;
		}
		if (rowset->cRows != 1)
			break;

		SRow &r0 = rowset->aRow[0];
		SPropValue *type = PpropFindProp(r0.lpProps, r0.cValues, PR_SERVICE_NAME_A);
		SPropValue *uid  = PpropFindProp(r0.lpProps, r0.cValues, PR_SERVICE_UID);
		if (type == NULL || PROP_TYPE(type->ulPropTag) == PT_ERROR) {
			printf("* Service without type\n");
			continue;
		}
		if (uid == NULL) {
			printf("* Service \"%s\" without UID\n", type->Value.lpszA);
			continue;
		}

		printf("* Service \"%s\"\n", type->Value.lpszA);
		if (PROP_TYPE(uid->ulPropTag) == PT_CLSID) {
			printf("* Did not expect to see a CLSID\n");
			continue;
		}
		if (PROP_TYPE(uid->ulPropTag) != PT_BINARY) {
			printf("* Unexpected proptag for UID, " HRFORMAT_X "\n", uid->ulPropTag);
			continue;
		}
		if (uid->Value.bin.cb != sizeof(MAPIUID)) {
			printf("* Unexpected svcuid length " HRFORMAT_U "\n", uid->Value.bin.cb);
			continue;
		}
		lookat_msgsvc(svcadm, uid);
	}
}

static void lookat_profile_list()
{
	object_ptr<IProfAdmin> profadm;
	HRESULT ret = MAPIAdminProfiles(0, &profadm);
	if (ret != hrSuccess) {
		printf("MAPIAdminProfiles failed: " HRFORMAT_X "\n", ret);
		return;
	}

	/*
	 * MAPI VFs (IProfAdmin::AdminServices, etc.) require ASCII data,
	 * even though its signature is TCHAR.
	 */
	object_ptr<IMAPITable> table;
	ret = profadm->GetProfileTable(0, &table);
	if (ret != hrSuccess) {
		printf("GetProfileTable failed: " HRFORMAT_X "\n", ret);
		return;
	}

	while (true) {
		memory_ptr<SRowSet> rowset;
		ret = table->QueryRows(1, 0, &rowset);
		if (ret != hrSuccess) {
			printf("QueryRows failed: " HRFORMAT_X "\n", ret);
			return;
		}
		if (rowset->cRows != 1)
			break;
		SRow &r0 = rowset->aRow[0];
		SPropValue *name = PpropFindProp(r0.lpProps, r0.cValues, PR_DISPLAY_NAME_A);
		if (name == NULL) {
			printf("* Ignoring profile with no name\n");
			continue;
		}
		if (PROP_TYPE(name->ulPropTag) == PT_ERROR) {
			printf("* Ignoring a profile with PR_DISPLAY_NAME=>PT_ERROR\n");
			continue;
		}
		if (strcmp(set_profile, "_all") != 0 &&
		    strcmp(set_profile, name->Value.lpszA) != 0) {
			printf("* Skipping profile \"%s\"\n", name->Value.lpszA);
			continue;
		}
		printf("* Profile \"%s\"\n", name->Value.lpszA);
		lookat_profile(profadm, name->Value.LPSZ);
	}
}

static void main2()
{
#ifdef M4L
	object_ptr<IMAPISession> ses;
	auto ret = HrOpenECSession(&ses, "mapitime", "", L"foo", L"xfoo",
	      "default:", 0, NULL, NULL);
	if (ret != hrSuccess)
		throw std::runtime_error("OpenECSession");
#endif
	lookat_profile_list();
}

int main(int argc, char **argv)
{
#ifdef M4L
	ec_log_get()->SetLoglevel(EC_LOGLEVEL_DEBUG);
#endif
	if (argc < 3) {
		printf("Usage: %s LEVEL PROFILE [ADDRESS]\n", argv[0]);
		printf("- A level of \"1\" operates on message services (ZARAFA6, CONTAB, etc.).\n");
		printf("- A level of \"2\" operates on service providers as well (ZARAFA6.ZARAFA6_ABP, CONTAB.ZARAFA6_ABP, ZARAFA6.ZARAFA6_MSMDB_public, etc.). Only choose this if level 1 does not fix the problem.\n");
		printf("- The magic profile name \"_all\" operates on all profiles.\n");
		printf("- Omitting ADDRESS will clear the property at the given levels.\n");
		return EXIT_FAILURE;
	}
	set_level = strtoul(argv[1], NULL, 0);
	set_profile = argv[2];
	if (argc >= 4)
		set_email = argv[3];
	HRESULT ret = MAPIInitialize(NULL);
	if (ret != hrSuccess) {
		printf("MAPIInitialize %lx\n", static_cast<unsigned long>(ret));
		return EXIT_FAILURE;
	}
	main2();
	MAPIUninitialize();
	return EXIT_SUCCESS;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 grommunio GmbH
// This file is part of Gromox.
/*
 * Use: x86_64-w64-mingw32-g++ -static getzones.cpp && ./a.exe
 */
#include <windows.h>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>

enum {
	TZ_BIN_VERSION_MAJOR = 2U,
	TZ_BIN_VERSION_MINOR = 1U,
	TZDEFINITION_FLAG_VALID_GUID = 0x1U,
	TZDEFINITION_FLAG_VALID_KEYNAME = 0x2U,
	TZRULE_FLAG_RECUR_CURRENT_TZREG = 0x1U,
	TZRULE_FLAG_EFFECTIVE_TZREG = 0x2U,
};

struct __attribute__((packed)) TZREG {
	long lBias;
	long lStandardBias;
	long lDaylightBias;
	SYSTEMTIME stStandardDate;
	SYSTEMTIME stDaylightDate;
};

struct __attribute__((packed)) TZRULE {
	uint8_t bMajorVersion = TZ_BIN_VERSION_MAJOR;
	uint8_t bMinorVersion = TZ_BIN_VERSION_MINOR;
	int16_t wReserved = 0x3E;
	int16_t wFlags = 0;
	int16_t wStartYear = 0;
	uint32_t pad_1 = 0x1, pad_2 = 0x1, pad_3 = 0;
	uint16_t pad_4 = 0;
	TZREG tzreg;
};

int do_zone2(std::string &blob, DYNAMIC_TIME_ZONE_INFORMATION &dtz)
{
	using C = const char *;
	DWORD first_year = 0, last_year = 0;
	// Default to at least 1 rule if effective years fail
	uint16_t cRules = 1;

	// Query the range of years this dynamic time zone has explicit rules for
	if (GetDynamicTimeZoneInformationEffectiveYears(&dtz,
	    &first_year, &last_year) == ERROR_SUCCESS)
		cRules = last_year - first_year + 1;

	uint8_t bv = TZ_BIN_VERSION_MAJOR;
	blob.append(C(&bv), 1); // bMajorversion
	bv = TZ_BIN_VERSION_MINOR;
	blob.append(C(&bv), 1); // bMinorversion
	uint16_t namelen = wcslen(dtz.TimeZoneKeyName);
	uint16_t cbHeader = namelen * 2 + 6;
	blob.append(C(&cbHeader), 2);
	uint16_t sv = TZDEFINITION_FLAG_VALID_KEYNAME;
	blob.append(C(&sv), 2); // wFlags/wReserved
	blob.append(C(&namelen), 2); // cchKeyName
	blob.append(C(dtz.TimeZoneKeyName), namelen * 2); // szKeyName
	blob.append(C(&cRules), 2);

	// Fetch and populate rules for every applicable year sequentially
	for (uint16_t i = 0; i < cRules; ++i) {
		WORD cur_year = cRules == 1 ? 1601 : first_year + i;
		TZRULE rule;
		TIME_ZONE_INFORMATION tzi{};

		// Get the specific rule parameters for this specific year
		auto ok = GetTimeZoneInformationForYear(cur_year, &dtz, &tzi);
		if (!ok) {
			// If fetching fails, fall back to base information defaults safely
			tzi.Bias = dtz.Bias;
			tzi.StandardBias = dtz.StandardBias;
			tzi.DaylightBias = dtz.DaylightBias;
			tzi.StandardDate = dtz.StandardDate;
			tzi.DaylightDate = dtz.DaylightDate;
		}

#if 0
		if (tzi.StandardDate.wMonth == 0)
			tzi.StandardBias = 0;
		if (tzi.DaylightDate.wMonth == 0)
			tzi.DaylightBias = 0;
#endif

		rule.wStartYear = cur_year;
		if (i == cRules - 1)
			rule.wFlags |= TZRULE_FLAG_EFFECTIVE_TZREG;

		// Map values into the binary sub-structure layout
		rule.tzreg.lBias = tzi.Bias;
		rule.tzreg.lStandardBias = tzi.StandardBias;
		rule.tzreg.lDaylightBias = tzi.DaylightBias;
		rule.tzreg.stStandardDate = tzi.StandardDate;
		rule.tzreg.stDaylightDate = tzi.DaylightDate;
		blob.append((char *)&rule, sizeof(rule));
	}
	return 0;
}

int do_zone(DYNAMIC_TIME_ZONE_INFORMATION &dtz)
{
	const auto &wname = dtz.TimeZoneKeyName;
	auto need = WideCharToMultiByte(CP_UTF8, 0, wname, wcslen(wname),
	            nullptr, 0, nullptr, nullptr);
	std::string name;
	name.resize(need);
	WideCharToMultiByte(CP_UTF8, 0, wname, wcslen(wname), name.data(),
		need, nullptr, nullptr);
	auto pos = name.find(" Standard Time"); /* from wintz_load_namemap */
	if (pos != name.npos)
		name.erase(pos, 14);
	for (auto &c : name) {
		/* from replace_unsafe_basename */
		auto safe = isascii(c) && (isalnum(c) ||
		            c == '+' || c == '-' || c == '^' || c == '_');
		if (!safe)
			c = '_';
	}
	name += ".tzd";

	std::string blob;
	if (do_zone2(blob, dtz) < 0)
		return -1;
	auto fp = fopen(name.c_str(), "wb");
	if (fp == nullptr) {
		fprintf(stderr, "%s: %s\n", name.c_str(), strerror(errno));
		return -1;
	} else if (fwrite(blob.data(), blob.size(), 1, fp) < 0) {
		fprintf(stderr, "fwrite: %s\n", strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	fprintf(stderr, "%s: %zu bytes\n", name.c_str(), blob.size());
	return 0;
}

int main()
{
	DYNAMIC_TIME_ZONE_INFORMATION tz;
	for (uint32_t idx = 0;
	     EnumDynamicTimeZoneInformation(idx, &tz) == ERROR_SUCCESS;
	     ++idx)
		do_zone(tz);
	return 0;
}

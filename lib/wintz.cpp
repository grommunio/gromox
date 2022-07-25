// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1 /* strcasestr */
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <tinyxml2.h>
#include <utility>
#include <unordered_map>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <libHX/io.h>
#include <libHX/string.h>

using namespace gromox;

static std::atomic<unsigned int> wintz_loaded;
static std::unordered_map<std::string, std::string> iana_to_wzone;
static std::unordered_map<std::string, std::string> wzone_to_tzdef;

static errno_t wintz_load_namemap(const char *dirs)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen_sd("windowsZones.xml", dirs));
	if (fp == nullptr) {
		fprintf(stderr, "Could not open windowsZones.xml: %s\n", strerror(errno));
		return errno;
	}
	tinyxml2::XMLDocument doc;
	auto ret = doc.LoadFile(fp.get());
	if (ret != tinyxml2::XML_SUCCESS) {
		fprintf(stderr, "Failed to load/parse windowsZones.xml\n");
		return EIO;
	}
	auto node = doc.RootElement();
	if (node == nullptr)
		return EIO;
	auto name = node->Name();
	if (name == nullptr || strcasecmp(name, "supplementalData") != 0) {
		fprintf(stderr, "No supplemental root element\n");
		return EIO;
	}
	node = node->FirstChildElement("windowsZones");
	if (node == nullptr) {
		fprintf(stderr, "No windowsZones element\n");
		return EIO;
	}
	node = node->FirstChildElement("mapTimezones");
	if (node == nullptr) {
		fprintf(stderr, "No mapTimezones element\n");
		return EIO;
	}
	for (node = node->FirstChildElement("mapZone");
	     node != nullptr; node = node->NextSiblingElement("mapZone")) {
		auto oattr = node->FindAttribute("other");
		auto iattr  = node->FindAttribute("type");
		if (oattr == nullptr || iattr == nullptr)
			continue;
		auto oval = oattr->Value();
		auto ival = iattr->Value();
		if (oval == nullptr || ival == nullptr)
			continue;
		std::string ovs = oval, ivs = ival;
		HX_strlower(ivs.data());
		auto p = strcasestr(ovs.c_str(), " Standard Time");
		if (p != nullptr)
			ovs.erase(p - ovs.c_str(), 14);
		std::replace(ovs.begin(), ovs.end(), ' ', '_');
		iana_to_wzone.emplace(std::move(ivs), std::move(ovs));
	}
	return 0;
}

static errno_t wintz_load_tzdefs(const char *dirs)
{
	for (const auto &tzpair : iana_to_wzone) {
		auto &wzone = tzpair.second;
		std::unique_ptr<FILE, file_deleter> fp(fopen_sd((wzone + ".tzd").c_str(), dirs));
		if (fp == nullptr) {
			fprintf(stderr, "Could not open %s: %s\n",
			        wzone.c_str(), strerror(errno));
			return errno;
		}
		size_t sl = 0;
		std::unique_ptr<char[], stdlib_delete> sd(HX_slurp_fd(fileno(fp.get()), &sl));
		if (sd == nullptr) {
			fprintf(stderr, "slurp_fd: %s\n", strerror(errno));
			return errno;
		}
		wzone_to_tzdef.emplace(wzone, std::string(sd.get(), sl));
	}
	return 0;
}

namespace gromox {

const std::string *ianatz_to_tzdef(const char *izone, const char *dirs)
{
	if (dirs == nullptr)
		dirs = PKGDATADIR;
	unsigned int exp = 0;
	if (wintz_loaded.compare_exchange_strong(exp, 1)) {
		auto ret = wintz_load_namemap(dirs);
		if (ret != 0)
			return nullptr;
		ret = wintz_load_tzdefs(dirs);
		if (ret != 0)
			return nullptr;
	}
	std::string lizone = izone;
	HX_strlower(lizone.data());
	auto wi = iana_to_wzone.find(lizone);
	if (wi == iana_to_wzone.end())
		return nullptr;
	auto ti = wzone_to_tzdef.find(wi->second);
	if (ti == wzone_to_tzdef.end())
		return nullptr;
	return &ti->second;
}

}

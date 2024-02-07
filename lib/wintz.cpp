// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022-2023 grommunio GmbH
// This file is part of Gromox.
#define _GNU_SOURCE 1 /* strcasestr */
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <tinyxml2.h>
#include <utility>
#include <unordered_map>
#include <gromox/archive.hpp>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#include <libHX/io.h>
#include <libHX/string.h>

using namespace gromox;

static std::atomic<unsigned int> wintz_loaded;
static gromox::archive tzd_archive;
static std::unordered_map<std::string, std::string> iana_to_wzone;
static std::unordered_map<std::string, std::string> wzone_to_tzdef;

static errno_t wintz_load_namemap(const archive &arc)
{
	auto fp = arc.find("windowsZones.xml");
	if (fp == nullptr) {
		mlog(LV_ERR, "Could not open windowsZones.xml: %s", strerror(ENOENT));
		return ENOENT;
	}
	tinyxml2::XMLDocument doc;
	auto ret = doc.Parse(fp->data(), fp->size());
	if (ret != tinyxml2::XML_SUCCESS) {
		mlog(LV_ERR, "Failed to load/parse windowsZones.xml");
		return EIO;
	}
	auto node = doc.RootElement();
	if (node == nullptr)
		return EIO;
	auto name = node->Name();
	if (name == nullptr || strcasecmp(name, "supplementalData") != 0) {
		mlog(LV_ERR, "No supplemental root element");
		return EIO;
	}
	node = node->FirstChildElement("windowsZones");
	if (node == nullptr) {
		mlog(LV_ERR, "No windowsZones element");
		return EIO;
	}
	node = node->FirstChildElement("mapTimezones");
	if (node == nullptr) {
		mlog(LV_ERR, "No mapTimezones element");
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
		replace_unsafe_basename(ovs.data());
		for (auto &&i : gx_split(ivs, ' '))
			if (!i.empty())
				iana_to_wzone.emplace(std::move(i), ovs);
	}
	return 0;
}

static errno_t wintz_load_once()
{
	unsigned int exp = 0;
	if (!wintz_loaded.compare_exchange_strong(exp, 1))
		return 0;
	static constexpr char pak[] = PKGDATADIR "/timezone.pak";
	auto err = tzd_archive.open(pak);
	if (err != 0) {
		if (errno == ENOENT)
			return 0;
		mlog(LV_ERR, "Could not read %s: %s", pak, strerror(errno));
		return errno;
	}
	return wintz_load_namemap(tzd_archive);
}

namespace gromox {

const std::string_view *wintz_to_tzdef(const char *izone)
{
	if (wintz_load_once() != 0)
		return nullptr;
	return tzd_archive.find(izone + std::string(".tzd"));
}

const std::string_view *ianatz_to_tzdef(const char *izone)
{
	if (wintz_load_once() != 0)
		return nullptr;
	std::string lizone = izone;
	HX_strlower(lizone.data());
	auto wi = iana_to_wzone.find(lizone);
	if (wi == iana_to_wzone.end())
		return nullptr;
	return wintz_to_tzdef(wi->second.c_str());
}

}

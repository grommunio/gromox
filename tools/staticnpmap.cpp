// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <gromox/mapidefs.h>
#include "genimport.hpp"

struct namedprop_bimap {
	public:
	uint16_t emplace(uint16_t, PROPERTY_XNAME &&);

	gi_name_map fwd;
	std::unordered_map<std::string, uint16_t> rev;
	uint16_t nextid = 0x8000;
};

static struct namedprop_bimap static_namedprop_map;

uint16_t namedprop_bimap::emplace(uint16_t desired_propid, PROPERTY_XNAME &&name)
{
	if (desired_propid == 0)
		desired_propid = nextid;
	if (desired_propid == UINT16_MAX)
		return 0;
	/*
	 * Purpose of the rmap is to detect previously-added names.
	 * A text representation is used so we don't have to hash<PROPERTY_XNAME>.
	 */
	char guid[GUIDSTR_SIZE], txt[NP_STRBUF_SIZE];
	name.guid.to_str(guid, std::size(guid));
	if (name.kind == MNID_ID)
		snprintf(txt, std::size(txt), "GUID=%s,LID=%u", guid, name.lid);
	else
		snprintf(txt, std::size(txt), "GUID=%s,NAME=%s", guid, name.name.c_str());
	auto [iter, newly_added] = rev.emplace(txt, desired_propid);
	if (!newly_added)
		return iter->second;
	fwd.emplace(desired_propid, std::move(name));
	nextid = std::max(nextid, static_cast<uint16_t>(desired_propid + 1));
	return desired_propid;
}

static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) __attribute__((unused));
static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	ids->ppropid = gromox::me_alloc<uint16_t>(names->count);
	if (ids->ppropid == nullptr)
		return false;
	ids->count = names->count;
	for (size_t i = 0; i < names->count; ++i)
		(*ids)[i] = static_namedprop_map.emplace(0, names->ppropname[i]);
	return TRUE;
}

static const PROPERTY_XNAME *ee_get_propname(uint16_t) __attribute__((unused));
static const PROPERTY_XNAME *ee_get_propname(uint16_t propid)
{
	auto i = static_namedprop_map.fwd.find(propid);
	return i != static_namedprop_map.fwd.end() ? &i->second : nullptr;
}

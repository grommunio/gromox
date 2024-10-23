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
	gromox::propid_t emplace(gromox::propid_t, PROPERTY_XNAME &&);

	gi_name_map fwd;
	std::unordered_map<std::string, gromox::propid_t> rev;
	gromox::propid_t nextid = 0x8000;
};

static struct namedprop_bimap static_namedprop_map;

gromox::propid_t namedprop_bimap::emplace(gromox::propid_t desired_propid,
    PROPERTY_XNAME &&name)
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
	fwd.emplace(PROP_TAG(PT_UNSPECIFIED, desired_propid), std::move(name));
	nextid = std::max(nextid, static_cast<gromox::propid_t>(desired_propid + 1));
	return desired_propid;
}

static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) __attribute__((unused));
static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids) try
{
	ids->resize(names->count);
	for (size_t i = 0; i < names->count; ++i)
		(*ids)[i] = static_namedprop_map.emplace(0, names->ppropname[i]);
	return TRUE;
} catch (const std::bad_alloc &) {
	gromox::mlog(LV_ERR, "E-2237: ENOMEM");
	return false;
}

static const PROPERTY_XNAME *ee_get_propname(gromox::propid_t) __attribute__((unused));
static const PROPERTY_XNAME *ee_get_propname(gromox::propid_t propid)
{
	auto i = static_namedprop_map.fwd.find(propid);
	return i != static_namedprop_map.fwd.end() ? &i->second : nullptr;
}

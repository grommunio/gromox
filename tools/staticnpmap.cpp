// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdint>
#include <string>
#include <unordered_map>
#include <gromox/mapidefs.h>
#include "genimport.hpp"

static gi_name_map name_map;
static std::unordered_map<std::string, uint16_t> name_rev_map;
static uint16_t name_id = 0x8000;

static BOOL ee_get_propids(const PROPNAME_ARRAY *names, PROPID_ARRAY *ids)
{
	ids->ppropid = gromox::me_alloc<uint16_t>(names->count);
	if (ids->ppropid == nullptr)
		return false;
	ids->count = names->count;
	for (size_t i = 0; i < names->count; ++i) {
		auto &name = names->ppropname[i];
		char guid[GUIDSTR_SIZE], txt[NP_STRBUF_SIZE];
		name.guid.to_str(guid, std::size(guid));
		if (name.kind == MNID_ID)
			snprintf(txt, std::size(txt), "GUID=%s,LID=%u", guid, name.lid);
		else
			snprintf(txt, std::size(txt), "GUID=%s,NAME=%s", guid, name.pname);
		auto [iter, added] = name_rev_map.emplace(std::move(txt), name_id);
		if (!added) {
			ids->ppropid[i] = iter->second;
			continue;
		} else if (name_id == 0xffff) {
			ids->ppropid[i] = 0;
			continue;
		}
		name_map.emplace(PROP_TAG(PT_UNSPECIFIED, name_id), name);
		ids->ppropid[i] = name_id++;
	}
	return TRUE;
}

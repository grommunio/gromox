// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2023–2024 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <libHX/ctype_helper.h>
#include <libHX/scope.hpp>
#include <libHX/string.h>
#include <gromox/element_data.hpp>
#include <gromox/fileio.h>
#include <gromox/mapidefs.h>
#include <gromox/msgchg_grouping.hpp>
#include <gromox/proptag_array.hpp>
#include <gromox/util.hpp>

using namespace std::string_literals;
using namespace gromox;

namespace {

struct tag_entry {
	proptag_t proptag = 0;
	PROPERTY_XNAME propname{};
};

using taglist_t = std::vector<tag_entry>;
using grptotags_t = std::map<uint32_t, taglist_t>;

}

static std::map<uint32_t, grptotags_t> g_map_list; /* map to group; group to tags */

static errno_t mcg_parse(const char *line, tag_entry &node)
{
	auto &pn = node.propname;
	while (line != nullptr && *line != '\0') {
		const char *end = strchr(line, ','); /* CONST-STRCHR-MARKER */
		if (end == nullptr)
			end = line + strlen(line);
		if (strncasecmp(line, "GUID=", 5) == 0) {
			/* from_str really needs a \0 */
			char gp[39];
			gx_strlcpy(gp, &line[5], std::size(gp));
			auto p = strchr(gp, ',');
			if (p != nullptr)
				*p = '\0';
			if (!pn.guid.from_str(gp))
				return EINVAL;
		} else if (strncasecmp(line, "LID=", 4) == 0) {
			pn.kind = MNID_ID;
			pn.lid  = strtoul(&line[4], nullptr, 0);
			if (pn.lid == 0)
				return EINVAL;
		} else if (strncasecmp(line, "NAME=", 5) == 0) {
			pn.kind = MNID_STRING;
			pn.name = std::string(&line[5], end - &line[5]);
			if (pn.name.empty())
				return EINVAL;
		} else if (strncasecmp(line, "TYPE=", 5) == 0) {
			node.proptag = PROP_TAG(strtoul(&line[5], nullptr, 0), 0);
			if (node.proptag == PR_NULL)
				return EINVAL;
		} else if (line[0] == '0' && line[1] == 'x') {
			pn.guid = {};
			node.proptag = PROP_TAG(strtoul(&line[0], nullptr, 0), 0);
			if (node.proptag == PR_NULL)
				return EINVAL;
		}
		line = end;
		while (*line == ',')
			++line;
	}
	return 0;
}

static errno_t mcg_loadfile(const char *dirs, const char *file, uint32_t map_id)
{
	auto emp_res = g_map_list.emplace(map_id, grptotags_t{});
	if (!emp_res.second)
		return EEXIST;
	std::unique_ptr<FILE, file_deleter> fp(fopen_sd(file, dirs));
	if (fp == nullptr) {
		mlog(LV_ERR, "Could not open %s: %s", file, strerror(errno));
		return errno;
	}
	auto &grp_list = emp_res.first->second;
	std::vector<tag_entry> *tag_list = nullptr;
	hxmc_t *line = nullptr;
	auto cl_0 = HX::make_scope_exit([&]() { HXmc_free(line); });
	while (HX_getl(&line, fp.get()) != nullptr) {
		if (strncasecmp(line, "group:", 6) == 0) {
			auto i = strtoul(&line[6], nullptr, 0);
			tag_list = &grp_list.emplace(i, taglist_t{}).first->second;
			continue;
		}
		if (*line == '\0' || HX_isspace(*line))
			continue;
		if (tag_list == nullptr)
			return EINVAL;
		tag_entry tag;
		if (tag_list->size() > 0)
			tag.propname.guid = tag_list->back().propname.guid;
		auto err = mcg_parse(line, tag);
		if (err != 0)
			return err;
		tag_list->push_back(std::move(tag));
	}
	return 0;
}

errno_t msgchg_grouping_run(const char *datadir) try
{
	auto err = mcg_loadfile(datadir, "msgchg_1.txt", 1);
	if (err != 0)
		mlog(LV_ERR, "msgchggrp: map 1: %s", strerror(err));
	return g_map_list.size() != 0 ? err : errno_t{ENOENT};
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1493: ENOMEM");
	return ENOMEM;
}

uint32_t msgchg_grouping_get_last_map_id()
{
	return g_map_list.size() > 0 ? g_map_list.rbegin()->first : 0;
}

std::unique_ptr<property_groupinfo>
    msgchg_grouping_get_groupinfo(get_named_propid_t get_named_propid,
    void *store, uint32_t map_id) try
{
	auto map_iter = g_map_list.find(map_id);
	if (map_iter == g_map_list.end())
		return NULL;
	auto info = std::make_unique<property_groupinfo>(map_id);
	for (const auto &[group_id, raw_tags] : map_iter->second) {
		auto resolved_tags = proptag_array_init();
		for (const auto &node : raw_tags) {
			uint32_t tag = node.proptag;
			if (PROP_ID(tag) == 0) {
				propid_t propid = 0;
				PROPERTY_NAME pn(node.propname);
				if (!get_named_propid(store, TRUE,
				    &pn, &propid) || propid == 0) {
					proptag_array_free(resolved_tags);
					return nullptr;
				}
				tag = PROP_TAG(PROP_TYPE(tag), propid);
			}
			if (!proptag_array_append(resolved_tags, tag)) {
				proptag_array_free(resolved_tags);
				return nullptr;
			}
		}
		if (!info->append_internal(resolved_tags)) {
			proptag_array_free(resolved_tags);
			return nullptr;
		}
	}
	return info;
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1632: ENOMEM");
	return nullptr;
}

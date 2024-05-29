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
	uint32_t proptag = 0;
	PROPERTY_XNAME propname{};
};

using taglist_t = std::vector<tag_entry>;
using indextotags_t = std::map<uint32_t, taglist_t>;

}

static std::map<uint32_t, indextotags_t> g_group_list; /* group to indices; index to tags */
static const char *g_builtin_group_1[] = {
	"index:0",
	"0x0E070003",
	"0x65E20102",
	"0x3FFB0102",
	"0x3FFA001F",
	"0x67090040",

	"index:1",
	"0x0002000B",
	"0x00390040",
	"0x30070040",
	"0x0F020040",
	"0x10F2000B",
	"0x0E990102",
	"0x10F00102",
	"0x0E2F0003",
	"0x0E230003",
	"0x3FDE0003",
	"0x30080040",
	"0x0058000B",
	"0x3FFD0003",
	"0x0E060040",
	"0x3FF10003",
	"0x0059000B",
	"0x0057000B",
	"0x65E30102",
	"0x0F010040",
	"0x300B0102",
	"0x65C60003",
	"0x0E790003",
	"0x3F880014",
	"0x0E960102",

	"index:2",
	"0x10960003",
	"0x10900003",
	"0x10950003",
	"0x12051002",
	"0x10800003",
	"0x0ECD000B",
	"0x3DAD000B",
	"0x10810003",
	"0x10820040",
	"0x0C06000B",
	"0x12041002",
	"0x12060003",
	"0x12070102",
	"0x3FD9001F",
	"0x0E69000B",
	"0x0029000B",
	"0x00300040",
	"0x0E140003",
	"0x10910040",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34130,TYPE=0x0003",
	"LID=34132,TYPE=0x001F",
	"GUID=00062003-0000-0000-C000-000000000046,LID=33025,TYPE=0x0003",
	"LID=33026,TYPE=0x0005",
	"LID=33039,TYPE=0x0040",
	"LID=33052,TYPE=0x000B",

	"index:3",
	"0x0023000B",
	"0x00170003",
	"0x00260003",
	"0x00360003",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34179,TYPE=0x001F",
	"LID=34064,TYPE=0x0003",

	"index:4",
	"0x10130102",
	"0x1013001F",
	"0x1000001F",
	"0x10160003",
	"0x10090102",
	"0x0E1F000B",

	"index:5",
	"0x0E12000D",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33336,TYPE=0x001F",
	"LID=33373,TYPE=0x0102",
	"LID=33340,TYPE=0x001F",
	"LID=33339,TYPE=0x001F",

	"index:6",
	"0x0E13000D",

	"index:7",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34144,TYPE=0x0040",
	"LID=34051,TYPE=0x000B",
	"LID=34050,TYPE=0x0040",

	"index:8",
	"0x0F030102",
	"0x30130102",
	"0x00710102",
	"0x3016000B",
	"0x3DAA0102",
	"0x0070001F",
	"0x3001001F",
	"0x001A001F",
	"0x0E1D001F",
	"0x0C1F001F",
	"0x0C1A001F",
	"0x0065001F",
	"0x0042001F",
	"0x0037001F",
	"0x003D001F",

	"index:9",
	"0x3A2E001F",
	"0x3A1B001F",
	"0x3A24001F",
	"0x3A51001F",
	"0x3A08001F",
	"0x3A02001F",
	"0x3A1E001F",
	"0x3A57001F",
	"0x3A16001F",
	"0x3A26001F",
	"0x3A18001F",
	"0x0F01001F",
	"0x3003001F",
	"0x3A06001F",
	"0x3A2F001F",
	"0x3A09001F",
	"0x3A27001F",
	"0x3A1C001F",
	"0x3A21001F",
	"0x3A15001F",
	"0x3A2A001F",
	"0x3A2B001F",
	"0x3A1A001F",
	"0x3A28001F",
	"0x3A29001F",
	"0x3A11001F",
	"0x3A17001F",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34101,TYPE=0x001F",
	"LID=34105,TYPE=0x001F",
	"LID=34106,TYPE=0x001F",
	"GUID=00062004-0000-0000-c000-000000000046,LID=32912,TYPE=0x001F",
	"LID=32915,TYPE=0x001F",
	"LID=32916,TYPE=0x001F",
	"LID=32928,TYPE=0x001F",
	"LID=32931,TYPE=0x001F",
	"LID=32932,TYPE=0x001F",
	"LID=32896,TYPE=0x001F",
	"LID=32899,TYPE=0x001F",
	"LID=32900,TYPE=0x001F",
	"GUID=00020329-0000-0000-c000-000000000046,NAME=urn:schemas:contacts:fileas,TYPE=0x001F",
	"GUID=00062004-0000-0000-c000-000000000046,LID=32773,TYPE=0x001F",
	"LID=32794,TYPE=0x001F",
	"LID=32811,TYPE=0x001F",
	"LID=32866,TYPE=0x001F",
	"GUID=00020329-0000-0000-c000-000000000046,NAME=Keywords,TYPE=0x101F",
	"GUID=0006200a-0000-0000-c000-000000000046,LID=34560,TYPE=0x001F",
	"GUID=00062004-0000-0000-c000-000000000046,LID=32796,TYPE=0x001F",
	"GUID=00062040-0000-0000-c000-000000000046,LID=35409,TYPE=0x001F",
	"LID=35335,TYPE=0x001F",
	"LID=35343,TYPE=0x001F",
	"LID=35375,TYPE=0x001F",
	"LID=35333,TYPE=0x001F",
	"LID=35332,TYPE=0x001F",
	"GUID=00062003-0000-0000-c000-000000000046,LID=33055,TYPE=0x001F",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34212,TYPE=0x001F",
	"GUID=4442858e-a9e3-4e80-b900-317a210cc15b,NAME=UMAudioNotes,TYPE=0x001F",
	"GUID=00062004-0000-0000-c000-000000000046,LID=32795,TYPE=0x001F",
	"LID=32814,TYPE=0x001F",
	"LID=32812,TYPE=0x001F",
	"LID=32813,TYPE=0x001F",

	"index:10",
	"GUID=00062008-0000-0000-c000-000000000046,LID=34182,TYPE=0x001F",
	"LID=34096,TYPE=0x001F",
	"LID=34189,TYPE=0x001F",

	"index:11",
	"GUID=00020329-0000-0000-c000-000000000046,NAME=DRMServerLicenseCompressed,TYPE=0x0102",

	"index:12",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33283,TYPE=0x0003",
	"LID=33282,TYPE=0x0040",
	"LID=33281,TYPE=0x0003",
	"LID=33284,TYPE=0x0003",
	"LID=33321,TYPE=0x000B",
	"GUID=6ed8da90-450b-101b-98da-00aa003f1305,LID=26,TYPE=0x0040",

	"index:13",
	"0x0C17000B",
	"0x0063000B",

	"index:14",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33328,TYPE=0x001F",
	"LID=33312,TYPE=0x0040",
	"GUID=6ed8da90-450b-101b-98da-00aa003f1305,LID=1,TYPE=0x0040",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33304,TYPE=0x0003",

	"index:15",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33299,TYPE=0x0003",
	"LID=33294,TYPE=0x0040",
	"LID=33293,TYPE=0x0040",
	"LID=33301,TYPE=0x000B",
	"LID=33334,TYPE=0x0040",
	"LID=33333,TYPE=0x0040",
	"LID=33330,TYPE=0x001F",
	"LID=33315,TYPE=0x000B",
	"LID=33329,TYPE=0x0003",
	"GUID=6ed8da90-450b-101b-98da-00aa003f1305,LID=34,TYPE=0x001F",

	"index:16",
	"GUID=00062008-0000-0000-c000-000000000046,LID=33325,TYPE=0x0040",
	"LID=33324,TYPE=0x0003",

	"index:17",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33302,TYPE=0x0102",

	"index:18",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33288,TYPE=0x001F",
	"GUID=6ed8da90-450b-101b-98da-00aa003f1305,LID=40,TYPE=0x001F",
	"LID=2,TYPE=0x001F",

	"index:19",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33287,TYPE=0x0003",
	"LID=33303,TYPE=0x0003",
	"LID=33285,TYPE=0x0003",
	"LID=33316,TYPE=0x0003",
	"LID=33326,TYPE=0x001F",

	"index:20",
	"GUID=6ed8da90-450b-101b-98da-00aa003f1305,LID=12,TYPE=0x0003",
	"GUID=00062002-0000-0000-c000-000000000046,LID=33332,TYPE=0x001F",
	"LID=33331,TYPE=0x0102",

	"index:21",
	"0x30180102",
	"0x30190102",

	"index:22",
	"0x301F0040",
	"0x301E0003",
	"0x301C0040",
	"0x301D0003",
	"0x301A0003",
	"0x301B0102",

	"index:23",
	"0x30140102",

	"index:24",
	"GUID=11000e07-b51b-40d6-af21-caa85edab1d0,LID=6,TYPE=0x001F",
	"LID=5,TYPE=0x0102",
	"LID=14,TYPE=0x001F",
	"LID=11,TYPE=0x001F",
	"LID=21,TYPE=0x0003",
	"LID=13,TYPE=0x001F",
	"LID=12,TYPE=0x001F",
	"LID=22,TYPE=0x0003",
	"LID=20,TYPE=0x001F",
	"LID=15,TYPE=0x001F",
	"LID=17,TYPE=0x001F",
	"LID=16,TYPE=0x001F",
	"LID=8,TYPE=0x0040",
	"LID=23,TYPE=0x0102",
	"LID=7,TYPE=0x0102",
	"LID=9,TYPE=0x0040",
	"LID=10,TYPE=0x001F",
	"LID=19,TYPE=0x001F",
	"LID=18,TYPE=0x001F",
	nullptr,
};

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

static errno_t mcg_loadfile(const char *const *thelines, uint32_t group_id)
{
	auto emp_res = g_group_list.emplace(group_id, indextotags_t{});
	if (!emp_res.second)
		return EEXIST;
	auto &index_list = emp_res.first->second;
	std::vector<tag_entry> *tag_list = nullptr;
	for (; *thelines != nullptr; ++thelines) {
		auto line = *thelines;
		if (strncasecmp(line, "index:", 6) == 0) {
			auto i = strtoul(&line[6], nullptr, 0);
			tag_list = &index_list.emplace(i, taglist_t{}).first->second;
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

errno_t msgchg_grouping_run() try
{
	auto err = mcg_loadfile(g_builtin_group_1, 1);
	if (err != 0)
		mlog(LV_ERR, "msgchggrp: group 1: %s", strerror(err));
	return g_group_list.size() != 0 ? err : errno_t{ENOENT};
} catch (const std::bad_alloc &) {
	mlog(LV_ERR, "E-1493: ENOMEM");
	return ENOMEM;
}

uint32_t msgchg_grouping_get_last_group_id()
{
	return g_group_list.size() > 0 ? g_group_list.rbegin()->first : 0;
}

std::unique_ptr<property_groupinfo>
    msgchg_grouping_get_groupinfo(get_named_propid_t get_named_propid,
    void *store, uint32_t group_id) try
{
	auto group_iter = g_group_list.find(group_id);
	if (group_iter == g_group_list.end())
		return NULL;
	auto info = std::make_unique<property_groupinfo>(group_id);
	for (const auto &[index, raw_tags] : group_iter->second) {
		auto resolved_tags = proptag_array_init();
		for (const auto &node : raw_tags) {
			uint32_t tag = node.proptag;
			if (PROP_ID(tag) == 0) {
				uint16_t propid = 0;
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

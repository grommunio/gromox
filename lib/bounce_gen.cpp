// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <string>
#include <gromox/bounce_gen.hpp>
#include <gromox/element_data.hpp>
#include <gromox/mapidefs.h>
#include <gromox/mapitags.hpp>

namespace gromox {

std::string bounce_gen_rcpts(const tarray_set &rcpts, const char *sep)
{
	std::string r;
	for (size_t i = 0; i < rcpts.count; ++i) {
		auto str = rcpts.pparray[i]->get<const char>(PR_SMTP_ADDRESS);
		if (str == nullptr)
			continue;
		if (!r.empty() && sep != nullptr)
			r += sep;
		r += str;
	}
	return r;
}

std::string bounce_gen_attachs(const ATTACHMENT_LIST &at, const char *sep)
{
	std::string r;
	for (size_t i = 0; i < at.count; ++i) {
		auto str = at.pplist[i]->proplist.get<const char>(PR_ATTACH_LONG_FILENAME);
		if (str == nullptr)
			continue;
		if (!r.empty() && sep != nullptr)
			r += sep;
		r += str;
	}
	return r;
}

}

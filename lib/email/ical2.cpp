// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <optional>
#include <string>
#include <gromox/ical.hpp>

bool ical_append_subval(ICAL_VALUE *pivalue, const char *subval)
{
	try {
		if (subval == nullptr)
			pivalue->subval_list.emplace_back();
		else
			pivalue->subval_list.emplace_back(std::make_optional<std::string>(subval));
		return true;
	} catch (...) {
		return false;
	}
}

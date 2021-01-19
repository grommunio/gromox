// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cstring>
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

const char *ical_get_first_paramval(ICAL_LINE *piline, const char *name)
{
	auto it = std::find_if(piline->param_list.cbegin(), piline->param_list.cend(),
	          [=](const auto &e) { return strcasecmp(e->name.c_str(), name) == 0; });
	if (it == piline->param_list.cend())
		return nullptr;
	auto piparam = (*it).get();
	if (piparam->paramval_list.size() != 1)
		return nullptr;
	return piparam->paramval_list.front().c_str();
}

std::shared_ptr<ICAL_PARAM> ical_new_param(const char *name)
{
	try {
		auto p = std::make_shared<ICAL_PARAM>();
		p->name = name;
		return p;
	} catch (...) {
	}
	return nullptr;
}

std::shared_ptr<ICAL_VALUE> ical_new_value(const char *name)
{
	try {
		auto v = std::make_shared<ICAL_VALUE>();
		if (name != nullptr)
			v->name = name;
		return v;
	} catch (...) {
	}
	return nullptr;
}

int ical_append_param(ICAL_LINE *l, std::shared_ptr<ICAL_PARAM> p)
{
	try {
		l->param_list.push_back(std::move(p));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

int ical_append_value(ICAL_LINE *l, std::shared_ptr<ICAL_VALUE> v)
{
	try {
		l->value_list.push_back(std::move(v));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

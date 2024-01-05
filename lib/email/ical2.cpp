// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <gromox/defs.h>
#include <gromox/ical.hpp>

const char *ICAL_LINE::get_first_paramval(const char *name) const
{
	auto it = std::find_if(param_list.cbegin(), param_list.cend(),
	          [=](const auto &e) { return strcasecmp(e.name.c_str(), name) == 0; });
	if (it == param_list.cend())
		return nullptr;
	auto &piparam = *it;
	if (piparam.paramval_list.size() != 1)
		return nullptr;
	return piparam.paramval_list.front().c_str();
}

const ical_line *ical_component::get_line(const char *name) const
{
	for (const auto &l : line_list)
		if (strcasecmp(l.m_name.c_str(), name) == 0)
			return &l;
	return nullptr;
}

ical_line::ical_line(const char *name, const char *value) :
	m_name(name)
{
	auto &pivalue = append_value();
	pivalue.append_subval(value);
}

ical_line::ical_line(const char *name, std::string &&value) :
	m_name(name)
{
	auto &pivalue = append_value();
	pivalue.append_subval(std::move(value));
}

void ical_line::append_param(const char *tag, const char *s)
{
	ical_param p(tag);
	p.append_paramval(s);
	append_param(std::move(p));
}

/**
 * @tag may be nullptr.
 */
void ical_line::append_value(const char *tag, const char *s)
{
	ical_value v(tag);
	v.append_subval(s);
	append_value(std::move(v));
}

/**
 * @tag may be nullptr.
 */
void ical_line::append_value(const char *tag, std::string &&s)
{
	ical_value v(tag);
	v.append_subval(std::move(s));
	append_value(std::move(v));
}

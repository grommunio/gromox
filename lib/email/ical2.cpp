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

const char *ICAL_LINE::get_first_paramval(const char *name)
{
	auto it = std::find_if(param_list.cbegin(), param_list.cend(),
	          [=](const auto &e) { return strcasecmp(e->name.c_str(), name) == 0; });
	if (it == param_list.cend())
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

int ICAL_LINE::append_param(std::shared_ptr<ICAL_PARAM> p)
{
	try {
		param_list.push_back(std::move(p));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

int ICAL_LINE::append_value(std::shared_ptr<ICAL_VALUE> v)
{
	try {
		value_list.push_back(std::move(v));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

int ICAL_COMPONENT::append_line(std::shared_ptr<ICAL_LINE> l)
{
	try {
		line_list.push_back(std::move(l));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

std::shared_ptr<ICAL_LINE> ical_new_line(const char *name)
{
	try {
		auto l = std::make_shared<ICAL_LINE>();
		l->m_name = name;
		return l;
	} catch (...) {
	}
	errno = ENOMEM;
	return nullptr;
}

std::shared_ptr<ICAL_LINE> ICAL_COMPONENT::get_line(const char *name)
{
	for (auto l : line_list)
		if (strcasecmp(l->m_name.c_str(), name) == 0)
			return l;
	return nullptr;
}

int ICAL_COMPONENT::append_comp(std::shared_ptr<ICAL_COMPONENT> c)
{
	try {
		component_list.push_back(std::move(c));
		return 0;
	} catch (...) {
	}
	return -ENOMEM;
}

void ical_line::append_param(const char *tag, const char *s)
{
	auto p = ical_new_param(tag);
	if (p == nullptr)
		throw std::bad_alloc();
	p->append_paramval(s);
	if (append_param(p) != 0)
		throw std::bad_alloc();
}

/**
 * @tag may be nullptr.
 */
void ical_line::append_value(const char *tag, const char *s)
{
	auto v = ical_new_value(tag);
	if (v == nullptr)
		throw std::bad_alloc();
	v->append_subval(s);
	if (append_value(v) != 0)
		throw std::bad_alloc();
}

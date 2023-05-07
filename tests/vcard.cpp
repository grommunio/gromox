// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
#include <cstring>
#include <utility>
#include <gromox/ical.hpp>
#include <gromox/vcard.hpp>

static void t_card()
{
	vcard C;
	auto &l = C.append_line("ADR");
	l.append_param("TYPE", "WORK");
	vcard_value v;
	v.append_subval("HOME");
	v.append_subval("HOME2");
	l.append_value(std::move(v));
	v = {};
	v.append_subval("DO");
	v.append_subval("DO2");
	l.append_value(std::move(v));

	char buf[128000];
	if (!C.serialize(buf, std::size(buf)))
		printf("ERROR\n");
	else
		printf("%s\n", buf);
	C.clear();
	C.load_single_from_str_move(buf);
	if (!C.serialize(buf, std::size(buf)))
		printf("ERROR\n");
	else
		printf("%s\n", buf);

	strcpy(buf, "BEGIN:VCARD\n\nEND:VCARD\n");
	C.load_single_from_str_move(buf);
}

static void t_ical()
{
	printf("ical:\n");
	ical ic;
	auto &c = ic.append_comp("COMPX");
	auto &l = c.append_line("KEY", "VALUE1");
	auto &v = l.append_value();
	v.append_subval("SUBVAL");
	v.append_subval("SUBVAL");

	char buf[4096];
	ic.serialize(buf, std::size(buf));
	printf("%s\n", buf);
}

int main()
{
	t_card();
	t_ical();
	return EXIT_SUCCESS;
}

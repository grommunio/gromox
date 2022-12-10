// SPDX-License-Identifier: AGPL-3.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <gromox/defs.h>
#include <gromox/html.hpp>
#include <gromox/mail_func.hpp>
#include <gromox/oxcmail.hpp>
#include <gromox/rtf.hpp>
#include <gromox/rtfcp.hpp>
#include <gromox/tie.hpp>

using namespace gromox;

static void help()
{
	std::cout << "Usage: bodyconv {texttohtml|htmltortf|rtfcptortf|rtftohtml|htmltotext}" << std::endl;
	std::cout << "       Will read from stdin and output to stdout" << std::endl;
}

int main(int argc, const char **argv)
{
	if (argc < 2) {
		help();
		return EXIT_FAILURE;
	}
	html_init_library();
	rtf_init_library();
	std::string all;
	char buf[4096];
	ssize_t have_read;
	while ((have_read = read(STDIN_FILENO, buf, sizeof(buf))) > 0)
		all += std::string_view(buf, have_read);
	if (strcmp(argv[1], "texttohtml") == 0) {
		std::unique_ptr<char[], stdlib_delete> out(plain_to_html(all.c_str()));
		if (out != nullptr)
			std::cout << out.get() << std::endl;
	} else if (strcmp(argv[1], "htmltotext") == 0) {
		std::string out;
		if (html_to_plain(all.c_str(), all.size(), out) >= 0)
			std::cout << out << std::endl;
	} else if (strcmp(argv[1], "htmltortf") == 0) {
		std::unique_ptr<char[], stdlib_delete> out;
		size_t outlen = 0;
		if (html_to_rtf(all.c_str(), all.size(), CP_UTF8, &unique_tie(out), &outlen))
			std::cout << std::string_view(out.get(), outlen) << std::endl;
	} else if (strcmp(argv[1], "rtftohtml") == 0) {
		auto at = attachment_list_init();
		size_t outlen = 0;
		std::unique_ptr<char[], stdlib_delete> out;
		if (rtf_to_html(all.c_str(), all.size(), "utf-8", &unique_tie(out), &outlen, at))
			std::cout << std::string_view(out.get(), outlen) << std::endl;
	} else if (strcmp(argv[1], "rtfcptortf") == 0) {
		BINARY rtf_comp;
		rtf_comp.cb = all.size();
		rtf_comp.pv = deconst(all.c_str());
		auto unc_size = rtfcp_uncompressed_size(&rtf_comp);
		if (unc_size == -1) {
			fprintf(stderr, "Bad header magic, or data stream is shorter than the header says it should be.\n");
			return EXIT_FAILURE;
		}
		if (unc_size > 0) {
			std::string unc_data;
			unc_data.resize(unc_size);
			size_t unc_size2 = unc_size;
			if (rtfcp_uncompress(&rtf_comp, &unc_data[0], &unc_size2)) {
				unc_data.resize(unc_size2);
				std::cout << std::move(unc_data) << std::endl;
			}
		}
	} else {
		help();
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <libHX/scope.hpp>
#include <gromox/svc_loader.hpp>

using namespace gromox;

static constexpr generic_module g_dfl_svc_plugins[] = {{"dnsbl_filter", SVC_dnsbl_filter}};

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: dnsbl_check ipaddr[...]\n");
		return EXIT_FAILURE;
	}
	service_init({nullptr, g_dfl_svc_plugins, 1});
	auto cl_1 = HX::make_scope_exit(service_stop);
	if (service_run_early() != 0 || service_run() != 0) {
		fprintf(stderr, "service_run: failed\n");
		return EXIT_FAILURE;
	}
	bool (*judge)(const char *host, std::string &reason);
	judge = reinterpret_cast<decltype(judge)>(service_query("ip_filter_judge", "system", typeid(*judge)));
	for (int i = 1; i < argc; ++i) {
		if (strchr(argv[i], ':') == nullptr) {
			fprintf(stderr, "\"%s\" not recognized. Must use IPv6 address format (RFC 4291 §2.2)\n", argv[i]);
			return EXIT_FAILURE;
		}
		std::string reason;
		if (judge(argv[i], reason))
			printf("PASS\n");
		else
			printf("REJECTED: %s\n", reason.c_str());
	}
	service_release("ip_filter_judge", "system");
	return EXIT_SUCCESS;
}

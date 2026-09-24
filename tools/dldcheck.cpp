// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025-2026 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <libHX/scope.hpp>
#include <sys/stat.h>
#undef EXIT_FAILURE
#define EXIT_FAILURE 2

static std::string la_to_so_simple(std::string file)
{
	auto z = file.size();
	if (z >= 3 && file.compare(z - 3, z, ".la") == 0) {
		file.replace(z - 3, 3, ".so");
		auto pos = file.find_last_of('/');
		file.insert(pos != file.npos ? pos + 1 : 0, ".libs/");
	}
	return file;
}

static std::string la_to_so(const char *la_file)
{
	char *dlname = nullptr;
	auto cl_0 = HX::make_scope_exit([&]() { free(dlname); });
	const struct HXoption directives[] = {
		{"dlname", 0, HXTYPE_STRING, &dlname},
		HXOPT_TABLEEND,
	};
	auto ret = HX_shconfig(la_file, directives);
	if (ret <= 0 || dlname == nullptr)
		return la_to_so_simple(la_file);
	return dlname;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;
	auto stamp = argv[1];
	for (argv += 2; *argv != nullptr; ++argv) {
		auto file = la_to_so(*argv);
		auto h = dlopen(file.c_str(), RTLD_NOW);
		if (h == nullptr) {
			fprintf(stderr, "dlopen %s: %s\n", file.c_str(), dlerror());
			return EXIT_FAILURE;
		}
#if !defined(__sun)
		/*
		 * Crash on Solaris ld.so: It does not know STB_GNU_UNIQUE,
		 * so libraries get unloaded even in the face of registered
		 * global destructors.  That triggers a crash at the end of
		 * main().
		 */
		dlclose(h);
#endif
	}
	auto fd = open(stamp, O_CREAT | O_WRONLY | O_TRUNC, S_IRUGO | S_IWUGO);
	if (fd < 0)
		return EXIT_FAILURE;
	close(fd);
	return EXIT_SUCCESS;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <sys/stat.h>
#undef EXIT_FAILURE
#define EXIT_FAILURE 2

int main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;
	auto stamp = argv[1];
	for (argv += 2; *argv != nullptr; ++argv) {
		auto file = *argv;
		auto z = strlen(file);
		auto so = z >= 3 && strcmp(&file[z-3], ".la") == 0 ?
		          std::string(HX_dirname(file)) + "/.libs/" +
		          std::string(file, z - 3) + ".so" : std::string(file);
		auto h = dlopen(so.c_str(), RTLD_NOW);
		if (h == nullptr) {
			fprintf(stderr, "dlopen %s: %s\n", so.c_str(), dlerror());
			return EXIT_FAILURE;
		}
		dlclose(h);
	}
	auto fd = open(stamp, O_CREAT | O_WRONLY, S_IRUGO | S_IWUGO);
	if (fd < 0)
		return EXIT_FAILURE;
	close(fd);
	return EXIT_SUCCESS;
}

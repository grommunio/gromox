// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2023 grommunio GmbH
// This file is part of Gromox.
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <libHX/defs.h>
#include <sys/stat.h>
#undef EXIT_FAILURE
#define EXIT_FAILURE 2

int main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;
	auto stamp = argv[1];
	for (argv += 2; *argv != nullptr; ++argv) {
		std::string file = *argv;
		auto z = file.size();
		if (z >= 3 && file.compare(z - 3, z, ".la") == 0) {
			file.replace(z - 3, 3, ".so");
			auto pos = file.find_last_of('/');
			file.insert(pos != file.npos ? pos + 1 : 0, ".libs/");
		}
		auto h = dlopen(file.c_str(), RTLD_NOW);
		if (h == nullptr) {
			fprintf(stderr, "dlopen %s: %s\n", file.c_str(), dlerror());
			return EXIT_FAILURE;
		}
		dlclose(h);
	}
	auto fd = open(stamp, O_CREAT | O_WRONLY | O_TRUNC, S_IRUGO | S_IWUGO);
	if (fd < 0)
		return EXIT_FAILURE;
	close(fd);
	return EXIT_SUCCESS;
}

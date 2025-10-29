// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 grommunio GmbH
// This file is part of Gromox.
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/io.h>
#include <gromox/defs.h>
#include <gromox/util.hpp>
using namespace gromox;
int main(int argc, char **argv)
{
	size_t size = 0;
	std::unique_ptr<char[], stdlib_delete> buf(HX_slurp_fd(STDIN_FILENO, &size));
	if (buf == nullptr)
		return EXIT_FAILURE;
	utf8_filter(buf.get());
	auto z = strlen(buf.get());
	auto ret = HXio_fullwrite(STDOUT_FILENO, buf.get(), z);
	if (ret < 0 || static_cast<size_t>(ret) != z)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}

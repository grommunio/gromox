// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grammm GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <gromox/fileio.h>

namespace gromox {

std::vector<std::string> gx_split(const std::string_view &sv, char sep)
{
	size_t start = 0, pos;
	std::vector<std::string> out;
	while ((pos = sv.find(sep, start)) != sv.npos) {
		out.push_back(std::string(sv.substr(start, pos - start)));
		start = pos + 1;
	}
	out.push_back(std::string(sv.substr(start)));
	return out;
}

std::unique_ptr<FILE, file_deleter> fopen_sd(const char *filename, const char *sdlist)
{
	if (sdlist == nullptr || strchr(filename, '/') != nullptr)
		return std::unique_ptr<FILE, file_deleter>(fopen(filename, "r"));
	try {
		for (auto dir : gx_split(sdlist, ':')) {
			errno = 0;
			auto full = dir + "/" + filename;
			std::unique_ptr<FILE, file_deleter> fp(fopen(full.c_str(), "r"));
			if (fp != nullptr)
				return fp;
			if (errno != ENOENT) {
				fprintf(stderr, "fopen_sd %s: %s\n",
				        full.c_str(), strerror(errno));
				return nullptr;
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	return nullptr;
}

}

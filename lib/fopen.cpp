// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <gromox/fileio.h>
#include <gromox/util.hpp>

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

DIR_mp opendir_sd(const char *dirname, const char *sdlist)
{
	DIR_mp dn;
	if (sdlist == nullptr || strchr(dirname, '/') != nullptr) {
		dn.m_path = dirname;
		dn.m_dir.reset(opendir(dirname));
		return dn;
	}
	for (auto &&dir : gx_split(sdlist, ':')) {
		errno = 0;
		dn.m_path = std::move(dir) + "/" + dirname;
		dn.m_dir.reset(opendir(dn.m_path.c_str()));
		if (dn.m_dir != nullptr)
			return dn;
		if (errno != ENOENT) {
			mlog(LV_ERR, "opendir_sd %s: %s",
			        dn.m_path.c_str(), strerror(errno));
			return dn;
		}
	}
	dn.m_path.clear();
	return dn;
}

std::unique_ptr<FILE, file_deleter> fopen_sd(const char *filename, const char *sdlist)
{
	if (sdlist == nullptr || strchr(filename, '/') != nullptr)
		return std::unique_ptr<FILE, file_deleter>(fopen(filename, "r"));
	try {
		for (auto &&dir : gx_split(sdlist, ':')) {
			errno = 0;
			auto full = std::move(dir) + "/" + filename;
			std::unique_ptr<FILE, file_deleter> fp(fopen(full.c_str(), "r"));
			if (fp != nullptr)
				return fp;
			if (errno != ENOENT) {
				mlog(LV_ERR, "fopen_sd %s: %s",
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

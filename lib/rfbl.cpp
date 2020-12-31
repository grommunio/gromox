// SPDX-License-Identifier: AGPL-3.0-or-later, OR GPL-2.0-or-later WITH linking exception
// SPDX-FileCopyrightText: 2020 grammm GmbH
// This file is part of Gromox.
#include <list>
#include <memory>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <libHX/string.h>
#include <gromox/fileio.h>
#include <gromox/tie.hpp>

class file_deleter {
	public:
	void operator()(FILE *fp) { fclose(fp); }
};

class hxmc_deleter {
	public:
	void operator()(hxmc_t *s) { HXmc_free(s); }
};

using namespace gromox;

char **read_file_by_line(const char *file)
{
	std::unique_ptr<FILE, file_deleter> fp(fopen(file, "r"));
	if (fp == nullptr)
		return nullptr;

	hxmc_t *line = nullptr;
	try {
		std::list<std::unique_ptr<char[]>> dq;
		while (HX_getl(&line, fp.get()) != nullptr) {
			HX_chomp(line);
			decltype(dq)::value_type s(strdup(line));
			if (s == nullptr)
				return nullptr;
			dq.push_back(std::move(s));
		}
		HXmc_free(line);
		line = nullptr;
		auto ret = std::make_unique<char *[]>(dq.size() + 1);
		size_t i = 0;
		for (auto &e : dq)
			ret[i++] = e.release();
		return ret.release();
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	} catch (...) {
		HXmc_free(line);
		throw;
	}
}

int gx_vsnprintf1(char *buf, size_t sz, const char *file, unsigned int line,
    const char *fmt, va_list args)
{
	auto ret = vsnprintf(buf, sz, fmt, args);
	if (ret >= sz) {
		fprintf(stderr, "gx_snprintf: truncation at %s:%u (%d bytes into buffer of %zu)\n",
		        file, line, ret, sz);
		return strlen(buf);
	} else if (ret < 0) {
		*buf = '\0';
		return ret;
	}
	return ret;
}

int gx_snprintf1(char *buf, size_t sz, const char *file, unsigned int line,
    const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	auto ret = gx_vsnprintf1(buf, sz, file, line, fmt, args);
	va_end(args);
	return ret;
}

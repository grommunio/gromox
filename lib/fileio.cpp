#include <list>
#include <memory>
#include <cerrno>
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

	try {
		std::unique_ptr<char, hxmc_deleter> line;
		std::list<std::unique_ptr<char>> dq;
		while (HX_getl(&unique_tie(line), fp.get()) != nullptr) {
			decltype(dq)::value_type s(strdup(line.get()));
			if (s == nullptr)
				return nullptr;
			dq.push_back(std::move(s));
		}
		auto ret = std::make_unique<char *[]>(dq.size() + 1);
		size_t i = 0;
		for (auto &e : dq)
			ret[i++] = e.release();
		return ret.release();
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
}

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

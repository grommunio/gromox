#include <cstdio>
#include <cstring>
#include <string>
#include <cstdlib>
#include <gromox/ical.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/oxcical.hpp>
#include <gromox/scope.hpp>

using namespace gromox;

static std::string slurp_file(FILE *f)
{
	std::string outstr;
	char buf[4096];
	while (!feof(f)) {
		auto rd = fread(buf, 1, sizeof(buf), f);
		if (ferror(f))
			return outstr;
		outstr.append(buf, rd);
	}
	return outstr;
}

static std::string slurp_file(const char *file)
{
	std::string data;
	if (file == nullptr)
		return slurp_file(stdin);
	auto fp = fopen(file, "r");
	if (fp == nullptr) {
		fprintf(stderr, "open %s: %s", file, strerror(errno));
		return data;
	}
	auto cleanfp = make_scope_exit([&]() { fclose(fp); });
	return slurp_file(fp);
}

static BOOL get_propids(const PROPNAME_ARRAY *pn, PROPID_ARRAY *id)
{
	id->count = pn->count;
	id->ppropid = new uint16_t[id->count]{1};
	return TRUE;
}

static BOOL un_to_eid(const char *username, const char *dispname, BINARY *bv, int *adrtype)
{
	bv->pc = strdup(username);
	bv->cb = strlen(username);
	return TRUE;
}

int main(int argc, const char **argv)
{
	auto data = slurp_file(argc >= 2 ? argv[1] : nullptr);
	ICAL ical;
	ical_init(&ical);
	if (!ical_retrieve(&ical, data.data()))
		printf("BAD retrieve\n");
	auto msg = oxcical_import("UTC", &ical, malloc, get_propids, un_to_eid);
	if (msg == nullptr)
		printf("BAD import\n");
	return 0;
}

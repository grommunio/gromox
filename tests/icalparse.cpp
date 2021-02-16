#include <cstdio>
#include <cstring>
#include <string>
#include <cstdlib>
#include <gromox/fileio.h>
#include <gromox/ical.hpp>
#include <gromox/mapi_types.hpp>
#include <gromox/oxcical.hpp>
#include <gromox/scope.hpp>

using namespace gromox;

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

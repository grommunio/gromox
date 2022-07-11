#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <libHX/io.h>
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

static BOOL un_to_eid(const char *username, const char *dispname, BINARY *bv,
    enum display_type *)
{
	bv->pc = strdup(username);
	bv->cb = strlen(username);
	return TRUE;
}

int main(int argc, const char **argv)
{
	std::unique_ptr<char[], stdlib_delete> data;
	if (argc >= 2) {
		data.reset(HX_slurp_file(argv[1], nullptr));
		if (data == nullptr) {
			fprintf(stderr, "Error reading %s: %s\n", argv[1], strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		data.reset(HX_slurp_fd(STDIN_FILENO, nullptr));
		if (data == nullptr) {
			fprintf(stderr, "Error reading from stdin: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
	ICAL ical;
	if (ical.init() < 0) {
		printf("BAD ical_init\n");
		return EXIT_FAILURE;
	}
	if (!ical.retrieve(data.get()))
		printf("BAD retrieve\n");
	std::vector<std::unique_ptr<MESSAGE_CONTENT, mc_delete>> msgvec;
	if (!oxcical_import_multi("UTC", &ical, malloc, get_propids, un_to_eid, msgvec))
		printf("BAD import\n");
	printf("%zu logical events present\n", msgvec.size());
	return 0;
}

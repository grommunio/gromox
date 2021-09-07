#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <gromox/util.hpp> 
using namespace gromox;
static int t_interval()
{
	const char *in = " 1 d 1 h 1 m 1 s ";
	long exp = 86400 + 3600 + 60 + 1;
	auto got = atoitvl(in);
	if (got != exp) {
		printf("IN \"%s\" EXP %ld GOT %ld\n", in, exp, got);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
int main()
{
	auto ret = t_interval();
	if (ret != EXIT_SUCCESS)
		return ret;
}

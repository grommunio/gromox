#include <stdio.h>
#include <stdlib.h>
#include <gromox/resolv.h>
#include <libHX/misc.h>

int main(void)
{
	char **vec = NULL;
	int hosts = gx_getmxbyname("google.com", &vec);
	if (hosts < 0)
		perror("gx_getmxbyname");
	for (int i = 0; i < hosts; ++i)
		printf("%s\n", vec[i]);
	HX_zvecfree(vec);
	return EXIT_SUCCESS;
}

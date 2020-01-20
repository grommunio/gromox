#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <resolv.h>
#include <libHX/misc.h>
#include <gromox/resolv.h>

struct mx_entry {
	uint16_t prio;
	char *host;
};

static int getmx_make_request(const char *domain, unsigned char **answer, size_t *answ_size)
{
	struct __res_state state;
	if (res_ninit(&state) != 0)
		return -h_errno;
	*answ_size = 1 << 10;
	*answer = malloc(*answ_size);
	if (*answer == NULL)
		return -errno;
	while (true) {
		int ret = res_nsearch(&state, domain, ns_c_in, ns_t_mx, *answer, *answ_size);
		if (ret < 0)
			return -h_errno;
		if (ret <= *answ_size) {
			*answ_size = ret;
			break;
		}
		if (*answ_size >= (64 << 10))
			return -ERANGE;
		unsigned char *xnew = realloc(*answer, *answ_size *= 2);
		if (xnew == NULL)
			return -errno;
		*answer = xnew;
	}
	return 0;
}

static int getmx_extract_rr(unsigned char *answer, size_t answ_size,
    char ***mxlist)
{
	ns_msg ns_handle;
	ssize_t ret = ns_initparse(answer, answ_size, &ns_handle);
	if (ret < 0)
		return -h_errno;
	int records = ns_msg_count(ns_handle, ns_s_an);
	if (records < 0)
		return -h_errno;
	*mxlist = malloc((records + 1) * sizeof(**mxlist));
	if (*mxlist == NULL)
		return -errno;

	size_t current = 0;
	for (unsigned int i = 0; i < records; ++i) {
		ns_rr rr;
		ret = ns_parserr(&ns_handle, ns_s_an, i, &rr);
		if (ret < 0)
			continue;
		if (ns_rr_rdlen(rr) < NS_INT16SZ)
			continue;

		const unsigned char *rdata = ns_rr_rdata(rr);
		char buf[NS_MAXDNAME+1];
		ret = ns_name_uncompress(answer, answer + answ_size, rdata + NS_INT16SZ, buf, sizeof(buf));
		if (ret < 0)
			continue;
		buf[sizeof(buf)-1] = '\0';
		char *e = mxlist[0][current] = malloc(strlen(buf) + 1 + sizeof(uint16_t));
		if (e == NULL)
			return -errno;
		++current;
		memcpy(e, buf, strlen(buf) + 1);
		memcpy(e + strlen(buf) + 1, rdata, sizeof(uint16_t));
	}
	return current;
}

static int getmx_sort(const void *a, const void *b)
{
	const char *const *f = a, *const *g = b;
	uint16_t x, y;
	memcpy(&x, *f + strlen(*f) + 1, sizeof(x));
	memcpy(&y, *g + strlen(*g) + 1, sizeof(y));
	x = ntohs(x);
	y = ntohs(y);
	return x == y ? 0 : x < y ? -1 : 1;
}

int gx_getmxbyname(const char *domain, char ***vec)
{
	unsigned char *answer = NULL;
	size_t answ_size = 0;
	int ret = getmx_make_request(domain, &answer, &answ_size);
	if (ret < 0) {
		free(answer);
		return ret;
	}
	ret = getmx_extract_rr(answer, answ_size, vec);
	free(answer);
	if (ret < 0 && *vec != NULL)
		HX_zvecfree(*vec);
	else if (ret > 0)
		qsort(*vec, ret, sizeof(**vec), getmx_sort);
	return ret;
}

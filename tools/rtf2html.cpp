// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <unistd.h>
#include <libHX/option.h>
#include <gromox/list_file.hpp>
#include <gromox/paths.h>
#include <gromox/rtf.hpp>
#include <gromox/rtfcp.hpp>

namespace {

struct srcitem {
	unsigned int cpid;
	char s[64];
};

}

static std::unique_ptr<LIST_FILE> g_list_file;
static unsigned int opt_show_version;

static struct HXoption g_options_table[] = {
	{"version", 0, HXTYPE_NONE, &opt_show_version, nullptr, nullptr, 0, "Output version information and exit"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

int main(int argc, const char **argv)
{
	int offset;
	int read_len;
	int buff_len;
	BINARY rtf_bin;
	size_t tmp_len;
	ATTACHMENT_LIST *pattachments;
	
	setvbuf(stdout, nullptr, _IOLBF, 0);
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_show_version) {
		printf("version: %s\n", PACKAGE_VERSION);
		return 0;
	}
	offset = 0;
	buff_len = 64*1024;
	auto pbuff = gromox::me_alloc<char>(buff_len);
	if (NULL == pbuff) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	while ((read_len = read(STDIN_FILENO, pbuff, buff_len - offset)) > 0) {
		offset += read_len;
		if (offset == buff_len) {
			buff_len *= 2;
			auto nb = gromox::re_alloc<char>(pbuff, buff_len);
			if (NULL == pbuff) {
				fprintf(stderr, "out of memory\n");
				return 1;
			}
			pbuff = nb;
		}
	}
	rtf_bin.pv = pbuff;
	rtf_bin.cb = offset;
	ssize_t unc_size = rtfcp_uncompressed_size(&rtf_bin);
	if (unc_size < 0) {
		fprintf(stderr, "Input does not appear to be RTFCP\n");
		return EXIT_FAILURE;
	}
	pbuff = gromox::me_alloc<char>(unc_size);
	if (NULL == pbuff) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	size_t rtf_len = unc_size;
	if (!rtfcp_uncompress(&rtf_bin, pbuff, &rtf_len)) {
		fprintf(stderr, "fail to uncompress rtf\n");
		return 2;
	}
	g_list_file = list_file_initd("cpid.txt", PKGDATADIR, "%d%s:64");
	if (NULL == g_list_file) {
		fprintf(stderr, "list_file_init %s: %s\n",
			PKGDATADIR "/cpid.txt", strerror(errno));
		return 3;
	}
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		return 1;
	}
	if (!rtf_init_library()) {
		fprintf(stderr, "Failed to init RTF library\n");
		return 4;
	}
	char *htmlout = nullptr;
	if (rtf_to_html(pbuff, rtf_len, "utf-8", &htmlout, &tmp_len, pattachments)) {
		write(STDOUT_FILENO, htmlout, tmp_len);
		free(htmlout);
		exit(0);
	} else {
		fprintf(stderr, "fail to convert rtf\n");
		return 5;
	}
}

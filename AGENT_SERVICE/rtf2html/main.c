#include "rtf.h"
#include "rtfcp.h"
#include <stdio.h>
#include <stdlib.h>

#define RTF2HTML_VERSION		"1.0"

int main(int argc, char **argv)
{
	int offset;
	char *pbuff;
	int read_len;
	int buff_len;
	BINARY rtf_bin;
	size_t rtf_len;
	size_t tmp_len;
	ATTACHMENT_LIST *pattachments;
	
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", RTF2HTML_VERSION);
		return 0;
	}
	offset = 0;
	buff_len = 64*1024;
	pbuff = malloc(buff_len);
	if (NULL == pbuff) {
		fprintf(stderr, "out of memory\n");
		exit(-1);
	}
	while ((read_len = read(stdin, pbuff, buff_len - offset)) > 0) {
		offset += read_len;
		if (offset == buff_len) {
			buff_len *= 2;
			pbuff = realloc(pbuff, buff_len);
			if (NULL == pbuff) {
				fprintf(stderr, "out of memory\n");
				exit(-1);
			}
		}
	}
	rtf_bin.pb = pbuff;
	rtf_bin.cb = offset;
	pbuff = malloc(8*buff_len + 1024*1024);
	if (NULL == pbuff) {
		fprintf(stderr, "out of memory\n");
		exit(-1);
	}
	if (FALSE == rtfcp_uncompress(&rtf_bin, pbuff, &rtf_len)) {
		fprintf(stderr, "fail to uncompress rtf\n");
		exit(-2);
	}
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		exit(-1);
	}
	if (TRUE == rtf_to_html(pbuff, rtf_len, "utf-8",
		pbuff + rtf_len, &tmp_len, pattachments)) {
		write(stdout, pbuff + rtf_len, tmp_len);
		exit(0);
	} else {
		fprintf(stderr, "fail to convert rtf\n");
		exit(-3);
	}
}

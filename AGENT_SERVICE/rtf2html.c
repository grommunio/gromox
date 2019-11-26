#include "rtf.h"
#include "rtfcp.h"
#include "list_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RTF2HTML_VERSION		"1.0"

static LIST_FILE *g_list_file;

static const char* cpid_to_charset_to(uint32_t cpid)
{
	void *pitem;
	int i, item_num;
	
	item_num = list_file_get_item_num(g_list_file);
	pitem = list_file_get_list(g_list_file);
	for (i=0; i<item_num; i++) {
		if (*(uint32_t*)(pitem + (64+sizeof(int))*i) == cpid) {
			return pitem + (64+sizeof(int))*i + sizeof(int);
		}
	}
	return "us-ascii";
}

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
	while ((read_len = read(STDIN_FILENO, pbuff, buff_len - offset)) > 0) {
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
	g_list_file = list_file_init("../data/cpid.txt", "%d%s:64");
	if (NULL == g_list_file) {
		fprintf(stderr, "fail to load list file cpid.txt\n");
		exit(-3);
	}
	pattachments = attachment_list_init();
	if (NULL == pattachments) {
		exit(-1);
	}
	if (FALSE == rtf_init_library(cpid_to_charset_to)) {
		fprintf(stderr, "fail to init rtf library\n");
		exit(-4);
	}
	tmp_len = 8*buff_len + 1024*1024 - rtf_len;
	if (TRUE == rtf_to_html(pbuff, rtf_len, "utf-8",
		pbuff + rtf_len, &tmp_len, pattachments)) {
		write(STDOUT_FILENO, pbuff + rtf_len, tmp_len);
		exit(0);
	} else {
		fprintf(stderr, "fail to convert rtf\n");
		exit(-5);
	}
}

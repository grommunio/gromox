#ifndef _H_URI_RBL_
#define _H_URI_RBL_
#include "common_types.h"

enum {
	URI_RBL_SURBL,
	URI_RBL_URIBL
};

void uri_rbl_init(const char *cctld_path, const char *surbl_dns,
	const char *uribl_dns);

void uri_rbl_free();

int uri_rbl_run();

int uri_rbl_stop();

BOOL uri_rbl_check_cctld(const char *domain);

BOOL uri_rbl_judge(const char *uri, char *answer_buff, int answer_len);

BOOL uri_rbl_refresh();

const char* uri_rbl_get_dns(int param);

#endif


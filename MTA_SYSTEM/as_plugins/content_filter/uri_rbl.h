#pragma once
#include "common_types.h"

enum {
	URI_RBL_SURBL,
	URI_RBL_URIBL
};

void uri_rbl_init(const char *cctld_path, const char *surbl_dns,
	const char *uribl_dns);
extern void uri_rbl_free(void);
extern int uri_rbl_run(void);
extern int uri_rbl_stop(void);
BOOL uri_rbl_check_cctld(const char *domain);

BOOL uri_rbl_judge(const char *uri, char *answer_buff, int answer_len);
extern BOOL uri_rbl_refresh(void);
const char* uri_rbl_get_dns(int param);

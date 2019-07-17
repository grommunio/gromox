#ifndef _H_DNS_RBL_
#define _H_DNS_RBL_
#include "common_types.h"

void dns_rbl_init(const char *path);

void dns_rbl_free();

int dns_rbl_run();

int dns_rbl_stop();

BOOL dns_rbl_judge(const char *ip, char *answer_buff, int answer_len);

BOOL dns_rbl_refresh();

#endif


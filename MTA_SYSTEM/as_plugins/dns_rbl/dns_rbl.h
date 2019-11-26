#ifndef _H_DNS_RBL_
#define _H_DNS_RBL_
#include "common_types.h"

void dns_rbl_init(const char *path);
extern void dns_rbl_free(void);
extern int dns_rbl_run(void);
extern int dns_rbl_stop(void);
BOOL dns_rbl_judge(const char *ip, char *answer_buff, int answer_len);
extern BOOL dns_rbl_refresh(void);

#endif


#pragma once
#include "common_types.h"

enum {
	ESMTP_AUTH_RETRYING_TIMES

};

void esmtp_auth_init(int retrying_times);
extern int esmtp_auth_run(void);
BOOL esmtp_auth_login(const char *username, const char *password, char *reason,
	int reason_len);
extern int esmtp_auth_stop(void);
extern void esmtp_auth_free(void);
int esmtp_auth_get_param(int param);

void esmtp_auth_set_param(int param, int value);

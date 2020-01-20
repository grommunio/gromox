#pragma once
#include "mail.h"

void domain_sign_init(const char *path);
extern int domain_sign_run(void);
void domain_sign_mark(const char *domain, MAIL *pmail);
extern int domain_sign_stop(void);
extern void domain_sign_free(void);
void domain_sign_console_talk(int argc, char **argv, char *result, int length);

#ifndef _H_DOMAIN_SIGN_
#define _H_DOMAIN_SIGN_
#include "mail.h"

void domain_sign_init(const char *path);

int domain_sign_run();

void domain_sign_mark(const char *domain, MAIL *pmail);

int domain_sign_stop();

void domain_sign_free();

void domain_sign_console_talk(int argc, char **argv, char *result, int length);

#endif

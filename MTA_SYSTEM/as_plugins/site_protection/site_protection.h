#ifndef _SITE_PROTECTION_H_
#define _SITE_PROTECTION_H_

enum {
	SITE_PROTECTION_NONE,
	SITE_PROTECTION_OK,
	SITE_PROTECTION_REJECT,
	SITE_PROTECTION_RETRY
};

void site_protection_init(const char *path);
extern int site_protection_run(void);
extern int site_protection_stop(void);
extern void site_protection_free(void);
int site_protection_verify(char* domain, char* ip);

void site_protection_console_talk(int argc, char **argv, char *result,
	int length);

#endif


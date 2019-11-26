#ifndef _H_DOMAIN_KEYWORD_
#define _H_DOMAIN_KEYWORD_
#include "common_types.h"
#include "mem_file.h"

void domain_keyword_init(int growing_num, const char *root_path);
extern int domain_keyword_run(void);
BOOL domain_keyword_check(const char *from, MEM_FILE *pf_rcpt_to,
	const char *charset, const char *buff, int length);
extern int domain_keyword_stop(void);
extern void domain_keyword_free(void);
void domain_keyword_console_talk(int argc, char **argv, char *result, int length);

#endif /* _H_DOMAIN_KEYWORD_ */

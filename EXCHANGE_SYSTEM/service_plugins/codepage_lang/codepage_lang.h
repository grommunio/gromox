#ifndef _H_CODEPAGE_LANG_
#define _H_CODEPAGE_LANG_

#ifdef __cplusplus
#	include <cstdint>
#else
#	include <stdint.h>
#endif
#include "common_types.h"

void codepage_lang_init(const char *path);
extern int codepage_lang_run(void);
extern int codepage_lang_stop(void);
extern void codepage_lang_free(void);
BOOL codepage_lang_get_lang(uint32_t codepage, const char *tag,
	char *value, int len);
extern BOOL codepage_lang_reload(void);

#endif /* _H_CODEPAGE_LANG_ */
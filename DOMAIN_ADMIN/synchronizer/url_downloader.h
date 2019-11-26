#ifndef _H_URL_DOWNLOADER_
#define _H_URL_DOWNLOADER_
#include "common_types.h"

extern void url_downloader_init(void);
extern int url_downloader_run(void);
BOOL url_downloader_get(const char *url, const char *save_path);
extern int url_downloader_stop(void);
extern void url_downloader_free(void);

#endif

#ifndef _H_URL_DOWNLOADER_
#define _H_URL_DOWNLOADER_
#include "common_types.h"

void url_downloader_init();

int url_downloader_run();

BOOL url_downloader_get(const char *url, const char *save_path);

int url_downloader_stop();

void url_downloader_free();

#endif

#ifndef _H_MEDIA_MIGRATOR_
#define _H_MEDIA_MIGRATOR_

void media_migrator_init(const char *area_path);

int media_migrator_run();

int media_migrator_stop();

void media_migrator_free();

#endif

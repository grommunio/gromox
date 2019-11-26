#ifndef _H_MEDIA_MIGRATOR_
#define _H_MEDIA_MIGRATOR_

void media_migrator_init(const char *area_path);
extern int media_migrator_run(void);
extern int media_migrator_stop(void);
extern void media_migrator_free(void);

#endif

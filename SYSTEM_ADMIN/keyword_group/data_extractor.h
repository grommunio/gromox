#ifndef _H_DATA_EXTRACTOR_
#define _H_DATA_EXTRACTOR_
#include <time.h>


void data_extractor_init(const char *path);
extern int data_extractor_run(void);
void data_extractor_retrieve(int *array, int array_num);
extern int data_extractor_stop(void);
extern void data_extractor_free(void);

#endif

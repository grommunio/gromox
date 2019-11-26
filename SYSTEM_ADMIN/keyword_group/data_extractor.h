#ifndef _H_DATA_EXTRACTOR_
#define _H_DATA_EXTRACTOR_
#include <time.h>


void data_extractor_init(const char *path);

int data_extractor_run();

void data_extractor_retrieve(int *array, int array_num);

int data_extractor_stop();

void data_extractor_free();

#endif

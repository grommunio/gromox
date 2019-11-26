#ifndef _H_RESOURCE_
#define _H_RESOURCE_
#include "common_types.h"
#include "string_table.h"

void resource_init(char* cfg_filename);

void resource_free();

int resource_run();

int resource_stop();

BOOL resource_save();

BOOL resource_get_integer(int key, int* value);

const char* resource_get_string(int key);

BOOL resource_set_integer(int key, int value);

BOOL resource_set_string(int key, char* value);


#endif /* _H_RESOURCE_ */

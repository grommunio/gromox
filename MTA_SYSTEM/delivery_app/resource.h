#ifndef _H_RESOURCE_
#define _H_RESOURCE_
#include "common_types.h"

extern void resource_init(const char *cfg1, const char *cfg2);
extern void resource_free(void);
extern int resource_run(void);
extern int resource_stop(void);
extern BOOL resource_save(void);
extern BOOL resource_get_integer(const char *key, int *value);
extern const char *resource_get_string(const char *key);
extern BOOL resource_set_integer(const char *key, int value);
extern BOOL resource_set_string(const char *key, const char *value);

#endif /* _H_RESOURCE_ */

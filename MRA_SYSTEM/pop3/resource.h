#pragma once
#include "common_types.h"

typedef struct _POP3_ERROR_CODE {
    int     code;
    char    comment[512];
} POP3_ERROR_CODE;

enum {
    POP3_CODE_2170000 = 0,
    POP3_CODE_2170001,
    POP3_CODE_2170002,
    POP3_CODE_2170003,
    POP3_CODE_2170004,
    POP3_CODE_2170005,
    POP3_CODE_2170006,
    POP3_CODE_2170007,
    POP3_CODE_2170008,
    POP3_CODE_2170009,
    POP3_CODE_2170010,
    POP3_CODE_2170011,
    POP3_CODE_2170012,
    POP3_CODE_2170013,
    POP3_CODE_2170014,
    POP3_CODE_2170015,
    POP3_CODE_2170016,
    POP3_CODE_2170017,
    POP3_CODE_2170018,
    POP3_CODE_2170019,
    POP3_CODE_2170020,
    POP3_CODE_2170021,
    POP3_CODE_2170022,
	POP3_CODE_2170023,
	POP3_CODE_2170024,
	POP3_CODE_2170025,
	POP3_CODE_2170026,
    POP3_CODE_COUNT
};

#ifdef __cplusplus
extern "C" {
#endif

extern void resource_init(const char *cfg1, const char *cfg2);
extern void resource_free(void);
extern int resource_run(void);
extern int resource_stop(void);
extern BOOL resource_save(void);
extern BOOL resource_get_integer(const char *key, int *value);
extern const char *resource_get_string(const char *key);
extern BOOL resource_set_integer(const char *key, int value);
extern BOOL resource_set_string(const char *key, const char *value);
char* resource_get_pop3_code(int code_type, int n, int *len);
extern BOOL resource_refresh_pop3_code_table(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

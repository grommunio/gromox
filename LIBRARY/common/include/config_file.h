#ifndef _H_CONFIG_FILE_
#define _H_CONFIG_FILE_

#include "common_types.h"

typedef struct _CONFIG_ENTRY {
    char keyname[256];
    char value[256];
	BOOL is_touched;
} CONFIG_ENTRY;

typedef struct _CONFIG_FILE {
    CONFIG_ENTRY *config_table;
    size_t num_entries;
	size_t total_entries;
	char file_name[256];
} CONFIG_FILE;


#ifdef __cplusplus
extern "C" {
#endif

extern CONFIG_FILE *config_file_init(const char *filename);
void config_file_free(CONFIG_FILE* cfg_file);
extern char *config_file_get_value(CONFIG_FILE *, const char *key);
extern BOOL config_file_set_value(CONFIG_FILE *, const char *key, const char *value);
BOOL config_file_save(CONFIG_FILE* cfg_file);



#ifdef __cplusplus
}
#endif


#endif /* _H_CONFIG_FILE_ */

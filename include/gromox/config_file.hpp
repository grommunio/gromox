#pragma once
#include <gromox/common_types.hpp>

struct CONFIG_ENTRY {
    char keyname[256];
    char value[256];
	BOOL is_touched;
};

struct CONFIG_FILE {
    CONFIG_ENTRY *config_table;
    size_t num_entries;
	size_t total_entries;
	char file_name[256];
};

extern char *config_default_path(const char *filename);
extern CONFIG_FILE *config_file_init(const char *filename);
extern CONFIG_FILE *config_file_init2(const char *ov, const char *fb);
void config_file_free(CONFIG_FILE* cfg_file);
extern char *config_file_get_value(CONFIG_FILE *, const char *key);
extern BOOL config_file_set_value(CONFIG_FILE *, const char *key, const char *value);
BOOL config_file_save(CONFIG_FILE* cfg_file);
extern BOOL config_file_get_int(CONFIG_FILE *, const char *key, int *);
extern BOOL config_file_set_int(CONFIG_FILE *, const char *key, int);

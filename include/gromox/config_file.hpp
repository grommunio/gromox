#pragma once
#include <memory>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define resource_get_string(k) g_config_file->get_value(k)
#define resource_set_string(k, v) g_config_file->set_value((k), (v))
#define resource_get_integer(k, vp) g_config_file->get_int((k), (vp))
#define resource_get_uint(k, vp) g_config_file->get_uint((k), (vp))
#define resource_set_integer(k, v) g_config_file->set_int((k), (v))

enum cfg_flags {
	CFG_BOOL = 1U << 0,
	CFG_SIZE = 1U << 1,
	CFG_TIME = 1U << 2,
};

struct cfg_directive {
	const char *key = nullptr, *deflt = nullptr;
	unsigned int flags = 0;
	const char *min = nullptr, *max = nullptr;
};

struct CONFIG_ENTRY {
    char keyname[256];
    char value[256];
	BOOL is_touched;
};

struct GX_EXPORT CONFIG_FILE {
	~CONFIG_FILE();
	GX_EXPORT const char *get_value(const char *key) const;
	GX_EXPORT BOOL set_value(const char *key, const char *value);
	GX_EXPORT BOOL save();
	GX_EXPORT BOOL get_int(const char *key, int *) const;
	GX_EXPORT BOOL get_uint(const char *key, unsigned int *) const;
	GX_EXPORT unsigned long long get_ll(const char *key) const;
	GX_EXPORT BOOL set_int(const char *key, int);

    CONFIG_ENTRY *config_table;
    size_t num_entries;
	size_t total_entries;
	char file_name[256];
};

extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_init(const char *filename);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_initd(const char *basename, const char *searchdirs = nullptr);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_prg(const char *priority_location, const char *fallback_location_basename);

namespace gromox {

extern void config_file_apply(CONFIG_FILE &, const cfg_directive *);

}

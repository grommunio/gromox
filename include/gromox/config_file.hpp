#pragma once
#include <exception>
#include <memory>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define resource_set_string(k, v) g_config_file->set_value((k), (v))
#define resource_get_integer(k, vp) g_config_file->get_int((k), (vp))
#define resource_get_uint(k, vp) g_config_file->get_uint((k), (vp))
#define resource_set_integer(k, v) g_config_file->set_int((k), (v))
#define CFG_TABLE_END {}

enum cfg_flags {
	CFG_BOOL = 0x1U,
	CFG_SIZE = 0x2U,
	CFG_TIME = 0x4U,
	CFG_ALIAS = 0x8U,
};

/**
 * @deflt:	default value for this key.
 * 		If %CFG_ALIAS is in effect however, this specifies the actual key.
 * @min,@max:	clamp value to minimum/maximum (only if %CFG_SIZE,%CFG_TIME)
 */
struct cfg_directive {
	const char *key = nullptr, *deflt = nullptr;
	unsigned int flags = 0;
	const char *min = nullptr, *max = nullptr;

	bool operator<(const cfg_directive &) const;
	bool operator<(const char *) const;
	bool operator==(const cfg_directive &) const = delete;
};

struct CONFIG_ENTRY {
    char keyname[256];
    char value[256];
	BOOL is_touched;
};

struct GX_EXPORT CONFIG_FILE {
	CONFIG_FILE() = default;
	~CONFIG_FILE();
	NOMOVE(CONFIG_FILE);
	const char *get_value(const char *key) const;
	BOOL set_value(const char *key, const char *value);
	BOOL save();
	BOOL get_int(const char *key, int *) const;
	BOOL get_uint(const char *key, unsigned int *) const;
	unsigned long long get_ll(const char *key) const;
	BOOL set_int(const char *key, int);

    CONFIG_ENTRY *config_table;
    size_t num_entries;
	size_t total_entries;
	char file_name[256];
};

struct cfg_error : public std::exception {};

#define NO_SEARCH_DIRS nullptr
#if defined(__OpenBSD__)
#define RUNNING_IDENTITY "_gromox"
#else
#define RUNNING_IDENTITY "gromox"
#endif

extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_init(const char *filename, const cfg_directive *);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_initd(const char *basename, const char *searchdirs, const cfg_directive *);
extern GX_EXPORT std::shared_ptr<CONFIG_FILE> config_file_prg(const char *priority_location, const char *fallback_location_basename, const cfg_directive *);

namespace gromox {

extern GX_EXPORT errno_t switch_user_exec(const CONFIG_FILE &, const char **argv);

}

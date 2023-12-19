#pragma once
#include <map>
#include <memory>
#include <string>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#define CFG_TABLE_END {}

enum cfg_flags {
	CFG_BOOL = 0x1U,
	CFG_SIZE = 0x2U,
	CFG_TIME = 0x4U,
	CFG_ALIAS = 0x8U,
	CFG_TIME_NS = 0x10U,
	CFG_DEPRECATED = 0x20U,
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
};

class GX_EXPORT config_file {
	public:
	config_file() = default;
	config_file(const cfg_directive *);
	const char *get_value(const char *key) const __attribute__((nonnull(2)));
	unsigned long long get_ll(const char *key) const __attribute__((nonnull(2)));
	void set_value(const char *k, const char *v) __attribute__((nonnull(2,3)));
	BOOL save();

	std::string m_filename;
	bool m_touched = false;

	private:
	struct GX_EXPORT cfg_entry {
		cfg_entry() = default;
		cfg_entry(const char *s) __attribute__((nonnull(2))) : m_val(s) {}
		cfg_entry(const cfg_directive &d);
		void set(const char *s) __attribute__((nonnull(2)));
		std::string m_val, m_min, m_max;
		unsigned int m_flags = 0;
	};
	using map_type = std::map<std::string, cfg_entry>;
	using value_type = map_type::value_type;
	map_type m_vars;
};
using CONFIG_FILE = config_file;

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

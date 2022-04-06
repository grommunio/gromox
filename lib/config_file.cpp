// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
// SPDX-FileCopyrightText: 2020–2021 grommunio GmbH
// This file is part of Gromox.
/*
 *	config file parser, which parse a (key = value) format config file.
 *	The comments is start with '#' at the leading of each comment line
 *
 */
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <gromox/config_file.hpp>
#include <gromox/defs.h>
#include <gromox/fileio.h>
#include <gromox/paths.h>
#include <gromox/util.hpp>
#define MAX_LINE_LEN		1024
#define EXT_ENTRY_NUM		64

using namespace std::string_literals;
using namespace gromox;

static void config_file_apply_1(CONFIG_FILE &cfg, const cfg_directive &d);
static void config_file_parse_line(std::shared_ptr<CONFIG_FILE> &cfg, char *line);

bool cfg_directive::operator<(const char *s) const
{
	return strcmp(key, s) < 0;
}

bool cfg_directive::operator<(const cfg_directive &o) const
{
	return strcmp(key, o.key) < 0;
}

static const char *default_searchpath()
{
	const char *ed = getenv("GROMOX_CONFIG_PATH");
	return ed != nullptr ? ed : PKGSYSCONFDIR;
}

static std::shared_ptr<CONFIG_FILE> config_file_alloc(size_t z)
{
	std::shared_ptr<CONFIG_FILE> cfg;
	try {
		cfg = std::make_shared<CONFIG_FILE>();
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	cfg->total_entries = z;
	cfg->config_table = static_cast<CONFIG_ENTRY *>(calloc(z, sizeof(CONFIG_ENTRY)));
	if (cfg->config_table == NULL) {
		return NULL;
	}
	return cfg;
}

/*
 *	init a config file object with the specified filename
 *
 *	@param
 *		filename [in]		the config filename that mapped 
 *							the object
 *	@return
 *		a pointer point to the config file object, NULL if
 *		some error occurs
 */
std::shared_ptr<CONFIG_FILE> config_file_init(const char *filename,
    const cfg_directive *key_desc)
{
	char line[MAX_LINE_LEN];	/* current line being processed */
	size_t i, table_size;		   /* loop counter, table line num */
	
	FILE *fin = fopen(filename, "r");
	if (fin == NULL) {
		return NULL;
	}
	for (table_size = 0; fgets(line, MAX_LINE_LEN, fin); table_size++) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			table_size--;
		}
	}
	auto cfg = config_file_alloc(table_size + EXT_ENTRY_NUM);
	if (cfg == NULL) {
		debug_info("[config_file]: config_file_init: %s, alloc fail", filename);
		fclose(fin);
		return NULL;
	}
	rewind(fin);
	/* read the first 2 entries from each line, the rest are comments */

	for (i=0; fgets(line, MAX_LINE_LEN, fin); i++) {
		if (line[0] == '\r' || line[0] == '\n' || line[0] == '#') {
			i--;
			continue;
		}
		/* prevent line exceed maximum length ---MAX_LINE_LEN */
		line[sizeof(line) - 1] = '\0';
		config_file_parse_line(cfg, line);
	}

	fclose(fin);
	gx_strlcpy(cfg->file_name, filename, GX_ARRAY_SIZE(cfg->file_name));
	if (key_desc != nullptr)
		for (; key_desc->key != nullptr; ++key_desc)
			config_file_apply_1(*cfg, *key_desc);
	return cfg;
}

/***
 * @fb:		filename (base) - "foo.cfg"
 * @sdlist:	colon-separated path list
 *
 * Attempt to read config file @fb from various paths (@sdlist).
 */
std::shared_ptr<CONFIG_FILE> config_file_initd(const char *fb,
    const char *sdlist, const cfg_directive *key_desc)
{
	if (sdlist == nullptr || strchr(fb, '/') != nullptr)
		return config_file_init(fb, key_desc);
	errno = 0;
	try {
		for (auto dir : gx_split(sdlist, ':')) {
			if (dir.size() == 0)
				continue;
			errno = 0;
			auto full = dir + "/" + fb;
			auto cfg = config_file_init(full.c_str(), key_desc);
			if (cfg != nullptr)
				return cfg;
			if (errno != ENOENT) {
				fprintf(stderr, "config_file_initd %s: %s\n",
				        full.c_str(), strerror(errno));
				return nullptr;
			}
		}
	} catch (const std::bad_alloc &) {
		errno = ENOMEM;
		return nullptr;
	}
	auto cfg = config_file_alloc(EXT_ENTRY_NUM);
	if (cfg == NULL)
		return nullptr;
	gx_strlcpy(cfg->file_name, fb, GX_ARRAY_SIZE(cfg->file_name));
	if (key_desc != nullptr)
		for (; key_desc->key != nullptr; ++key_desc)
			config_file_apply_1(*cfg, *key_desc);
	return cfg;
}

/**
 * Routine intended for programs:
 *
 * Read user-specified config file (@uc) or, if that is unset, try the default file
 * (@fb, located in default searchpaths) in silent mode.
 */
std::shared_ptr<CONFIG_FILE> config_file_prg(const char *ov, const char *fb,
    const cfg_directive *key_desc)
{
	if (ov == nullptr)
		return config_file_initd(fb, default_searchpath(), key_desc);
	auto cfg = config_file_init(ov, key_desc);
	if (cfg == nullptr)
		fprintf(stderr, "config_file_init %s: %s\n", ov, strerror(errno));
	return cfg;
}

/*
 *	free the specified config file object
 *
 *	@param
 *		cfg_file [in]	the object to release
 */
CONFIG_FILE::~CONFIG_FILE()
{
	free(config_table);
}

/*
 *	get the value from the specified config file object with 
 *	the key as the entry
 *
 *	@param
 *		cfg_file [in]		the specified config file object
 *		key [in]			which mapped to the return value
 *
 *	@return
 *		the value that mapped the specified key
 */
const char *CONFIG_FILE::get_value(const char *key) const
{
	auto cfg_file = this;
	size_t i, len;

#ifdef _DEBUG_UMTA
	if (key == nullptr) {
		debug_info("[config_file]: config_file_get_value: invalid param");
		return NULL;
	}
#endif
	len = strlen(key);
	for (i=0; i<len; i++) {
		if ((key[i] >= '0' && key[i] <= '9') ||
			(key[i] >= 'a' && key[i] <= 'z') ||
			(key[i] >= 'A' && key[i] <= 'Z') ||
			'-' == key[i] || '_' == key[i]) {
			continue;
		} else {
			return NULL;
		}
	}
	for (i = 0; i < cfg_file->num_entries; i++) {
		if (0 == strcasecmp(key, cfg_file->config_table[i].keyname)) {
			return cfg_file->config_table[i].value;
		}
	}
	return NULL;
}

/*
 *	parse the specified line and store the first two item into
 *	the key and value buffer. the line is like:
 *			key = value		# comments
 *
 *	@param
 *		cfg [in]		config file object
 *		line [int]		line read from file
 */
static void config_file_parse_line(std::shared_ptr<CONFIG_FILE> &cfg, char *line)
{
	char temp_buf[MAX_LINE_LEN];
	char *equal_ptr = NULL;
	char *cr_ptr	= NULL;
	char *lf_ptr	= NULL;
	size_t index;

#ifdef _DEBUG_UMTA
	if (NULL == cfg || NULL == line) {
		debug_info("[config_file]: config_file_parse_line, param NULL");
		return;
	}
#endif
	gx_strlcpy(temp_buf, line, GX_ARRAY_SIZE(temp_buf));
	cr_ptr = strchr(temp_buf, '\r');
	if (NULL != cr_ptr) {
		*cr_ptr = '\0';
	}
	lf_ptr = strchr(temp_buf, '\n');
	if (NULL != lf_ptr) {
		*lf_ptr = '\0';
	}
	HX_strrtrim(temp_buf);
	HX_strltrim(temp_buf);
	equal_ptr = strchr(temp_buf, '=');
	if (NULL == equal_ptr) {
		return;
	}
	*equal_ptr = '\0';
	equal_ptr ++;
	HX_strrtrim(temp_buf);
	HX_strltrim(equal_ptr);
	if (strlen(temp_buf) == 0)
		return;
	index = cfg->num_entries;
	cfg->num_entries ++;
	cfg->config_table[index].is_touched = FALSE;
	gx_strlcpy(cfg->config_table[index].keyname, temp_buf, GX_ARRAY_SIZE(cfg->config_table[index].keyname));
	HX_strlower(cfg->config_table[index].keyname);
	gx_strlcpy(cfg->config_table[index].value, equal_ptr, GX_ARRAY_SIZE(cfg->config_table[index].value));
	return;
}

BOOL CONFIG_FILE::set_value(const char *key, const char *value)
{
	auto cfg_file = this;
	size_t index, i, len;   

#ifdef _DEBUG_UMTA
	if (key == nullptr || value == nullptr) {
		debug_info("[config_file]: config_file_set_value: invalid param");
		return FALSE;
	}
#endif
	len = strlen(key);
	for (i=0; i<len; i++) {
		if ((key[i] >= '0'&& key[i] <= '9') ||
			(key[i] >= 'a' && key[i] <= 'z') ||
			(key[i] >= 'A' && key[i] <= 'Z') ||
			'-' == key[i] || '_' == key[i]) {
			continue;
		} else {
			return FALSE;
		}
	}
	len = strlen(value);
	for (i=0; i<len; i++) {
		if ('#' == value[i]) {
			return FALSE;
		}
	}
	for (i=0; i<cfg_file->num_entries; i++) {
		if (0 == strcasecmp(key, cfg_file->config_table[i].keyname)) {
			if (cfg_file->config_table[i].value != value) {
				gx_strlcpy(cfg_file->config_table[i].value, value, GX_ARRAY_SIZE(cfg_file->config_table[i].value));
				cfg_file->config_table[i].is_touched = TRUE;
			}
			return TRUE;
		}
	}
	
	if (cfg_file->num_entries == cfg_file->total_entries) {
		return FALSE;
	}
	index = cfg_file->num_entries;
	cfg_file->num_entries ++;
	cfg_file->config_table[index].is_touched = TRUE;
	gx_strlcpy(cfg_file->config_table[index].keyname, key, GX_ARRAY_SIZE(cfg_file->config_table[index].keyname));
	HX_strlower(cfg_file->config_table[index].keyname);
	gx_strlcpy(cfg_file->config_table[index].value, value, GX_ARRAY_SIZE(cfg_file->config_table[index].value));
	return TRUE;
}

BOOL CONFIG_FILE::save()
{
	auto cfg = this;
	auto tbl = cfg->config_table;
	if (std::none_of(&tbl[0], &tbl[cfg->num_entries],
	    [&](const CONFIG_ENTRY &x) { return x.is_touched; }))
		return TRUE;
	std::unique_ptr<FILE, file_deleter> fp(fopen(cfg->file_name, "w"));
	if (fp == nullptr)
		return FALSE;
	for (size_t i = 0; i < cfg->num_entries; ++i)
		fprintf(fp.get(), "%s = %s\n", tbl[i].keyname, tbl[i].value);
	return TRUE;
}

BOOL CONFIG_FILE::get_int(const char *key, int *value) const
{
	auto v = get_value(key);
	if (v == nullptr)
		return FALSE;
	*value = strtol(v, nullptr, 0);
	return TRUE;
}

BOOL CONFIG_FILE::get_uint(const char *key, unsigned int *value) const
{
	auto v = get_value(key);
	if (v == nullptr)
		return FALSE;
	*value = strtoul(v, nullptr, 0);
	return TRUE;
}

unsigned long long CONFIG_FILE::get_ll(const char *key) const
{
	auto sv = get_value(key);
	if (sv == nullptr) {
		fprintf(stderr, "*** config key \"%s\" has no default and was not set either\n", key);
		throw cfg_error();
	}
	return strtoull(sv, nullptr, 0);
}

BOOL CONFIG_FILE::set_int(const char *key, int value)
{
	char buf[HXSIZEOF_Z32];
	snprintf(buf, arsizeof(buf), "%d", value);
	return set_value(key, buf);
}

static void config_file_apply_1(CONFIG_FILE &cfg, const cfg_directive &d)
{
	auto sv = cfg.get_value(d.key);
	if (sv == nullptr)
		sv = d.deflt;
	if (d.flags & CFG_BOOL) {
		cfg.set_value(d.key, parse_bool(sv) ? "1" : "0");
		return;
	}
	if (d.flags & CFG_TIME) {
		auto nv = HX_strtoull_sec(sv, nullptr);
		if (d.min != nullptr)
			nv = std::max(nv, HX_strtoull_sec(d.min, nullptr));
		if (d.max != nullptr)
			nv = std::min(nv, HX_strtoull_sec(d.max, nullptr));
		char out[HXSIZEOF_Z64];
		snprintf(out, arsizeof(out), "%llu", nv);
		cfg.set_value(d.key, out);
		return;
	}
	if (d.flags & CFG_SIZE) {
		auto nv = HX_strtoull_unit(sv, nullptr, 1024);
		if (d.min != nullptr)
			nv = std::max(nv, HX_strtoull_unit(d.min, nullptr, 1024));
		if (d.max != nullptr)
			nv = std::min(nv, HX_strtoull_unit(d.max, nullptr, 1024));
		char out[HXSIZEOF_Z64];
		snprintf(out, arsizeof(out), "%llu", static_cast<unsigned long long>(nv));
		cfg.set_value(d.key, out);
		return;
	}
	cfg.set_value(d.key, sv);
}

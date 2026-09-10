#pragma once
#include <string>
#include <utility>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

struct GX_EXPORT vcard_param {
	vcard_param(std::string_view n) : m_name(std::move(n)) {}
	void append_paramval(std::string_view sv) { m_paramvals.emplace_back(std::move(sv)); }
	inline const char *name() const { return m_name.c_str(); }
	inline const std::string &name_s() const { return m_name; }

	std::string m_name;
	std::vector<std::string> m_paramvals;
};

struct GX_EXPORT vcard_value {
	void append_subval(const char *s) { m_subvals.emplace_back(gromox::znul(s)); }
	void append_subval(std::string &&s) { m_subvals.emplace_back(std::move(s)); }
	std::vector<std::string> m_subvals;
};

struct GX_EXPORT vcard_line {
	vcard_line(std::string_view n) : m_name(std::move(n)) {}
	inline vcard_param &append_param(vcard_param &&o) { return m_params.emplace_back(std::move(o)); }
	inline vcard_param &append_param(std::string_view k) { return m_params.emplace_back(std::move(k)); }
	vcard_param &append_param(std::string_view k, std::string_view v);
	inline vcard_value &append_value(vcard_value &&o) { return m_values.emplace_back(std::move(o)); }
	inline vcard_value &append_value() { return m_values.emplace_back(); }
	vcard_value &append_value(const char *);
	vcard_value &append_value(std::string &&);
	const char *get_first_subval() const;
	inline const char *name() const { return m_name.c_str(); }
	inline const std::string &name_s() const { return m_name; }

	std::string m_name;
	std::vector<vcard_param> m_params;
	std::vector<vcard_value> m_values;
	unsigned int m_lnum = 0;
};

struct GX_EXPORT vcard {
	inline void clear() { m_lines.clear(); }
	ec_error_t load_single_from_str_move(char *in_buff);
	bool serialize(std::string &out) const;
	vcard_line &append_line(vcard_line &&o);
	vcard_line &append_line(std::string_view);
	vcard_line &append_line(std::string_view, const char *);

	std::vector<vcard_line> m_lines;
};

extern GX_EXPORT ec_error_t vcard_load_multi_from_str_move(char *input, std::vector<vcard> &, size_t limit = 0);

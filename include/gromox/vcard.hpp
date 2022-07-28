#pragma once
#include <string>
#include <utility>
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/defs.h>
#include <gromox/mapierr.hpp>

struct GX_EXPORT vcard_param {
	vcard_param(const char *n) : m_name(n) {}
	void append_paramval(const char *s) { m_paramvals.emplace_back(s); }
	inline const char *name() const { return m_name.c_str(); }

	std::string m_name;
	std::vector<std::string> m_paramvals;
};
using VCARD_PARAM = vcard_param;

struct GX_EXPORT vcard_value {
	void append_subval(const char *s) { m_subvals.emplace_back(gromox::znul(s)); }
	std::vector<std::string> m_subvals;
};
using VCARD_VALUE = vcard_value;

struct GX_EXPORT vcard_line {
	vcard_line(const char *n) : m_name(n) {}
	inline vcard_param &append_param(vcard_param &&o) { m_params.push_back(std::move(o)); return m_params.back(); }
	vcard_param &append_param(const char *p, const char *pv);
	inline vcard_value &append_value(vcard_value &&o) { m_values.push_back(std::move(o)); return m_values.back(); }
	inline vcard_value &append_value() { return m_values.emplace_back(); }
	vcard_value &append_value(const char *);
	const char *get_first_subval() const;
	inline const char *name() const { return m_name.c_str(); }

	std::string m_name;
	std::vector<vcard_param> m_params;
	std::vector<vcard_value> m_values;
};
using VCARD_LINE = vcard_line;

struct GX_EXPORT vcard {
	inline void clear() { m_lines.clear(); }
	ec_error_t retrieve_single(char *in_buff);
	BOOL serialize(char *out_buff, size_t max_length);
	inline vcard_line &append_line(vcard_line &&o) { m_lines.push_back(std::move(o)); return m_lines.back(); }
	vcard_line &append_line(const char *);
	vcard_line &append_line(const char *, const char *);

	std::vector<vcard_line> m_lines;
};
using VCARD = vcard;

extern GX_EXPORT ec_error_t vcard_retrieve_multi(char *input, std::vector<vcard> &, size_t limit = 0);

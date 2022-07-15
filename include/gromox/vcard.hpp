#pragma once
#include <vector>
#include <gromox/common_types.hpp>
#include <gromox/mapierr.hpp>
#include <gromox/double_list.hpp>
#define VCARD_NAME_LEN		32

struct GX_EXPORT vcard_param {
	vcard_param(const char *);
	~vcard_param();
	ec_error_t append_paramval(const char *paramval);
	inline const char *name() const { return m_name; }

	DOUBLE_LIST_NODE node{};
	char m_name[VCARD_NAME_LEN]{};
	DOUBLE_LIST pparamval_list{};
};
using VCARD_PARAM = vcard_param;

struct GX_EXPORT vcard_value {
	vcard_value();
	~vcard_value();
	ec_error_t append_subval(const char *);

	DOUBLE_LIST_NODE node{};
	DOUBLE_LIST subval_list{};
};
using VCARD_VALUE = vcard_value;

struct GX_EXPORT vcard_line {
	vcard_line(const char *);
	~vcard_line();
	ec_error_t append_param(VCARD_PARAM *);
	vcard_param &append_param(const char *);
	vcard_param &append_param(const char *, const char *);
	vcard_value &append_value();
	ec_error_t append_value(VCARD_VALUE *);
	vcard_value &append_value(const char *);
	const char *get_first_subval() const;
	inline const char *name() const { return m_name; }

	DOUBLE_LIST_NODE node{};
	char m_name[VCARD_NAME_LEN]{};
	DOUBLE_LIST param_list{}, value_list{};
};
using VCARD_LINE = vcard_line;

struct GX_EXPORT vcard {
	vcard();
	vcard(vcard &&o);
	~vcard();
	vcard &operator=(vcard &&);

	void clear();
	ec_error_t retrieve_single(char *in_buff);
	BOOL serialize(char *out_buff, size_t max_length);
	ec_error_t append_line(vcard_line *);
	vcard_line &append_line(const char *);
	vcard_line &append_line(const char *, const char *);

	DOUBLE_LIST line_list{};
};
using VCARD = vcard;

VCARD_LINE* vcard_new_line(const char *name);
VCARD_PARAM* vcard_new_param(const char*name);
extern VCARD_VALUE *vcard_new_value();
extern GX_EXPORT ec_error_t vcard_retrieve_multi(char *input, std::vector<vcard> &, size_t limit = 0);

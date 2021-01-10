// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/mapidefs.h>
#include <gromox/proc_common.h>
#include "nsp_ndr.h"
#include <iconv.h>
#include <cstring>
#include <cstdlib>
#define FLAG_HEADER			0x1
#define FLAG_CONTENT		0x2


static int nsp_ndr_pull_restriction(NDR_PULL *pndr, int flag, RESTRICTION *r);

static int nsp_ndr_push_restriction(NDR_PUSH *pndr, int flag, const RESTRICTION *r);

static int nsp_ndr_to_utf16(int ndr_flag, const char *src, char *dst, size_t len)
{
	size_t in_len;
	size_t out_len;
	char *pin, *pout;
	iconv_t conv_id;

	if (ndr_flag & NDR_FLAG_BIGENDIAN) {
		conv_id = iconv_open("UTF-16", "UTF-8");
	} else {
		conv_id = iconv_open("UTF-16LE", "UTF-8");
	}
	
	pin = (char*)src;
	pout = dst;
	in_len = strlen(src) + 1;
	memset(dst, 0, len);
	out_len = len;
	if (-1 == iconv(conv_id, &pin, &in_len, &pout, &len)) {
		iconv_close(conv_id);
		return -1;
	} else {
		iconv_close(conv_id);
		return out_len - len;
	}
}

static BOOL nsp_ndr_to_utf8(int ndr_flag, const char *src,
	size_t src_len, char *dst, size_t len)
{
	char *pin, *pout;
	iconv_t conv_id;

	if (ndr_flag & NDR_FLAG_BIGENDIAN) {
		conv_id = iconv_open("UTF-8", "UTF-16");
	} else {
		conv_id = iconv_open("UTF-8", "UTF-16LE");
	}
	pin = (char*)src;
	pout = dst;
	memset(dst, 0, len);
	if (-1 == iconv(conv_id, &pin, &src_len, &pout, &len)) {
		iconv_close(conv_id);
		return FALSE;
	} else {
		iconv_close(conv_id);
		return TRUE;
	}
}

static int nsp_ndr_pull_stat(NDR_PULL *pndr, STAT *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->sort_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->container_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cur_rec);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_int32(pndr, &r->delta);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->num_pos);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->total_rec);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->codepage);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->template_locale);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->sort_locale);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_stat(NDR_PUSH *pndr, const STAT *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->sort_type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->container_id);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cur_rec);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_int32(pndr, r->delta);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->num_pos);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->total_rec);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->codepage);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->template_locale);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->sort_locale);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_flatuid(NDR_PULL *pndr, FLATUID *r)
{
	return ndr_pull_array_uint8(pndr, r->ab, 16);
}

static int nsp_ndr_push_flatuid(NDR_PUSH *pndr, const FLATUID *r)
{	
	return ndr_push_array_uint8(pndr, r->ab, 16);
}

static int nsp_ndr_pull_proptag_array(NDR_PULL *pndr, PROPTAG_ARRAY *r)
{
	int status;
	uint32_t cnt;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	status = ndr_pull_ulong(pndr, &size);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cvalues);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->cvalues > 100001) {
		return NDR_ERR_RANGE;
	}
	status = ndr_pull_ulong(pndr, &offset);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_ulong(pndr, &length);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != offset || length > size) {
		return NDR_ERR_ARRAY_SIZE;
	}
	
	if (size != r->cvalues + 1 || length != r->cvalues) {
		return NDR_ERR_ARRAY_SIZE;
	}
	r->pproptag = static_cast<uint32_t *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(uint32_t) * size));
	if (NULL == r->pproptag) {
		return NDR_ERR_ALLOC;
	}
	
	for (cnt=0; cnt<length; cnt++) {
		status = ndr_pull_uint32(pndr, &r->pproptag[cnt]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_proptag_array(NDR_PUSH *pndr, const PROPTAG_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	status = ndr_push_ulong(pndr, r->cvalues + 1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cvalues);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, 0);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_ulong(pndr, r->cvalues);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	for (cnt=0; cnt<r->cvalues; cnt++) {
		status = ndr_push_uint32(pndr, r->pproptag[cnt]);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_property_name(NDR_PULL *pndr, int flag, PROPERTY_NAME *r)
{
	int status;
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pguid = static_cast<FLATUID *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(FLATUID)));
			if (NULL == r->pguid) {
				return NDR_ERR_ALLOC;
			}
		} else {
			r->pguid = NULL;
		}
		status = ndr_pull_uint32(pndr, &r->reserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->id);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pguid) {
			status = nsp_ndr_pull_flatuid(pndr, r->pguid);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_string_array(NDR_PULL *pndr, int flag, STRING_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->ppstr = (char**)(long)ptr;
		} else {
			r->ppstr = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL == r->ppstr) {
			return NDR_ERR_SUCCESS;
		}
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (size != r->cvalues) {
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ppstr = static_cast<char **>(ndr_stack_alloc(NDR_STACK_IN, sizeof(char *) * size));
		if (NULL == r->ppstr) {
			return NDR_ERR_ALLOC;
		}
		for (cnt=0; cnt<size; cnt++) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (0 != ptr) {
				r->ppstr[cnt] = (char*)(long)ptr;
			} else {
				r->ppstr[cnt] = NULL;
			}
		}
		for (cnt=0; cnt<size; cnt++) {
			if (NULL != r->ppstr[cnt]) {
				status = ndr_pull_ulong(pndr, &size1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length1 > size1) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length1, sizeof(uint8_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				r->ppstr[cnt] = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, length1 + 1));
				if (NULL == r->ppstr[cnt]) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, r->ppstr[cnt], length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_string_array(NDR_PUSH *pndr, int flag, const STRING_ARRAY *r)
{
	int status;
	int length;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->ppstr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ppstr) {
			status = ndr_push_ulong(pndr, r->cvalues);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = ndr_push_unique_ptr(pndr, r->ppstr[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				if (NULL != r->ppstr[cnt]) {
					length = strlen(r->ppstr[cnt]) + 1;
					status = ndr_push_ulong(pndr, length);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
					status = ndr_push_ulong(pndr, 0);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
					status = ndr_push_ulong(pndr, length);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
					status = ndr_push_string(pndr, r->ppstr[cnt], length);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_strings_array(NDR_PULL *pndr, int flag, STRINGS_ARRAY *r)
{
	int status;
	uint32_t cnt;
	uint32_t ptr;
	uint32_t size;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->count);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->count > 100000) {
			return NDR_ERR_RANGE;
		}
		if (r->count != size) {
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ppstrings = static_cast<char **>(ndr_stack_alloc(NDR_STACK_IN, sizeof(char *) * size));
		if (NULL == r->ppstrings) {
			return NDR_ERR_ALLOC;
		}
		for (cnt=0; cnt<size; cnt++) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (0 != ptr) {
				r->ppstrings[cnt] = (char*)(long)ptr;
			} else {
				r->ppstrings[cnt] = NULL;
			}
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		for (cnt=0; cnt<r->count; cnt++) {
			if (NULL != r->ppstrings[cnt]) {
				status = ndr_pull_ulong(pndr, &size1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length1 > size1) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length1, sizeof(uint8_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				r->ppstrings[cnt] = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, length1 + 1));
				if (NULL == r->ppstrings[cnt]) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, r->ppstrings[cnt], length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_wstring_array(NDR_PULL *pndr, int flag, STRING_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	char *pwstring;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	

	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->ppstr = (char**)(long)ptr;
		} else {
			r->ppstr = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL == r->ppstr) {
			return NDR_ERR_SUCCESS;
		}
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (size != r->cvalues) {
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ppstr = static_cast<char **>(ndr_stack_alloc(NDR_STACK_IN, sizeof(char *) * size));
		if (NULL == r->ppstr) {
			return NDR_ERR_ALLOC;
		}
		for (cnt=0; cnt<size; cnt++) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (0 != ptr) {
				r->ppstr[cnt] = (char*)(long)ptr;
			} else {
				r->ppstr[cnt] = NULL;
			}
		}
		for (cnt=0; cnt<size; cnt++) {
			if (NULL != r->ppstr[cnt]) {
				status = ndr_pull_ulong(pndr, &size1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length1 > size1) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length1, sizeof(uint16_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				pwstring = static_cast<char *>(malloc(sizeof(uint16_t) * length1 + 1));
				if (NULL == pwstring) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, pwstring, sizeof(uint16_t)*length1);
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				r->ppstr[cnt] = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1));
				if (NULL == r->ppstr[cnt]) {
					free(pwstring);
					return NDR_ERR_ALLOC;
				}
				if (FALSE == nsp_ndr_to_utf8(pndr->flags, pwstring, sizeof(uint16_t)*length1,
					r->ppstr[cnt], 2*sizeof(uint16_t)*length1)) {
					free(pwstring);
					return NDR_ERR_CHARCNV;
				}
				free(pwstring);
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_wstring_array(NDR_PUSH *pndr, int flag, const STRING_ARRAY *r)
{
	int status;
	int length;
	uint32_t cnt;
	char *pwstring;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->ppstr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ppstr) {
			status = ndr_push_ulong(pndr, r->cvalues);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = ndr_push_unique_ptr(pndr, r->ppstr[cnt]);
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				if (NULL != r->ppstr[cnt]) {
					length = 2*strlen(r->ppstr[cnt]) + 2;
					pwstring = static_cast<char *>(malloc(length));
					if (NULL == pwstring) {
						return NDR_ERR_ALLOC;
					}
					length = nsp_ndr_to_utf16(pndr->flags, r->ppstr[cnt], pwstring, length);
					if (-1 == length) {
						free(pwstring);
						return NDR_ERR_CHARCNV;
					}
					status = ndr_push_ulong(pndr, length/sizeof(uint16_t));
					if (NDR_ERR_SUCCESS != status) {
						free(pwstring);
						return status;
					}
					status = ndr_push_ulong(pndr, 0);
					if (NDR_ERR_SUCCESS != status) {
						free(pwstring);
						return status;
					}
					status = ndr_push_ulong(pndr, length/sizeof(uint16_t));
					if (NDR_ERR_SUCCESS != status) {
						free(pwstring);
						return status;
					}
					status = ndr_push_string(pndr, pwstring, length);
					free(pwstring);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_wstrings_array(NDR_PULL *pndr, int flag, STRINGS_ARRAY *r)
{
	int status;
	uint32_t cnt;
	uint32_t ptr;
	uint32_t size;
	char *pwstring;
	uint32_t size1;
	uint32_t offset;
	uint32_t length1;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->count);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->count > 100000) {
			return NDR_ERR_RANGE;
		}
		if (r->count != size) {
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ppstrings = static_cast<char **>(ndr_stack_alloc(NDR_STACK_IN, sizeof(char *) * size));
		if (NULL == r->ppstrings) {
			return NDR_ERR_ALLOC;
		}
		for (cnt=0; cnt<size; cnt++) {
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (0 != ptr) {
				r->ppstrings[cnt] = (char*)(long)ptr;
			} else {
				r->ppstrings[cnt] = NULL;
			}
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		for (cnt=0; cnt<r->count; cnt++) {
			if (NULL != r->ppstrings[cnt]) {
				status = ndr_pull_ulong(pndr, &size1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length1);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length1 > size1) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length1, sizeof(uint16_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				pwstring = static_cast<char *>(malloc(sizeof(uint16_t) * length1 + 1));
				if (NULL == pwstring) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, pwstring, sizeof(uint16_t)*length1);
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				r->ppstrings[cnt] = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, 2 * sizeof(uint16_t) * length1));
				if (NULL == r->ppstrings[cnt]) {
					free(pwstring);
					return NDR_ERR_ALLOC;
				}
				if (FALSE == nsp_ndr_to_utf8(pndr->flags, pwstring, sizeof(uint16_t)*length1,
					r->ppstrings[cnt], 2*sizeof(uint16_t)*length1)) {
					free(pwstring);
					return NDR_ERR_CHARCNV;
				}
				free(pwstring);
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_binary(NDR_PULL *pndr, int flag, BINARY *r)
{
	int status;
	uint32_t ptr;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cb);
		if (r->cb > 2097152) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (0 != ptr) {
			r->pb = (uint8_t*)(long)ptr;
		} else {
			r->pb = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pb) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cb) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pb = static_cast<uint8_t *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(uint8_t)));
			if (NULL == r->pb) {
				return NDR_ERR_ALLOC;
			}
			status = ndr_pull_array_uint8(pndr, r->pb, size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_binary(NDR_PUSH *pndr, int flag, const BINARY *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cb);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pb);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pb) {
			status = ndr_push_ulong(pndr, r->cb);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			status = ndr_push_array_uint8(pndr, r->pb, r->cb);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_filetime(NDR_PULL *pndr, FILETIME *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->low_datetime);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->high_datetime);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_trailer_align(pndr, 4);
}

static int nsp_ndr_push_filetime(NDR_PUSH *pndr, const FILETIME *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->low_datetime);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->high_datetime);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_trailer_align(pndr, 4);
}

static int nsp_ndr_pull_short_array(NDR_PULL *pndr, int flag, SHORT_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->ps = (uint16_t*)(long)ptr;
		} else {
			r->ps = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ps) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->ps = static_cast<uint16_t *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(uint16_t) * size));
			if (NULL == r->ps) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = ndr_pull_uint16(pndr, &r->ps[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return status;
}

static int nsp_ndr_push_short_array(NDR_PUSH *pndr, int flag, const SHORT_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->ps);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ps) {
			status = ndr_push_ulong(pndr, r->cvalues);
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = ndr_push_uint16(pndr, r->ps[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_long_array(NDR_PULL *pndr, int flag, LONG_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (0 != ptr) {
			r->pl = (uint32_t*)(long)ptr;
		} else {
			r->pl = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pl) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pl = static_cast<uint32_t *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(uint32_t)));
			if (NULL == r->pl) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = ndr_pull_uint32(pndr, &r->pl[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_long_array(NDR_PUSH *pndr, int flag, const LONG_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pl);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pl) {
			status = ndr_push_ulong(pndr, r->cvalues);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = ndr_push_uint32(pndr, r->pl[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_binary_array(NDR_PULL *pndr, int flag, BINARY_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (0 != ptr) {
			r->pbin = (BINARY*)(long)ptr;
		} else {
			r->pbin = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pbin) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pbin = static_cast<BINARY *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(BINARY)));
			if (NULL == r->pbin) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_binary(pndr, FLAG_HEADER, &r->pbin[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_binary(pndr, FLAG_CONTENT, &r->pbin[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_binary_array(NDR_PUSH *pndr, int flag, const BINARY_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pbin);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pbin) {
			status = ndr_push_ulong(pndr, r->cvalues);
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = nsp_ndr_push_binary(pndr, FLAG_HEADER, &r->pbin[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = nsp_ndr_push_binary(pndr, FLAG_CONTENT, &r->pbin[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_flatuid_array(NDR_PULL *pndr, int flag, FLATUID_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;

	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->ppguid = (FLATUID**)(long)ptr;
		} else {
			r->ppguid = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ppguid) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->ppguid = static_cast<FLATUID **>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(FLATUID *)));
			if (NULL == r->ppguid) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = ndr_pull_generic_ptr(pndr, &ptr);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != ptr) {
					r->ppguid[cnt] = static_cast<FLATUID *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(FLATUID)));
					if (NULL == r->ppguid[cnt]) {
						return NDR_ERR_ALLOC;
					}
				} else {
					r->ppguid[cnt] = NULL;
				}
			}
			for (cnt=0; cnt<size; cnt++) {
				if (NULL != r->ppguid[cnt]) {
					status = nsp_ndr_pull_flatuid(pndr, r->ppguid[cnt]);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_flatuid_array(NDR_PUSH *pndr, int flag, const FLATUID_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->ppguid);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->ppguid) {
			status = ndr_push_ulong(pndr, r->cvalues);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = ndr_push_unique_ptr(pndr, r->ppguid[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				if (NULL != r->ppguid[cnt]) {
					status = nsp_ndr_push_flatuid(pndr, r->ppguid[cnt]);
					if (NDR_ERR_SUCCESS != status) {
						return status;
					}
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_filetime_array(NDR_PULL *pndr, int flag, FILETIME_ARRAY *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pftime = (FILETIME*)(long)ptr;
		} else {
			r->pftime = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pftime) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pftime = static_cast<FILETIME *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(FILETIME)));
			if (NULL == r->pftime) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_filetime(pndr, &r->pftime[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_filetime_array(NDR_PUSH *pndr, int flag, const FILETIME_ARRAY *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pftime);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pftime) {
			status = ndr_push_ulong(pndr, r->cvalues);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = nsp_ndr_push_filetime(pndr, &r->pftime[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_prop_val_union(NDR_PULL *pndr, int flag, int *ptype, PROP_VAL_UNION *r)
{
	int status;
	uint32_t ptr;
	uint32_t size;
	char *pwstring;
	uint32_t offset;
	uint32_t length;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, reinterpret_cast<uint32_t *>(ptype));
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		switch (*ptype) {
		case PT_SHORT:
			status = ndr_pull_uint16(pndr, &r->s);
			break;
		case PT_LONG:
		case PROPVAL_TYPE_EMBEDDEDTABLE:
			status = ndr_pull_uint32(pndr, &r->l);
			break;
		case PT_BOOLEAN:
			status = ndr_pull_uint8(pndr, &r->b);
			break;
		case PT_STRING8:
		case PT_UNICODE:
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (0 != ptr) {
				r->pstr = (char*)(long)ptr;
			} else {
				r->pstr = NULL;
			}
			break;
		case PT_BINARY:
			status = nsp_ndr_pull_binary(pndr, FLAG_HEADER, &r->bin);
			break;
		case PROPVAL_TYPE_FLATUID:
			status = ndr_pull_generic_ptr(pndr, &ptr);
			if (0 != ptr) {
				r->pguid = (FLATUID*)(long)ptr;
			} else {
				r->pguid = NULL;
			}
			break;
		case PT_SYSTIME:
			status = nsp_ndr_pull_filetime(pndr, &r->ftime);
			break;
		case PT_ERROR:
			status = ndr_pull_uint32(pndr, &r->err);
			break;
		case PT_MV_SHORT:
			status = nsp_ndr_pull_short_array(pndr, FLAG_HEADER, &r->short_array);
			break;
		case PT_MV_LONG:
			status = nsp_ndr_pull_long_array(pndr, FLAG_HEADER, &r->long_array);
			break;
		case PT_MV_STRING8:
			status = nsp_ndr_pull_string_array(pndr, FLAG_HEADER, &r->string_array);
			break;
		case PT_MV_BINARY:
			status = nsp_ndr_pull_binary_array(pndr, FLAG_HEADER, &r->bin_array);
			break;
		case PROPVAL_TYPE_FLATUID_ARRAY:
			status = nsp_ndr_pull_flatuid_array(pndr, FLAG_HEADER, &r->guid_array);
			break;
		case PT_MV_UNICODE:
			status = nsp_ndr_pull_wstring_array(pndr, FLAG_HEADER, &r->string_array);
			break;
		case PT_MV_SYSTIME:
			status = nsp_ndr_pull_filetime_array(pndr, FLAG_HEADER, &r->ftime_array);
			break;
		case PT_NULL:
			status = ndr_pull_uint32(pndr, &r->reserved);
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		switch (*ptype) {
		case PT_SHORT:
			break;
		case PT_LONG:
		case PROPVAL_TYPE_EMBEDDEDTABLE:
			break;
		case PT_BOOLEAN:
			break;
		case PT_STRING8:
			if (NULL != r->pstr) {
				status = ndr_pull_ulong(pndr, &size);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length > size) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				r->pstr = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, length + 1));
				if (NULL == r->pstr) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, r->pstr, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			break;
		case PT_UNICODE:
			if (NULL != r->pstr) {
				status = ndr_pull_ulong(pndr, &size);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &offset);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_pull_ulong(pndr, &length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				if (0 != offset || length > size) {
					return NDR_ERR_ARRAY_SIZE;
				}
				status = ndr_pull_check_string(pndr, length, sizeof(uint16_t));
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				pwstring = static_cast<char *>(malloc(sizeof(uint16_t) * length + 1));
				if (NULL == pwstring) {
					return NDR_ERR_ALLOC;
				}
				status = ndr_pull_string(pndr, pwstring, sizeof(uint16_t)*length);
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				r->pstr = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, 2 * sizeof(uint16_t) * length));
				if (NULL == r->pstr) {
					free(pwstring);
					return NDR_ERR_ALLOC;
				}
				if (FALSE == nsp_ndr_to_utf8(pndr->flags,
					pwstring, sizeof(uint16_t)*length,
					r->pstr, 2*sizeof(uint16_t)*length)) {
					free(pwstring);
					return NDR_ERR_CHARCNV;
				}
				free(pwstring);
			}
			break;
		case PT_BINARY:
			status = nsp_ndr_pull_binary(pndr, FLAG_CONTENT, &r->bin);
			break;
		case PROPVAL_TYPE_FLATUID:
			if (NULL != r->pguid) {
				status = nsp_ndr_pull_flatuid(pndr, r->pguid);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			break;
		case PT_SYSTIME:
			break;
		case PT_ERROR:
			break;
		case PT_MV_SHORT:
			status = nsp_ndr_pull_short_array(pndr, FLAG_CONTENT, &r->short_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_LONG:
			status = nsp_ndr_pull_long_array(pndr, FLAG_CONTENT, &r->long_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_STRING8:
			status = nsp_ndr_pull_string_array(pndr, FLAG_CONTENT, &r->string_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_BINARY:
			status = nsp_ndr_pull_binary_array(pndr, FLAG_CONTENT, &r->bin_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PROPVAL_TYPE_FLATUID_ARRAY:
			status = nsp_ndr_pull_flatuid_array(pndr, FLAG_CONTENT, &r->guid_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_UNICODE:
			status = nsp_ndr_pull_wstring_array(pndr, FLAG_CONTENT, &r->string_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_SYSTIME:
			status = nsp_ndr_pull_filetime_array(pndr, FLAG_CONTENT, &r->ftime_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_NULL:
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_prop_val_union(NDR_PUSH *pndr, int flag, int type, const PROP_VAL_UNION *r)
{
	int status;
	int length;
	char *pwstring;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, type);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		switch (type) {
		case PT_SHORT:
			status = ndr_push_uint16(pndr, r->s);
			break;
		case PT_LONG:
		case PROPVAL_TYPE_EMBEDDEDTABLE:
			status = ndr_push_uint32(pndr, r->l);
			break;
		case PT_BOOLEAN:
			status = ndr_push_uint8(pndr, r->b);
			break;
		case PT_STRING8:
		case PT_UNICODE:
			status = ndr_push_unique_ptr(pndr, r->pstr);
			break;
		case PT_BINARY:
			status = nsp_ndr_push_binary(pndr, FLAG_HEADER, &r->bin);
			break;
		case PROPVAL_TYPE_FLATUID:
			status = ndr_push_unique_ptr(pndr, r->pguid);
			break;
		case PT_SYSTIME:
			status = nsp_ndr_push_filetime(pndr, &r->ftime);
			break;
		case PT_ERROR:
			status = ndr_push_uint32(pndr, r->err);
			break;
		case PT_MV_SHORT:
			status = nsp_ndr_push_short_array(pndr, FLAG_HEADER, &r->short_array);
			break;
		case PT_MV_LONG:
			status = nsp_ndr_push_long_array(pndr, FLAG_HEADER, &r->long_array);
			break;
		case PT_MV_STRING8:
			status = nsp_ndr_push_string_array(pndr, FLAG_HEADER, &r->string_array);
			break;
		case PT_MV_BINARY:
			status = nsp_ndr_push_binary_array(pndr, FLAG_HEADER, &r->bin_array);
			break;
		case PROPVAL_TYPE_FLATUID_ARRAY:
			status = nsp_ndr_push_flatuid_array(pndr, FLAG_HEADER, &r->guid_array);
			break;
		case PT_MV_UNICODE:
			status = nsp_ndr_push_wstring_array(pndr, FLAG_HEADER, &r->string_array);
			break;
		case PT_MV_SYSTIME:
			status = nsp_ndr_push_filetime_array(pndr, FLAG_HEADER, &r->ftime_array);
			break;
		case PT_NULL:
			status = ndr_push_uint32(pndr, r->reserved);
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
		
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		switch (type) {
		case PT_SHORT:
			break;
		case PT_LONG:
		case PROPVAL_TYPE_EMBEDDEDTABLE:
			break;
		case PT_BOOLEAN:
			break;
		case PT_STRING8:
			if (NULL != r->pstr) {
				length = strlen(r->pstr) + 1;
				status = ndr_push_ulong(pndr, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_push_ulong(pndr, 0);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_push_ulong(pndr, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				status = ndr_push_string(pndr, r->pstr, length);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			break;
		case PT_UNICODE:
			if (NULL != r->pstr) {
				length = strlen(r->pstr) + 1;
				pwstring = static_cast<char *>(malloc(2 * length));
				if (NULL == pwstring) {
					return NDR_ERR_ALLOC;
				}
				length = nsp_ndr_to_utf16(pndr->flags, r->pstr, pwstring, 2*length);
				if (-1 == length) {
					free(pwstring);
					return NDR_ERR_CHARCNV;
				}
				status = ndr_push_ulong(pndr, length/sizeof(uint16_t));
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				status= ndr_push_ulong(pndr, 0);
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				status = ndr_push_ulong(pndr, length/sizeof(uint16_t));
				if (NDR_ERR_SUCCESS != status) {
					free(pwstring);
					return status;
				}
				status = ndr_push_string(pndr, pwstring, length);
				free(pwstring);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			break;
		case PT_BINARY:
			status = nsp_ndr_push_binary(pndr, FLAG_CONTENT, &r->bin);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PROPVAL_TYPE_FLATUID:
			if (NULL != r->pguid) {
				status = nsp_ndr_push_flatuid(pndr, r->pguid);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			break;
		case PT_SYSTIME:
			break;
		case PT_ERROR:
			break;
		case PT_MV_SHORT:
			status = nsp_ndr_push_short_array(pndr, FLAG_CONTENT, &r->short_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_LONG:
			status = nsp_ndr_push_long_array(pndr, FLAG_CONTENT, &r->long_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_STRING8:
			status = nsp_ndr_push_string_array(pndr, FLAG_CONTENT, &r->string_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_BINARY:
			status = nsp_ndr_push_binary_array(pndr, FLAG_CONTENT, &r->bin_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PROPVAL_TYPE_FLATUID_ARRAY:
			status = nsp_ndr_push_flatuid_array(pndr, FLAG_CONTENT, &r->guid_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_UNICODE:
			status = nsp_ndr_push_wstring_array(pndr, FLAG_CONTENT, &r->string_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_MV_SYSTIME:
			status = nsp_ndr_push_filetime_array(pndr, FLAG_CONTENT, &r->ftime_array);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case PT_NULL:
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_property_value(NDR_PULL *pndr, int flag, PROPERTY_VALUE *r)
{
	int type;
	int status;
	
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->reserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = nsp_ndr_pull_prop_val_union(pndr, FLAG_HEADER, &type, &r->value);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (PROP_TYPE(r->proptag) != type)
			return NDR_ERR_BAD_SWITCH;
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		type = PROP_TYPE(r->proptag);
		status = nsp_ndr_pull_prop_val_union(pndr, FLAG_CONTENT, &type, &r->value);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return NDR_ERR_SUCCESS;
	
}

static int nsp_ndr_push_property_value(NDR_PUSH *pndr, int flag, const PROPERTY_VALUE *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->reserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = nsp_ndr_push_prop_val_union(pndr, FLAG_HEADER, PROP_TYPE(r->proptag), &r->value);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		status = nsp_ndr_push_prop_val_union(pndr, FLAG_CONTENT, PROP_TYPE(r->proptag), &r->value);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_property_row(NDR_PULL *pndr, int flag, PROPERTY_ROW *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->reserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cvalues > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pprops = (PROPERTY_VALUE*)(long)ptr;
		} else {
			r->pprops = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprops) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cvalues) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pprops = static_cast<PROPERTY_VALUE *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(PROPERTY_VALUE)));
			if (NULL == r->pprops) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_property_value(pndr, FLAG_HEADER, &r->pprops[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_property_value(pndr, FLAG_CONTENT, &r->pprops[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_property_row(NDR_PUSH *pndr, int flag, const PROPERTY_ROW *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->reserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cvalues);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pprops);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprops) {
			status = ndr_push_ulong(pndr, r->cvalues);
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = nsp_ndr_push_property_value(pndr, FLAG_HEADER, &r->pprops[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<r->cvalues; cnt++) {
				status = nsp_ndr_push_property_value(pndr, FLAG_CONTENT, &r->pprops[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_proprow_set(NDR_PUSH *pndr, int flag, const PROPROW_SET *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_ulong(pndr, r->crows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->crows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		for (cnt=0; cnt<r->crows; cnt++) {
			status = nsp_ndr_push_property_row(pndr, FLAG_HEADER, &r->prows[cnt]);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		for (cnt=0; cnt<r->crows; cnt++) {
			status = nsp_ndr_push_property_row(pndr, FLAG_CONTENT, &r->prows[cnt]);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_and_or(NDR_PULL *pndr, int flag, RESTRICTION_AND_OR *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->cres);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->cres > 100000) {
			return NDR_ERR_RANGE;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pres = (RESTRICTION*)(long)ptr;
		} else {
			r->pres = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = ndr_pull_ulong(pndr, &size);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			if (size != r->cres) {
				return NDR_ERR_ARRAY_SIZE;
			}
			r->pres = static_cast<RESTRICTION *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(RESTRICTION)));
			if (NULL == r->pres) {
				return NDR_ERR_ALLOC;
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_restriction(pndr, FLAG_HEADER, &r->pres[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<size; cnt++) {
				status = nsp_ndr_pull_restriction(pndr, FLAG_CONTENT, &r->pres[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_and_or(NDR_PUSH *pndr, int flag, const RESTRICTION_AND_OR *r)
{
	int status;
	uint32_t cnt;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->cres);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pres);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = ndr_push_ulong(pndr, r->cres);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			for (cnt=0; cnt<r->cres; cnt++) {
				status = nsp_ndr_push_restriction(pndr, FLAG_HEADER, &r->pres[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
			for (cnt=0; cnt<r->cres; cnt++) {
				status = nsp_ndr_push_restriction(pndr, FLAG_CONTENT, &r->pres[cnt]);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_not(NDR_PULL *pndr, int flag, RESTRICTION_NOT *r)
{
	int status;
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pres = static_cast<RESTRICTION *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(RESTRICTION)));
			if (NULL == r->pres) {
				return NDR_ERR_ALLOC;
			}
		} else {
			r->pres = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = nsp_ndr_pull_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pres);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_not(NDR_PUSH *pndr, int flag, const RESTRICTION_NOT *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pres);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = nsp_ndr_push_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pres);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_content(NDR_PULL *pndr, int flag, RESTRICTION_CONTENT *r)
{
	int status;
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->fuzzy_level);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (0 != ptr) {
			r->pprop = static_cast<PROPERTY_VALUE *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPERTY_VALUE)));
			if (NULL == r->pprop) {
				return NDR_ERR_ALLOC;
			}
		} else {
			r->pprop = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprop) {
			status = nsp_ndr_pull_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, r->pprop);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_content(NDR_PUSH *pndr, int flag, const RESTRICTION_CONTENT *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->fuzzy_level);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pprop);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprop) {
			status = nsp_ndr_push_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, r->pprop);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_property(NDR_PULL *pndr, int flag, RESTRICTION_PROPERTY *r)
{
	int status;
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->relop);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pprop = static_cast<PROPERTY_VALUE *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPERTY_VALUE)));
			if (NULL == r->pprop) {
				return NDR_ERR_ALLOC;
			}
		} else {
			r->pprop = NULL;
		}
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprop) {
			status = nsp_ndr_pull_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, r->pprop);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_property(NDR_PUSH *pndr, int flag, const RESTRICTION_PROPERTY *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->relop);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->proptag);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pprop);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pprop) {
			status = nsp_ndr_push_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, r->pprop);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_propcompare(NDR_PULL *pndr, RESTRICTION_PROPCOMPARE *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->relop);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_propcompare(NDR_PUSH *pndr, const RESTRICTION_PROPCOMPARE *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->relop);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->proptag1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->proptag2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_bitmask(NDR_PULL *pndr, RESTRICTION_BITMASK *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->rel_mbr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->mask);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_bitmask(NDR_PUSH *pndr, const RESTRICTION_BITMASK *r)
{
	int status;

	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->rel_mbr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->mask);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_size(NDR_PULL *pndr, RESTRICTION_SIZE *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->relop);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->cb);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_size(NDR_PUSH *pndr, const RESTRICTION_SIZE *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->relop);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->cb);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_exist(NDR_PULL *pndr, RESTRICTION_EXIST *r)
{
	int status;
	
	status = ndr_pull_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_exist(NDR_PUSH *pndr, const RESTRICTION_EXIST *r)
{
	int status;
	
	status = ndr_push_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->reserved1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->reserved2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_trailer_align(pndr, 4);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_sub(NDR_PULL *pndr, int flag, RESTRICTION_SUB *r)
{
	int status;
	uint32_t ptr;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->subobject);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_generic_ptr(pndr, &ptr);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != ptr) {
			r->pres = static_cast<RESTRICTION *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(RESTRICTION)));
			if (NULL == r->pres) {
				return NDR_ERR_ALLOC;
			}
		} else {
			r->pres = NULL;
		}
		status = ndr_pull_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = nsp_ndr_pull_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pres);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_sub(NDR_PUSH *pndr, int flag, const RESTRICTION_SUB *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->subobject);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_unique_ptr(pndr, r->pres);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		if (NULL != r->pres) {
			status = nsp_ndr_push_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pres);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction_union(NDR_PULL *pndr, int flag, int *ptype, RESTRICTION_UNION *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, reinterpret_cast<uint32_t *>(ptype));
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		
		status = ndr_pull_union_align(pndr, 5);
		switch (*ptype) {
		case RESTRICTION_TYPE_AND:
			status = nsp_ndr_pull_restriction_and_or(pndr, FLAG_HEADER, &r->res_and);
			break;
		case RESTRICTION_TYPE_OR:
			status = nsp_ndr_pull_restriction_and_or(pndr, FLAG_HEADER, &r->res_or);
			break;
		case RESTRICTION_TYPE_NOT:
			status = nsp_ndr_pull_restriction_not(pndr, FLAG_HEADER, &r->res_not);
			break;
		case RESTRICTION_TYPE_CONTENT:
			status = nsp_ndr_pull_restriction_content(pndr, FLAG_HEADER, &r->res_content);
			break;
		case RESTRICTION_TYPE_PROPERTY:
			status = nsp_ndr_pull_restriction_property(pndr, FLAG_HEADER, &r->res_property);
			break;
		case RESTRICTION_TYPE_PROPCOMPARE:
			status = nsp_ndr_pull_restriction_propcompare(pndr, &r->res_propcompare);
			break;
		case RESTRICTION_TYPE_BITMASK:
			status = nsp_ndr_pull_restriction_bitmask(pndr, &r->res_bitmask);
			break;
		case RESTRICTION_TYPE_SIZE:
			status = nsp_ndr_pull_restriction_size(pndr, &r->res_size);
			break;
		case RESTRICTION_TYPE_EXIST:
			status = nsp_ndr_pull_restriction_exist(pndr, &r->res_exist);
			break;
		case RESTRICTION_TYPE_SUBRESTRICTION:
			status = nsp_ndr_pull_restriction_sub(pndr, FLAG_HEADER, &r->res_sub);
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
		
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		switch (*ptype) {
		case RESTRICTION_TYPE_AND:
			status = nsp_ndr_pull_restriction_and_or(pndr, FLAG_CONTENT, &r->res_and);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case RESTRICTION_TYPE_OR:
			status = nsp_ndr_pull_restriction_and_or(pndr, FLAG_CONTENT, &r->res_or);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case RESTRICTION_TYPE_NOT:
			status = nsp_ndr_pull_restriction_not(pndr, FLAG_CONTENT, &r->res_not);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case RESTRICTION_TYPE_CONTENT:
			status = nsp_ndr_pull_restriction_content(pndr, FLAG_CONTENT, &r->res_content);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case RESTRICTION_TYPE_PROPERTY:
			status = nsp_ndr_pull_restriction_property(pndr, FLAG_CONTENT, &r->res_property);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		case RESTRICTION_TYPE_PROPCOMPARE:
			break;
		case RESTRICTION_TYPE_BITMASK:
			break;
		case RESTRICTION_TYPE_SIZE:
			break;
		case RESTRICTION_TYPE_EXIST:
			break;
		case RESTRICTION_TYPE_SUBRESTRICTION:
			status = nsp_ndr_pull_restriction_sub(pndr, FLAG_CONTENT, &r->res_sub);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction_union(NDR_PUSH *pndr, int flag, int type, const RESTRICTION_UNION *r)
{
	int status;

	if (flag & FLAG_HEADER) {
		status = ndr_push_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, type);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_union_align(pndr, 5);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		switch (type) {
		case RESTRICTION_TYPE_AND:
			status = nsp_ndr_push_restriction_and_or(pndr, FLAG_HEADER, &r->res_and);
			break;
		case RESTRICTION_TYPE_OR:
			status = nsp_ndr_push_restriction_and_or(pndr, FLAG_HEADER, &r->res_or);
			break;
		case RESTRICTION_TYPE_NOT:
			status = nsp_ndr_push_restriction_not(pndr, FLAG_HEADER, &r->res_not);
			break;
		case RESTRICTION_TYPE_CONTENT:
			status = nsp_ndr_push_restriction_content(pndr, FLAG_HEADER, &r->res_content);
			break;
		case RESTRICTION_TYPE_PROPERTY:
			status = nsp_ndr_push_restriction_property(pndr, FLAG_HEADER, &r->res_property);
			break;
		case RESTRICTION_TYPE_PROPCOMPARE:
			status = nsp_ndr_push_restriction_propcompare(pndr, &r->res_propcompare);
			break;
		case RESTRICTION_TYPE_BITMASK:
			status = nsp_ndr_push_restriction_bitmask(pndr, &r->res_bitmask);
			break;
		case RESTRICTION_TYPE_SIZE:
			status = nsp_ndr_push_restriction_size(pndr, &r->res_size);
			break;
		case RESTRICTION_TYPE_EXIST:
			status = nsp_ndr_push_restriction_exist(pndr, &r->res_exist);
			break;
		case RESTRICTION_TYPE_SUBRESTRICTION:
			status = nsp_ndr_push_restriction_sub(pndr, FLAG_HEADER, &r->res_sub);
			break;
		default:
			return NDR_ERR_BAD_SWITCH;
		}
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		switch (type) {
			case RESTRICTION_TYPE_AND:
				status = nsp_ndr_push_restriction_and_or(pndr, FLAG_CONTENT, &r->res_and);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			case RESTRICTION_TYPE_OR:
				status = nsp_ndr_push_restriction_and_or(pndr, FLAG_CONTENT, &r->res_or);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			case RESTRICTION_TYPE_NOT:
				status = nsp_ndr_push_restriction_not(pndr, FLAG_CONTENT, &r->res_not);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			case RESTRICTION_TYPE_CONTENT:
				status = nsp_ndr_push_restriction_content(pndr, FLAG_CONTENT, &r->res_content);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			case RESTRICTION_TYPE_PROPERTY:
				status = nsp_ndr_push_restriction_property(pndr, FLAG_CONTENT, &r->res_property);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			case RESTRICTION_TYPE_PROPCOMPARE:
				break;
			case RESTRICTION_TYPE_BITMASK:
				break;
			case RESTRICTION_TYPE_SIZE:
				break;
			case RESTRICTION_TYPE_EXIST:
				break;
			case RESTRICTION_TYPE_SUBRESTRICTION:
				status = nsp_ndr_push_restriction_sub(pndr, FLAG_CONTENT, &r->res_sub);
				if (NDR_ERR_SUCCESS != status) {
					return status;
				}
				break;
			default:
				return NDR_ERR_BAD_SWITCH;
		}
		
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_pull_restriction(NDR_PULL *pndr, int flag, RESTRICTION *r)
{
	int type;
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_pull_align(pndr, 4);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_uint32(pndr, &r->res_type);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = nsp_ndr_pull_restriction_union(pndr, FLAG_HEADER, &type, &r->res);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (r->res_type != type) {
			return NDR_ERR_BAD_SWITCH;
		}
		status = ndr_pull_trailer_align(pndr, 4);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		type = r->res_type;
		status = nsp_ndr_pull_restriction_union(pndr, FLAG_CONTENT, &type, &r->res);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return NDR_ERR_SUCCESS;
}

static int nsp_ndr_push_restriction(NDR_PUSH *pndr, int flag, const RESTRICTION *r)
{
	int status;
	
	if (flag & FLAG_HEADER) {
		status = ndr_push_align(pndr, 4);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_uint32(pndr, r->res_type);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = nsp_ndr_push_restriction_union(pndr, FLAG_HEADER, r->res_type, &r->res);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_push_trailer_align(pndr, 4);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	
	if (flag & FLAG_CONTENT) {
		status = nsp_ndr_push_restriction_union(pndr, FLAG_CONTENT, r->res_type, &r->res);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspibind(NDR_PULL *pndr, NSPIBIND_IN *r)
{
	int status;
	uint32_t ptr;
	

	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pserver_guid = static_cast<FLATUID *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(FLATUID)));
		if (NULL == r->pserver_guid) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_flatuid(pndr, r->pserver_guid);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pserver_guid = NULL;
	}
	
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspibind(NDR_PUSH *pndr, const NSPIBIND_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pserver_guid);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pserver_guid) {
		status = nsp_ndr_push_flatuid(pndr, r->pserver_guid);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiunbind(NDR_PULL *pndr, NSPIUNBIND_IN *r)
{
	int status;

	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiunbind(NDR_PUSH *pndr, const NSPIUNBIND_OUT *r)
{
	int status;	
	
	status = ndr_push_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_uint32(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiupdatestat(NDR_PULL *pndr, NSPIUPDATESTAT_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pdelta = static_cast<int32_t *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(int32_t)));
		if (NULL == r->pdelta) {
			return NDR_ERR_ALLOC;
		}
		status = ndr_pull_int32(pndr, r->pdelta);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pdelta = NULL;
	}
	
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiupdatestat(NDR_PUSH *pndr, const NSPIUPDATESTAT_OUT *r)
{
	int status;
	
	status = nsp_ndr_push_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->pdelta);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pdelta) {
		status = ndr_push_int32(pndr, *r->pdelta);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_uint32(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiqueryrows(NDR_PULL *pndr, NSPIQUERYROWS_IN *r)
{
	int status;
	uint32_t ptr;
	uint32_t cnt;
	uint32_t size;
	
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->table_count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (r->table_count > 100000) {
		return NDR_ERR_RANGE;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (size != r->table_count) {
			return NDR_ERR_ARRAY_SIZE;
		}
		r->ptable = static_cast<uint32_t *>(ndr_stack_alloc(NDR_STACK_IN, size * sizeof(uint32_t)));
		if (NULL == r->ptable) {
			return NDR_ERR_ALLOC;
		}
		for (cnt=0; cnt<size; cnt++) {
			status = ndr_pull_uint32(pndr, &r->ptable[cnt]);
			if (NDR_ERR_SUCCESS != status) {
				return status;
			}
		}
	} else {
		r->ptable = NULL;
	}
	status = ndr_pull_uint32(pndr, &r->count);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiqueryrows(NDR_PUSH *pndr, const NSPIQUERYROWS_OUT *r)
{
	int status;
	
	status = nsp_ndr_push_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_uint32(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_pull_nspiseekentries(NDR_PULL *pndr, NSPISEEKENTRIES_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_property_value(pndr, FLAG_HEADER|FLAG_CONTENT, &r->target);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->ptable = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->ptable) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->ptable);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->ptable = NULL;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiseekentries(NDR_PUSH *pndr, const NSPISEEKENTRIES_OUT *r)
{
	int status;
	
	status = nsp_ndr_push_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetmatches(NDR_PULL *pndr, NSPIGETMATCHES_IN *r)
{
	int status;
	uint32_t ptr;

	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (0 != ptr) {
		r->preserved = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->preserved) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->preserved);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->preserved = NULL;
	}
	status = ndr_pull_uint32(pndr, &r->reserved2);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pfilter = static_cast<RESTRICTION *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(RESTRICTION)));
		if (NULL == r->pfilter) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_restriction(pndr, FLAG_HEADER|FLAG_CONTENT, r->pfilter);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pfilter = NULL;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->ppropname = static_cast<PROPERTY_NAME *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPERTY_NAME)));
		if (NULL == r->ppropname) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_property_name(pndr, FLAG_HEADER|FLAG_CONTENT, r->ppropname);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->ppropname = NULL;
	}
	
	status = ndr_pull_uint32(pndr, &r->requested);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspigetmatches(NDR_PUSH *pndr, const NSPIGETMATCHES_OUT *r)
{
	int status;
	
	status = nsp_ndr_push_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->poutmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->poutmids) {
		status = nsp_ndr_push_proptag_array(pndr, r->poutmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresortrestriction(NDR_PULL *pndr, NSPIRESORTRESTRICTION_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_proptag_array(pndr, &r->inmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->poutmids = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->poutmids) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->poutmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->poutmids = NULL;
	}
	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspiresortrestriction(NDR_PUSH *pndr, const NSPIRESORTRESTRICTION_OUT *r)
{
	int status;
	
	status = nsp_ndr_push_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->poutmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->poutmids) {
		status = nsp_ndr_push_proptag_array(pndr, r->poutmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspidntomid(NDR_PULL *pndr, NSPIDNTOMID_IN *r)
{
	int status;

	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return nsp_ndr_pull_strings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->names);
}

int nsp_ndr_push_nspidntomid(NDR_PUSH *pndr, const NSPIDNTOMID_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->poutmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->poutmids) {
		status = nsp_ndr_push_proptag_array(pndr, r->poutmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetproplist(NDR_PULL *pndr, NSPIGETPROPLIST_IN *r)
{
	int status;

	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->mid);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->codepage);
}

int nsp_ndr_push_nspigetproplist(NDR_PUSH *pndr, const NSPIGETPROPLIST_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pproptags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pproptags) {
		status = nsp_ndr_push_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetprops(NDR_PULL *pndr, NSPIGETPROPS_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}

	return NDR_ERR_SUCCESS;
}

int nsp_ndr_push_nspigetprops(NDR_PUSH *pndr, const NSPIGETPROPS_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspicomparemids(NDR_PULL *pndr, NSPICOMPAREMIDS_IN *r)
{
	int status;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->mid1);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->mid2);
}

int nsp_ndr_push_nspicomparemids(NDR_PUSH *pndr, const NSPICOMPAREMIDS_OUT *r)
{
	int status;
	
	status = ndr_push_uint32(pndr, r->result);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_push_uint32(pndr, r->result1);
}

int nsp_ndr_pull_nspimodprops(NDR_PULL *pndr, NSPIMODPROPS_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, &r->row);
}

int nsp_ndr_push_nspimodprops(NDR_PUSH *pndr, const NSPIMODPROPS_OUT *r)
{
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigetspecialtable(NDR_PULL *pndr, NSPIGETSPECIALTABLE_IN *r)
{
	int status;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->version);
}

int nsp_ndr_push_nspigetspecialtable(NDR_PUSH *pndr, const NSPIGETSPECIALTABLE_OUT *r)
{
	int status;
	
	status = ndr_push_uint32(pndr, r->version);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspigettemplateinfo(NDR_PULL *pndr, NSPIGETTEMPLATEINFO_IN *r)
{
	int status;
	uint32_t ptr;
	uint32_t size;
	uint32_t offset;
	uint32_t length;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->type);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (0 != ptr) {
		status = ndr_pull_ulong(pndr, &size);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &offset);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		status = ndr_pull_ulong(pndr, &length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		if (0 != offset || length > size) {
			return NDR_ERR_ARRAY_SIZE;
		}
		status = ndr_pull_check_string(pndr, length, sizeof(uint8_t));
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
		r->pdn = static_cast<char *>(ndr_stack_alloc(NDR_STACK_IN, length + 1));
		if (NULL == r->pdn) {
			return NDR_ERR_ALLOC;
		}
		status = ndr_pull_string(pndr, r->pdn, length);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pdn = NULL;
	}
	status = ndr_pull_uint32(pndr, &r->codepage);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->locale_id);
}

int nsp_ndr_push_nspigettemplateinfo(NDR_PUSH *pndr, const NSPIGETTEMPLATEINFO_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pdata);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pdata) {
		status = nsp_ndr_push_property_row(pndr, FLAG_HEADER|FLAG_CONTENT, r->pdata);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspimodlinkatt(NDR_PULL *pndr, NSPIMODLINKATT_IN *r)
{
	int status;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->flags);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->proptag);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->mid);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return nsp_ndr_pull_binary_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->entry_ids);
}

int nsp_ndr_push_nspimodlinkatt(NDR_PUSH *pndr, const NSPIMODLINKATT_OUT *r)
{
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiquerycolumns(NDR_PULL *pndr, NSPIQUERYCOLUMNS_IN *r)
{
	int status;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	return ndr_pull_uint32(pndr, &r->flags);
}

int nsp_ndr_push_nspiquerycolumns(NDR_PUSH *pndr, const NSPIQUERYCOLUMNS_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pcolumns);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pcolumns) {
		status = nsp_ndr_push_proptag_array(pndr, r->pcolumns);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresolvenames(NDR_PULL *pndr, NSPIRESOLVENAMES_IN *r)
{
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}
	return nsp_ndr_pull_strings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->strs);
	
}

int nsp_ndr_push_nspiresolvenames(NDR_PUSH *pndr, const NSPIRESOLVENAMES_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pmids) {
		status = nsp_ndr_push_proptag_array(pndr, r->pmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

int nsp_ndr_pull_nspiresolvenamesw(NDR_PULL *pndr, NSPIRESOLVENAMESW_IN *r)
{
	
	int status;
	uint32_t ptr;
	
	status = ndr_pull_context_handle(pndr, &r->handle);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_uint32(pndr, &r->reserved);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = nsp_ndr_pull_stat(pndr, &r->stat);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	status = ndr_pull_generic_ptr(pndr, &ptr);
	if (0 != ptr) {
		r->pproptags = static_cast<PROPTAG_ARRAY *>(ndr_stack_alloc(NDR_STACK_IN, sizeof(PROPTAG_ARRAY)));
		if (NULL == r->pproptags) {
			return NDR_ERR_ALLOC;
		}
		status = nsp_ndr_pull_proptag_array(pndr, r->pproptags);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	} else {
		r->pproptags = NULL;
	}
	
	return nsp_ndr_pull_wstrings_array(pndr, FLAG_HEADER|FLAG_CONTENT, &r->strs);
}

int nsp_ndr_push_nspiresolvenamesw(NDR_PUSH *pndr, const NSPIRESOLVENAMESW_OUT *r)
{
	int status;
	
	status = ndr_push_unique_ptr(pndr, r->pmids);
	if (NDR_ERR_SUCCESS != status) {
		return status;
	}
	if (NULL != r->pmids) {
		status = nsp_ndr_push_proptag_array(pndr, r->pmids);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	status = ndr_push_unique_ptr(pndr, r->prows);
	if (NULL != r->prows) {
		status = nsp_ndr_push_proprow_set(pndr, FLAG_HEADER|FLAG_CONTENT, r->prows);
		if (NDR_ERR_SUCCESS != status) {
			return status;
		}
	}
	return ndr_push_uint32(pndr, r->result);
}

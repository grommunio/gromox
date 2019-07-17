#include "request_parser.h"
#include <stdio.h>


enum {
	PARAM_TYPE_STRING = 0,
	PARAM_TYPE_ARRAY
};

typedef struct _ITEM_DATA {
	int type;
	void *pdata;
} ITEM_DATA;

static void request_parser_unencode(const char *src, char *dest);

REQUEST_PARSER* request_parser_init(const char *request_string)
{
	int len;
	char *ptr;
	char *ptr1;
	char *ptoken;
	char *pparam;
	char *last_ptr;
	ITEM_DATA *pitem;
	ITEM_DATA tmp_item;
	ASSOC_ARRAY *parray;
	IDX_ARRAY *pindex;
	char *decoded_string;
	
	parray = assoc_array_init(sizeof(ITEM_DATA));
	if (NULL == parray) {
		return NULL;
	}
	len = strlen(request_string);
	decoded_string = (char*)malloc(len + 2);
	if (NULL == decoded_string) {
		assoc_array_free(parray);
		return NULL;
	}
	request_parser_unencode(request_string, decoded_string);
	len = strlen(decoded_string);
	if (len > 0 && '\n' == decoded_string[len - 1]) {
		len --;
		decoded_string[len] = '\0';
	}
	
	if (len > 0) {
		decoded_string[len] = '&';
		len ++;
		decoded_string[len] = '\0';
	}
	
	ptr = decoded_string;
	last_ptr = decoded_string;
	
	while ('\0' != *ptr) {
		if ('&' == *ptr) {
			/* check if the '&' is only a character of the value */
			ptr1 = strchr(ptr + 1, '&');
			if (NULL != ptr1 && NULL == memchr(
				ptr + 1, '=', ptr1 - ptr - 1)) {
				ptr ++;
				continue;
			}
			*ptr = '\0';
			ptoken = strchr(last_ptr, '=');
			if (NULL != ptoken) {
				*ptoken = '\0';
				ptoken ++;
				pparam = strdup(ptoken);
				if (NULL != pparam) {
					pitem = (ITEM_DATA*)assoc_array_get_by_key(parray,
								last_ptr);
					if (NULL == pitem) {
						tmp_item.type = PARAM_TYPE_STRING;
						tmp_item.pdata = pparam;
						assoc_array_assign(parray, last_ptr, &tmp_item);
					} else {
						if (PARAM_TYPE_STRING == pitem->type) {
							pindex = idx_array_init(sizeof(char*));
							if (NULL != pindex) {
								idx_array_append(pindex, &pitem->pdata);
								idx_array_append(pindex, &pparam);
								tmp_item.type = PARAM_TYPE_ARRAY;
								tmp_item.pdata = pindex;
								assoc_array_eliminate(parray, last_ptr);
								assoc_array_assign(parray,
									last_ptr, &tmp_item);
							} else {
								free(pparam);
							}
						} else {
							idx_array_append((IDX_ARRAY*)pitem->pdata,
								&pparam);
						}
					}
				}
			}
			last_ptr = ptr + 1;
		}
		ptr ++;
	}
	
	free(decoded_string);
	return parray;
}

const char* request_parser_get(REQUEST_PARSER *pparser, const char *name)
{
	ITEM_DATA *pitem;

	if (NULL == pparser) {
		return NULL;
	}
	pitem = (ITEM_DATA*)assoc_array_get_by_key(pparser, name);
	if (NULL == pitem) {
		return NULL;
	}

	if (PARAM_TYPE_STRING == pitem->type) {
		return pitem->pdata;
	}
	
	return NULL;
}

IDX_ARRAY* request_parser_get_array(REQUEST_PARSER *pparser, const char *name)
{
	ITEM_DATA *pitem;

	if (NULL == pparser) {
		return NULL;
	}
	pitem = (ITEM_DATA*)assoc_array_get_by_key(pparser, name);
	if (NULL == pitem) {
		return NULL;
	}
	if (PARAM_TYPE_ARRAY == pitem->type) {
		return pitem->pdata;
	}
	return NULL;
}

size_t request_parser_num(REQUEST_PARSER *pparser)
{
	if (NULL == pparser) {
		return 0;
	}
	return assoc_array_get_elements_num(pparser);
}

static void request_parser_enum(const char *key, ITEM_DATA *pitem)
{
	char **ppvalue;
	size_t i, num;

	if (PARAM_TYPE_STRING == pitem->type) {
		free(pitem->pdata);
	} else {
		num = idx_array_get_capacity((IDX_ARRAY*)pitem->pdata);
		for (i=0; i<num; i++) {
			ppvalue = (char**)idx_array_get_item(
						(IDX_ARRAY*)pitem->pdata, i);
			free(*ppvalue);
		}
		idx_array_free((IDX_ARRAY*)pitem->pdata);
	}
}

void request_parser_free(REQUEST_PARSER *pparser)
{
	assoc_array_foreach(pparser, (ASSOC_ARRAY_ENUM)request_parser_enum);
	assoc_array_free(pparser);
}

static void request_parser_unencode(const char *src, char *dest)
{
	int code;
	const char *last;
	
	last = src + strlen(src);
	for (; src != last; src++, dest++) {
		if (*src == '+') {
			*dest = ' ';
		} else if (*src == '%') {
			if (sscanf(src+1, "%2x", &code) != 1) {
				code = '?';
			}
			*dest = code;
			src +=2;
		} else {
			*dest = *src;
		}
	}
	*dest = '\0';
}


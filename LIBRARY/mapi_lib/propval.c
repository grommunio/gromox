#include <gromox/mapidefs.h>
#include "guid.h"
#include "util.h"
#include "propval.h"
#include "restriction.h"
#include "rule_actions.h"
#include <stdlib.h>
#include <string.h>

void* propval_dup(uint16_t type, void *pvalue)
{
	int i;
	void *preturn;
	uint32_t length;
	
	if (NULL == pvalue) {
		debug_info("[propval]: cannot duplicate NULL propval");
		return NULL;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		preturn = malloc(sizeof(TYPED_PROPVAL));
		if (NULL == preturn) {
			return NULL;
		}
		((TYPED_PROPVAL*)preturn)->type = ((TYPED_PROPVAL*)pvalue)->type;
		((TYPED_PROPVAL*)preturn)->pvalue = propval_dup(
											((TYPED_PROPVAL*)pvalue)->type,
											((TYPED_PROPVAL*)pvalue)->pvalue);
		if (NULL == ((TYPED_PROPVAL*)preturn)->pvalue) {
			free(preturn);
			return NULL;
		}
		return preturn;
	case PT_SHORT:
		preturn = malloc(sizeof(uint16_t));
		if (NULL == preturn) {
			return NULL;
		}
		*(uint16_t*)preturn = *(uint16_t*)pvalue;
		return preturn;
	case PT_ERROR:
	case PT_LONG:
		preturn = malloc(sizeof(uint32_t));
		if (NULL == preturn) {
			return NULL;
		}
		*(uint32_t*)preturn = *(uint32_t*)pvalue;
		return preturn;
	case PT_FLOAT:
		preturn = malloc(sizeof(float));
		if (NULL == preturn) {
			return NULL;
		}
		*(float*)preturn = *(float*)pvalue;
		return preturn;
	case PT_DOUBLE:
	case PT_APPTIME:
		preturn = malloc(sizeof(double));
		if (NULL == preturn) {
			return NULL;
		}
		*(double*)preturn = *(double*)pvalue;
		return preturn;
	case PT_BOOLEAN:
		preturn = malloc(sizeof(uint8_t));
		if (NULL == preturn) {
			return NULL;
		}
		*(uint8_t*)preturn = *(uint8_t*)pvalue;
		return preturn;
	case PT_CURRENCY:
	case PT_I8:
	case PROPVAL_TYPE_FILETIME:
		preturn = malloc(sizeof(uint64_t));
		if (NULL == preturn) {
			return NULL;
		}
		*(uint64_t*)preturn = *(uint64_t*)pvalue;
		return preturn;
	case PT_STRING8:
	case PT_UNICODE:
		return strdup(pvalue);
	case PT_CLSID:
		preturn = malloc(sizeof(GUID));
		if (NULL == preturn) {
			return NULL;
		}
		memcpy(preturn, pvalue, sizeof(GUID));
		return preturn;
	case PROPVAL_TYPE_SVREID:
		preturn = malloc(sizeof(SVREID));
		if (NULL == preturn) {
			return NULL;
		}
		if (NULL != ((SVREID*)pvalue)->pbin) {
			((SVREID*)preturn)->pbin = malloc(sizeof(BINARY));
			if (NULL == ((SVREID*)preturn)->pbin) {
				free(preturn);
				return NULL;
			}
			((SVREID*)preturn)->pbin->cb = ((SVREID*)pvalue)->pbin->cb;
			length = ((SVREID*)pvalue)->pbin->cb;
			if (0 == length) {
				((SVREID*)preturn)->pbin->pb = NULL;
			} else {
				((SVREID*)preturn)->pbin->pb = malloc(length);
				if (NULL == ((SVREID*)preturn)->pbin->pb) {
					free(((SVREID*)preturn)->pbin);
					free(preturn);
					return NULL;
				}
				memcpy(((SVREID*)preturn)->pbin->pb,
					((SVREID*)pvalue)->pbin->pb, length);
			}
		} else {
			memcpy(preturn, pvalue, sizeof(SVREID));
		}
		return preturn;
	case PROPVAL_TYPE_RESTRICTION:
		return restriction_dup(pvalue);
	case PROPVAL_TYPE_RULE:
		return rule_actions_dup(pvalue);
	case PT_BINARY:
	case PT_OBJECT:
		preturn = malloc(sizeof(BINARY));
		if (NULL == preturn) {
			return NULL;
		}
		((BINARY*)preturn)->cb = ((BINARY*)pvalue)->cb;
		length = ((BINARY*)pvalue)->cb;
		if (0 == length) {
			((BINARY*)preturn)->pb = NULL;
		} else {
			((BINARY*)preturn)->pb = malloc(length);
			if (NULL == ((BINARY*)preturn)->pb) {
				free(preturn);
				return NULL;
			}
			memcpy(((BINARY*)preturn)->pb, ((BINARY*)pvalue)->pb, length);
		}
		return preturn;
	case PT_MV_SHORT:
		preturn = malloc(sizeof(SHORT_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((SHORT_ARRAY*)preturn)->count = ((SHORT_ARRAY*)pvalue)->count;
		if (0 == ((SHORT_ARRAY*)pvalue)->count) {
			((SHORT_ARRAY*)preturn)->ps = NULL;
		} else {
			((SHORT_ARRAY*)preturn)->ps = 
					malloc(sizeof(uint16_t)*((SHORT_ARRAY*)pvalue)->count);
			if (NULL == ((SHORT_ARRAY*)preturn)->ps) {
				free(preturn);
				return NULL;
			}
			memcpy(((SHORT_ARRAY*)preturn)->ps, ((SHORT_ARRAY*)pvalue)->ps,
						sizeof(uint16_t)*((SHORT_ARRAY*)pvalue)->count);
		}
		return preturn;
	case PT_MV_LONG:
		preturn = malloc(sizeof(LONG_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((LONG_ARRAY*)preturn)->count = ((LONG_ARRAY*)pvalue)->count;
		if (0 == ((LONG_ARRAY*)pvalue)->count) {
			((LONG_ARRAY*)preturn)->pl = NULL;
		} else {
			((LONG_ARRAY*)preturn)->pl =
					malloc(sizeof(uint32_t)*((LONG_ARRAY*)pvalue)->count);
			if (NULL == ((LONG_ARRAY*)preturn)->pl) {
				free(preturn);
				return NULL;
			}
			memcpy(((LONG_ARRAY*)preturn)->pl, ((LONG_ARRAY*)pvalue)->pl,
						sizeof(uint32_t)*((LONG_ARRAY*)pvalue)->count);
		}
		return preturn;
	case PT_MV_I8:
		preturn = malloc(sizeof(LONGLONG_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((LONGLONG_ARRAY*)preturn)->count = ((LONGLONG_ARRAY*)pvalue)->count;
		if (0 == ((LONGLONG_ARRAY*)pvalue)->count) {
			((LONGLONG_ARRAY*)preturn)->pll = NULL;
		} else {
			((LONGLONG_ARRAY*)preturn)->pll =
					malloc(sizeof(uint64_t)*((LONGLONG_ARRAY*)pvalue)->count);
			if (NULL == ((LONGLONG_ARRAY*)preturn)->pll) {
				free(preturn);
				return NULL;
			}
			memcpy(((LONGLONG_ARRAY*)preturn)->pll, ((LONGLONG_ARRAY*)pvalue)->pll,
						sizeof(uint64_t)*((LONGLONG_ARRAY*)pvalue)->count);
		}
		return preturn;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		preturn = malloc(sizeof(STRING_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((STRING_ARRAY*)preturn)->count = ((STRING_ARRAY*)pvalue)->count;
		if (0 == ((STRING_ARRAY*)pvalue)->count) {
			((STRING_ARRAY*)preturn)->ppstr = NULL;
		} else {
			((STRING_ARRAY*)preturn)->ppstr =
					malloc(sizeof(void*)*((STRING_ARRAY*)pvalue)->count);
			if (NULL == ((STRING_ARRAY*)preturn)->ppstr) {
				free(preturn);
				return NULL;
			}
			for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
				((STRING_ARRAY*)preturn)->ppstr[i] =
						strdup(((STRING_ARRAY*)pvalue)->ppstr[i]);
				if (NULL == ((STRING_ARRAY*)preturn)->ppstr[i]) {
					for (i-=1;i>=0; i--) {
						free(((STRING_ARRAY*)preturn)->ppstr[i]);
					}
					free(((STRING_ARRAY*)preturn)->ppstr);
					free(preturn);
					return NULL;
				}
			}
		}
		return preturn;
	case PT_MV_CLSID:
		preturn = malloc(sizeof(GUID_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((GUID_ARRAY*)preturn)->count = ((GUID_ARRAY*)pvalue)->count;
		if (0 == ((GUID_ARRAY*)pvalue)->count) {
			((GUID_ARRAY*)preturn)->pguid = NULL;
		} else {
			((GUID_ARRAY*)preturn)->pguid =
				malloc(sizeof(uint32_t)*((GUID_ARRAY*)pvalue)->count);
			if (NULL == ((GUID_ARRAY*)preturn)->pguid) {
				free(preturn);
				return NULL;
			}
			memcpy(((GUID_ARRAY*)preturn)->pguid,((GUID_ARRAY*)pvalue)->pguid,
									sizeof(GUID)*((GUID_ARRAY*)pvalue)->count);
		}
		return preturn;
	case PT_MV_BINARY:
		preturn = malloc(sizeof(BINARY_ARRAY));
		if (NULL == preturn) {
			return NULL;
		}
		((BINARY_ARRAY*)preturn)->count = ((BINARY_ARRAY*)pvalue)->count;
		if (0 == ((BINARY_ARRAY*)pvalue)->count) {
			((BINARY_ARRAY*)preturn)->pbin = NULL;
		} else {
			((BINARY_ARRAY*)preturn)->pbin =
				malloc(sizeof(BINARY)*((BINARY_ARRAY*)pvalue)->count);
			if (NULL == ((BINARY_ARRAY*)preturn)->pbin) {
				free(preturn);
				return NULL;
			}
			for (i=0; i<((BINARY_ARRAY*)pvalue)->count; i++) {
				((BINARY_ARRAY*)preturn)->pbin[i].cb =
						((BINARY_ARRAY*)pvalue)->pbin[i].cb;
				length = ((BINARY_ARRAY*)pvalue)->pbin[i].cb;
				if (0 == length) {
					((BINARY_ARRAY*)preturn)->pbin[i].pb = NULL;
					continue;
				}
				((BINARY_ARRAY*)preturn)->pbin[i].pb = malloc(length);
				if (NULL == ((BINARY_ARRAY*)preturn)->pbin[i].pb) {
					for (i-=1; i>=0; i--) {
						if (NULL != ((BINARY_ARRAY*)preturn)->pbin[i].pb) {
							free(((BINARY_ARRAY*)preturn)->pbin[i].pb);
						}
					}
					free(((BINARY_ARRAY*)preturn)->pbin);
					free(preturn);
					return NULL;
				}
				memcpy(((BINARY_ARRAY*)preturn)->pbin[i].pb,
					((BINARY_ARRAY*)pvalue)->pbin[i].pb, length);
			}
		}
		return preturn;
	}
	return NULL;
}

void propval_free(uint16_t type, void *pvalue)
{
	int i;
	
	if (NULL == pvalue) {
		debug_info("[propval] cannot free NULL propval");
		return;
	}
	switch (type) {
	case PT_UNSPECIFIED:
		propval_free(((TYPED_PROPVAL*)pvalue)->type,
					((TYPED_PROPVAL*)pvalue)->pvalue);
		break;
	case PT_SHORT:
	case PT_LONG:
	case PT_FLOAT:
	case PT_DOUBLE:
	case PT_CURRENCY:
	case PT_APPTIME:
	case PT_ERROR:
	case PT_BOOLEAN:
	case PT_I8:
	case PT_STRING8:
	case PT_UNICODE:
	case PROPVAL_TYPE_FILETIME:
	case PT_CLSID:
		break;
	case PROPVAL_TYPE_RESTRICTION:
		restriction_free(pvalue);
		return;
	case PROPVAL_TYPE_RULE:
		rule_actions_free(pvalue);
		return;
	case PROPVAL_TYPE_SVREID:
		if (NULL != ((SVREID*)pvalue)->pbin) {
			if (NULL != ((SVREID*)pvalue)->pbin->pb) {
				free(((SVREID*)pvalue)->pbin->pb);
			}
			free(((SVREID*)pvalue)->pbin);
		}
		break;
	case PT_BINARY:
	case PT_OBJECT:
		if (NULL != ((BINARY*)pvalue)->pb) {
			free(((BINARY*)pvalue)->pb);
		}
		break;
	case PT_MV_SHORT:
		if (NULL != ((SHORT_ARRAY*)pvalue)->ps) {
			free(((SHORT_ARRAY*)pvalue)->ps);
		}
		break;
	case PT_MV_LONG:
		if (NULL != ((LONG_ARRAY*)pvalue)->pl) {
			free(((LONG_ARRAY*)pvalue)->pl);
		}
		break;
	case PT_MV_I8:
		if (NULL != ((LONGLONG_ARRAY*)pvalue)->pll) {
			free(((LONGLONG_ARRAY*)pvalue)->pll);
		}
		break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			free(((STRING_ARRAY*)pvalue)->ppstr[i]);
		}
		if (NULL != ((STRING_ARRAY*)pvalue)->ppstr) {
			free(((STRING_ARRAY*)pvalue)->ppstr);
		}
		break;
	case PT_MV_CLSID:
		if (NULL != ((GUID_ARRAY*)pvalue)->pguid) {
			free(((GUID_ARRAY*)pvalue)->pguid);
		}
		break;
	case PT_MV_BINARY:
		for (i=0; i<((BINARY_ARRAY*)pvalue)->count; i++) {
			if (NULL != ((BINARY_ARRAY*)pvalue)->pbin[i].pb) {
				free(((BINARY_ARRAY*)pvalue)->pbin[i].pb);
			}
		}
		if (NULL != ((BINARY_ARRAY*)pvalue)->pbin) {
			free(((BINARY_ARRAY*)pvalue)->pbin);
		}
		break;
	}
	free(pvalue);
}

static uint32_t propval_utf16_len(const char *putf8_string)
{
	int len;
	
	if (FALSE == utf8_len(putf8_string, &len)) {
		return 0;
	}
	return 2*len;
}

uint32_t propval_size(uint16_t type, void *pvalue)
{
	int i;
	uint32_t length;
	
	switch (type) {
	case PT_UNSPECIFIED:
		return propval_size(((TYPED_PROPVAL*)pvalue)->type,
						((TYPED_PROPVAL*)pvalue)->pvalue);
	case PT_SHORT:
		return sizeof(uint16_t);
	case PT_ERROR:
	case PT_LONG:
		return sizeof(uint32_t);
	case PT_FLOAT:
		return sizeof(float);
	case PT_DOUBLE:
	case PT_APPTIME:
		return sizeof(double);
	case PT_BOOLEAN:
		return sizeof(uint8_t);
	case PT_OBJECT:
	case PT_BINARY:
		return ((BINARY*)pvalue)->cb;
	case PT_CURRENCY:
	case PT_I8:
	case PROPVAL_TYPE_FILETIME:
		return sizeof(uint64_t);
	case PT_STRING8:
		return strlen(pvalue) + 1;
	case PT_UNICODE:
		return propval_utf16_len(pvalue);
	case PT_CLSID:
		return 16;
	case PROPVAL_TYPE_SVREID:
		if (NULL != ((SVREID*)pvalue)->pbin) {
			return ((SVREID*)pvalue)->pbin->cb + 1;
		}
		return 21;
	case PROPVAL_TYPE_RESTRICTION:
		return restriction_size(pvalue);
	case PROPVAL_TYPE_RULE:
		return rule_actions_size(pvalue);
	case PT_MV_SHORT:
		return sizeof(uint16_t)*((SHORT_ARRAY*)pvalue)->count;
	case PT_MV_LONG:
		return sizeof(uint32_t)*((LONG_ARRAY*)pvalue)->count;
	case PT_MV_I8:
		return sizeof(uint64_t)*((LONGLONG_ARRAY*)pvalue)->count;
	case PT_MV_STRING8:
		length = 0;
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			length += strlen(((STRING_ARRAY*)pvalue)->ppstr[i]) + 1;
		}
		return length;
	case PT_MV_UNICODE:
		length = 0;
		for (i=0; i<((STRING_ARRAY*)pvalue)->count; i++) {
			length += propval_utf16_len(((STRING_ARRAY*)pvalue)->ppstr[i]);
		}
		return length;
	case PT_MV_CLSID:
		return 16*((GUID_ARRAY*)pvalue)->count;
	case PT_MV_BINARY:
		length = 0;
		for (i=0; i<((BINARY_ARRAY*)pvalue)->count; i++) {
			length += ((BINARY_ARRAY*)pvalue)->pbin[i].cb;
		}
		return length;
	}
	return 0;
}

BOOL propval_compare_relop(uint8_t relop,
	uint16_t proptype, void *pvalue1, void *pvalue2)
{
	int i;
	
	switch (proptype) {
	case PT_SHORT:
		switch (relop) {
		case RELOP_LT:
			if (*(uint16_t*)pvalue1 < *(uint16_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(uint16_t*)pvalue1 <= *(uint16_t*)pvalue2) {
				return TRUE;
			}
		case RELOP_GT:
			if (*(uint16_t*)pvalue1 > *(uint16_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(uint16_t*)pvalue1 >= *(uint16_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(uint16_t*)pvalue1 == *(uint16_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(uint16_t*)pvalue1 != *(uint16_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_LONG:
	case PT_ERROR:
		switch (relop) {
		case RELOP_LT:
			if (*(uint32_t*)pvalue1 < *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(uint32_t*)pvalue1 <= *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (*(uint32_t*)pvalue1 > *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(uint32_t*)pvalue1 >= *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(uint32_t*)pvalue1 == *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(uint32_t*)pvalue1 != *(uint32_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_BOOLEAN:
		switch (relop) {
		case RELOP_LT:
			if (*(uint8_t*)pvalue1 < *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(uint8_t*)pvalue1 <= *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (*(uint8_t*)pvalue1 > *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(uint8_t*)pvalue1 >= *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(uint8_t*)pvalue1 == *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(uint8_t*)pvalue1 != *(uint8_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_CURRENCY:
	case PT_I8:
	case PROPVAL_TYPE_FILETIME:
		switch (relop) {
		case RELOP_LT:
			if (*(uint64_t*)pvalue1 < *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(uint64_t*)pvalue1 <= *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (*(uint64_t*)pvalue1 > *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(uint64_t*)pvalue1 >= *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(uint64_t*)pvalue1 == *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(uint64_t*)pvalue1 != *(uint64_t*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_FLOAT:
		switch (relop) {
		case RELOP_LT:
			if (*(float*)pvalue1 < *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(float*)pvalue1 <= *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (*(float*)pvalue1 > *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(float*)pvalue1 >= *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(float*)pvalue1 == *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(float*)pvalue1 != *(float*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_DOUBLE:
	case PT_APPTIME:
		switch (relop) {
		case RELOP_LT:
			if (*(double*)pvalue1 < *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (*(double*)pvalue1 <= *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (*(double*)pvalue1 > *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (*(double*)pvalue1 >= *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (*(double*)pvalue1 == *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (*(double*)pvalue1 != *(double*)pvalue2) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_STRING8:
	case PT_UNICODE:
		switch (relop) {
		case RELOP_LT:
			if (strcasecmp(pvalue1, pvalue2) < 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (strcasecmp(pvalue1, pvalue2) <= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (strcasecmp(pvalue1, pvalue2) > 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (strcasecmp(pvalue1, pvalue2) >= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (strcasecmp(pvalue1, pvalue2) == 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (strcasecmp(pvalue1, pvalue2) != 0) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_CLSID:
		switch (relop) {
		case RELOP_LT:
			if (guid_compare(pvalue1, pvalue2) < 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (guid_compare(pvalue1, pvalue2) <= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (guid_compare(pvalue1, pvalue2) > 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (guid_compare(pvalue1, pvalue2) >= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (guid_compare(pvalue1, pvalue2) == 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (guid_compare(pvalue1, pvalue2) != 0) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_BINARY:
		switch (relop) {
		case RELOP_LT:
			if (0 == ((BINARY*)pvalue1)->cb &&
				0 != ((BINARY*)pvalue2)->cb) {
				return TRUE;
			}
			if (0 == ((BINARY*)pvalue1)->cb ||
				0 == ((BINARY*)pvalue2)->cb) {
				return FALSE;	
			}
			if (((BINARY*)pvalue1)->cb >
				((BINARY*)pvalue2)->cb) {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue2)->cb) < 0) {
					return TRUE;
				}
			} else {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue1)->cb) < 0) {
					return TRUE;
				}
			}
			return FALSE;
		case RELOP_LE:
			if (0 == ((BINARY*)pvalue1)->cb) {
				return TRUE;
			}
			if (0 == ((BINARY*)pvalue2)->cb) {
				return FALSE;
			}
			if (((BINARY*)pvalue1)->cb >
				((BINARY*)pvalue2)->cb) {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue2)->cb) <= 0) {
					return TRUE;
				}
			} else {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue1)->cb) <= 0) {
					return TRUE;
				}
			}
			return FALSE;
		case RELOP_GT:
			if (0 != ((BINARY*)pvalue1)->cb &&
				0 == ((BINARY*)pvalue2)->cb) {
				return TRUE;
			}
			if (0 == ((BINARY*)pvalue1)->cb ||
				0 == ((BINARY*)pvalue2)->cb) {
				return FALSE;	
			}
			if (((BINARY*)pvalue1)->cb >
				((BINARY*)pvalue2)->cb) {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue2)->cb) > 0) {
					return TRUE;
				}
			} else {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue1)->cb) > 0) {
					return TRUE;
				}
			}
			return FALSE;
		case RELOP_GE:
			if (0 == ((BINARY*)pvalue2)->cb) {
				return TRUE;
			}
			if (0 == ((BINARY*)pvalue1)->cb) {
				return FALSE;	
			}
			if (((BINARY*)pvalue1)->cb >
				((BINARY*)pvalue2)->cb) {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue2)->cb) >= 0) {
					return TRUE;
				}
			} else {
				if (memcmp(((BINARY*)pvalue1)->pb,
					((BINARY*)pvalue2)->pb,
					((BINARY*)pvalue1)->cb) >= 0) {
					return TRUE;
				}
			}
			return FALSE;
		case RELOP_EQ:
			if (((BINARY*)pvalue1)->cb != ((BINARY*)pvalue2)->cb) {
				return FALSE;
			}
			if (NULL == ((BINARY*)pvalue1)->pb) {
				return TRUE;
			}
			if (memcmp(((BINARY*)pvalue1)->pb, ((BINARY*)pvalue2)->pb,
				((BINARY*)pvalue1)->cb) == 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (((BINARY*)pvalue1)->cb != ((BINARY*)pvalue2)->cb) {
				return TRUE;
			}
			if (NULL == ((BINARY*)pvalue1)->pb) {
				return FALSE;
			}
			if (memcmp(((BINARY*)pvalue1)->pb, ((BINARY*)pvalue2)->pb,
				((BINARY*)pvalue1)->cb) != 0) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PROPVAL_TYPE_SVREID:
		switch (relop) {
		case RELOP_EQ:
			if ((NULL == ((SVREID*)pvalue1)->pbin &&
				NULL != ((SVREID*)pvalue2)->pbin) ||
				(NULL != ((SVREID*)pvalue1)->pbin &&
				NULL == ((SVREID*)pvalue2)->pbin)) {
				return FALSE;	
			} else if (NULL != ((SVREID*)pvalue1)->pbin
				&& NULL != ((SVREID*)pvalue2)->pbin) {
				if (((SVREID*)pvalue1)->pbin->cb !=
					((SVREID*)pvalue2)->pbin->cb) {
					return FALSE;	
				}
				if (0 == ((SVREID*)pvalue1)->pbin->cb) {
					return TRUE;
				}
				if (0 == memcmp(((SVREID*)pvalue1)->pbin->pb,
					((SVREID*)pvalue2)->pbin->pb,
					((SVREID*)pvalue1)->pbin->cb)) {
					return TRUE;	
				}
				return FALSE;
			}
			if (((SVREID*)pvalue1)->folder_id !=
				((SVREID*)pvalue2)->folder_id) {
				return FALSE;
			}
			if (((SVREID*)pvalue1)->message_id !=
				((SVREID*)pvalue2)->message_id) {
				return FALSE;
			}
			if (((SVREID*)pvalue1)->instance !=
				((SVREID*)pvalue2)->instance) {
				return FALSE;
			}
			return TRUE;
		case RELOP_NE:
			if ((NULL == ((SVREID*)pvalue1)->pbin &&
				NULL != ((SVREID*)pvalue2)->pbin) ||
				(NULL != ((SVREID*)pvalue1)->pbin &&
				NULL == ((SVREID*)pvalue2)->pbin)) {
				return TRUE;	
			} else if (NULL != ((SVREID*)pvalue1)->pbin
				&& NULL != ((SVREID*)pvalue2)->pbin) {
				if (((SVREID*)pvalue1)->pbin->cb !=
					((SVREID*)pvalue2)->pbin->cb) {
					return TRUE;	
				}
				if (0 == ((SVREID*)pvalue1)->pbin->cb) {
					return FALSE;
				}
				if (0 != memcmp(((SVREID*)pvalue1)->pbin->pb,
					((SVREID*)pvalue2)->pbin->pb,
					((SVREID*)pvalue1)->pbin->cb)) {
					return TRUE;	
				}
				return FALSE;
			}
			if (((SVREID*)pvalue1)->folder_id ==
				((SVREID*)pvalue2)->folder_id) {
				return FALSE;
			}
			if (((SVREID*)pvalue1)->message_id ==
				((SVREID*)pvalue2)->message_id) {
				return FALSE;
			}
			if (((SVREID*)pvalue1)->instance ==
				((SVREID*)pvalue2)->instance) {
				return FALSE;
			}
			return TRUE;
		}
		return FALSE;
	case PT_MV_SHORT:
		switch (relop) {
		case RELOP_EQ:
			if (((SHORT_ARRAY*)pvalue1)->count !=
				((SHORT_ARRAY*)pvalue2)->count) {
				return FALSE;
			}
			if (0 != memcmp(((SHORT_ARRAY*)pvalue1)->ps,
				((SHORT_ARRAY*)pvalue2)->ps, sizeof(uint16_t)
				*((SHORT_ARRAY*)pvalue1)->count)) {
				return FALSE;
			}
			return TRUE;
		case RELOP_NE:
			if (((SHORT_ARRAY*)pvalue1)->count !=
				((SHORT_ARRAY*)pvalue2)->count) {
				return TRUE;
			}
			if (0 != memcmp(((SHORT_ARRAY*)pvalue1)->ps,
				((SHORT_ARRAY*)pvalue2)->ps, sizeof(uint16_t)
				*((SHORT_ARRAY*)pvalue1)->count)) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_MV_LONG:
		switch (relop) {
		case RELOP_EQ:
			if (((LONG_ARRAY*)pvalue1)->count !=
				((LONG_ARRAY*)pvalue2)->count) {
				return FALSE;
			}
			if (0 != memcmp(((LONG_ARRAY*)pvalue1)->pl,
				((LONG_ARRAY*)pvalue2)->pl, sizeof(uint32_t)
				*((LONG_ARRAY*)pvalue1)->count)) {
				return FALSE;
			}
			return TRUE;
		case RELOP_NE:
			if (((LONG_ARRAY*)pvalue1)->count !=
				((LONG_ARRAY*)pvalue2)->count) {
				return TRUE;
			}
			if (0 != memcmp(((LONG_ARRAY*)pvalue1)->pl,
				((LONG_ARRAY*)pvalue2)->pl, sizeof(uint32_t)
				*((LONG_ARRAY*)pvalue1)->count)) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_MV_I8:
		switch (relop) {
		case RELOP_EQ:
			if (((LONGLONG_ARRAY*)pvalue1)->count !=
				((LONGLONG_ARRAY*)pvalue2)->count) {
				return FALSE;
			}
			if (0 != memcmp(((LONGLONG_ARRAY*)pvalue1)->pll,
				((LONGLONG_ARRAY*)pvalue2)->pll, sizeof(uint64_t)
				*((LONGLONG_ARRAY*)pvalue1)->count)) {
				return FALSE;
			}
			return TRUE;
		case RELOP_NE:
			if (((LONGLONG_ARRAY*)pvalue1)->count !=
				((LONGLONG_ARRAY*)pvalue2)->count) {
				return TRUE;
			}
			if (0 != memcmp(((LONGLONG_ARRAY*)pvalue1)->pll,
				((LONGLONG_ARRAY*)pvalue2)->pll, sizeof(uint64_t)
				*((LONGLONG_ARRAY*)pvalue1)->count)) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	case PT_MV_STRING8:
	case PT_MV_UNICODE:
		switch (relop) {
		case RELOP_EQ:
			if (((STRING_ARRAY*)pvalue1)->count !=
				((STRING_ARRAY*)pvalue2)->count) {
				return FALSE;
			}
			for (i=0; i<((STRING_ARRAY*)pvalue1)->count; i++) {
				if (0 != strcasecmp(((STRING_ARRAY*)pvalue1)->ppstr[i],
					((STRING_ARRAY*)pvalue2)->ppstr[i])) {
					return FALSE;	
				}
			}
			return TRUE;
		case RELOP_NE:
			if (((STRING_ARRAY*)pvalue1)->count !=
				((STRING_ARRAY*)pvalue2)->count) {
				return TRUE;
			}
			for (i=0; i<((STRING_ARRAY*)pvalue1)->count; i++) {
				if (0 != strcasecmp(((STRING_ARRAY*)pvalue1)->ppstr[i],
					((STRING_ARRAY*)pvalue2)->ppstr[i])) {
					return TRUE;	
				}
			}
			return FALSE;
		}
		return FALSE;
	case PT_MV_BINARY:
		switch (relop) {
		case RELOP_EQ:
			if (((BINARY_ARRAY*)pvalue1)->count !=
				((BINARY_ARRAY*)pvalue2)->count) {
				return FALSE;
			}
			for (i=0; i<((BINARY_ARRAY*)pvalue1)->count; i++) {
				if (((BINARY_ARRAY*)pvalue1)->pbin[i].cb !=
					((BINARY_ARRAY*)pvalue2)->pbin[i].cb) {
					return FALSE;	
				}
				if (0 != memcmp(((BINARY_ARRAY*)pvalue1)->pbin[i].pb,
					((BINARY_ARRAY*)pvalue2)->pbin[i].pb,
					((BINARY_ARRAY*)pvalue1)->pbin[i].cb)) {
					return FALSE;
				}
			}
			return TRUE;
		case RELOP_NE:
			if (((BINARY_ARRAY*)pvalue1)->count !=
				((BINARY_ARRAY*)pvalue2)->count) {
				return TRUE;
			}
			for (i=0; i<((BINARY_ARRAY*)pvalue1)->count; i++) {
				if (((BINARY_ARRAY*)pvalue1)->pbin[i].cb !=
					((BINARY_ARRAY*)pvalue2)->pbin[i].cb) {
					return TRUE;	
				}
				if (0 != memcmp(((BINARY_ARRAY*)pvalue1)->pbin[i].pb,
					((BINARY_ARRAY*)pvalue2)->pbin[i].pb,
					((BINARY_ARRAY*)pvalue1)->pbin[i].cb)) {
					return TRUE;
				}
			}
			return FALSE;
		}
		return FALSE;
	}
	return FALSE;
}


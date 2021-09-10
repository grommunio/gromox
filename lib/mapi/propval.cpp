// SPDX-License-Identifier: GPL-2.0-only WITH linking exception
#include <cstdint>
#include <gromox/defs.h>
#include <gromox/mapidefs.h>
#include <gromox/guid.hpp>
#include <gromox/util.hpp>
#include <gromox/propval.hpp>
#include <gromox/restriction.hpp>
#include <gromox/rule_actions.hpp>
#include <cstdlib>
#include <cstring>

void* propval_dup(uint16_t type, void *pvi)
{
	if (pvi == nullptr) {
		debug_info("[propval]: cannot duplicate NULL propval");
		return NULL;
	}
	switch (type) {
	case PT_UNSPECIFIED: {
		auto preturn = static_cast<TYPED_PROPVAL *>(malloc(sizeof(TYPED_PROPVAL)));
		auto psrc = static_cast<TYPED_PROPVAL *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->type = psrc->type;
		preturn->pvalue = propval_dup(psrc->type, psrc->pvalue);
		if (preturn->pvalue == nullptr) {
			free(preturn);
			return NULL;
		}
		return preturn;
	}
	case PT_SHORT: {
		auto preturn = static_cast<uint16_t *>(malloc(sizeof(uint16_t)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<uint16_t *>(pvi);
		return preturn;
	}
	case PT_ERROR:
	case PT_LONG: {
		auto preturn = static_cast<uint32_t *>(malloc(sizeof(uint32_t)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<uint32_t *>(pvi);
		return preturn;
	}
	case PT_FLOAT: {
		auto preturn = static_cast<float *>(malloc(sizeof(float)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<float *>(pvi);
		return preturn;
	}
	case PT_DOUBLE:
	case PT_APPTIME: {
		auto preturn = static_cast<double *>(malloc(sizeof(double)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<double *>(pvi);
		return preturn;
	}
	case PT_BOOLEAN: {
		auto preturn = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<uint8_t *>(pvi);
		return preturn;
	}
	case PT_CURRENCY:
	case PT_I8:
	case PT_SYSTIME: {
		auto preturn = static_cast<uint64_t *>(malloc(sizeof(uint64_t)));
		if (NULL == preturn) {
			return NULL;
		}
		*preturn = *static_cast<uint64_t *>(pvi);
		return preturn;
	}
	case PT_STRING8:
	case PT_UNICODE:
		return strdup(static_cast<char *>(pvi));
	case PT_CLSID: {
		auto preturn = static_cast<GUID *>(malloc(sizeof(GUID)));
		if (NULL == preturn) {
			return NULL;
		}
		memcpy(preturn, pvi, sizeof(GUID));
		return preturn;
	}
	case PT_SVREID: {
		auto preturn = static_cast<SVREID *>(malloc(sizeof(SVREID)));
		auto psrc = static_cast<SVREID *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		if (psrc->pbin != nullptr) {
			preturn->pbin = static_cast<BINARY *>(malloc(sizeof(BINARY)));
			if (preturn->pbin == nullptr) {
				free(preturn);
				return NULL;
			}
			preturn->pbin->cb = psrc->pbin->cb;
			if (psrc->pbin->cb == 0) {
				preturn->pbin->pv = nullptr;
			} else {
				preturn->pbin->pv = malloc(psrc->pbin->cb);
				if (preturn->pbin->pv == nullptr) {
					free(preturn->pbin);
					free(preturn);
					return NULL;
				}
				memcpy(preturn->pbin->pv, psrc->pbin->pv, psrc->pbin->cb);
			}
		} else {
			memcpy(preturn, pvi, sizeof(SVREID));
		}
		return preturn;
	}
	case PT_SRESTRICTION:
		return restriction_dup(static_cast<RESTRICTION *>(pvi));
	case PT_ACTIONS:
		return rule_actions_dup(static_cast<RULE_ACTIONS *>(pvi));
	case PT_BINARY:
	case PT_OBJECT: {
		auto preturn = static_cast<BINARY *>(malloc(sizeof(BINARY)));
		auto psrc = static_cast<BINARY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->cb = psrc->cb;
		if (psrc->cb == 0) {
			preturn->pv = NULL;
		} else {
			preturn->pv = malloc(psrc->cb);
			if (preturn->pv == nullptr) {
				free(preturn);
				return NULL;
			}
			memcpy(preturn->pv, psrc->pv, psrc->cb);
		}
		return preturn;
	}
	case PT_MV_SHORT: {
		auto preturn = static_cast<SHORT_ARRAY *>(malloc(sizeof(SHORT_ARRAY)));
		auto psrc = static_cast<SHORT_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->ps = nullptr;
		} else {
			preturn->ps = static_cast<uint16_t *>(malloc(sizeof(uint16_t) * psrc->count));
			if (preturn->ps == nullptr) {
				free(preturn);
				return NULL;
			}
			memcpy(preturn->ps, psrc->ps, sizeof(uint16_t) * psrc->count);
		}
		return preturn;
	}
	case PT_MV_LONG: {
		auto preturn = static_cast<LONG_ARRAY *>(malloc(sizeof(LONG_ARRAY)));
		auto psrc = static_cast<LONG_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pl = NULL;
		} else {
			preturn->pl = static_cast<uint32_t *>(malloc(sizeof(uint32_t) * psrc->count));
			if (preturn->pl == nullptr) {
				free(preturn);
				return NULL;
			}
			memcpy(preturn->pl, psrc->pl, sizeof(uint32_t) * psrc->count);
		}
		return preturn;
	}
	case PT_MV_I8: {
		auto preturn = static_cast<LONGLONG_ARRAY *>(malloc(sizeof(LONGLONG_ARRAY)));
		auto psrc = static_cast<LONGLONG_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pll = nullptr;
		} else {
			preturn->pll = static_cast<uint64_t *>(malloc(sizeof(uint64_t) * psrc->count));
			if (preturn->pll == nullptr) {
				free(preturn);
				return NULL;
			}
			memcpy(preturn->pll, psrc->pll, sizeof(uint64_t) * psrc->count);
		}
		return preturn;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto preturn = static_cast<STRING_ARRAY *>(malloc(sizeof(STRING_ARRAY)));
		auto psrc = static_cast<STRING_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->ppstr = nullptr;
		} else {
			preturn->ppstr = static_cast<char **>(malloc(sizeof(char *) * psrc->count));
			if (preturn->ppstr == nullptr) {
				free(preturn);
				return NULL;
			}
			for (size_t i = 0; i < psrc->count; ++i) {
				preturn->ppstr[i] = strdup(psrc->ppstr[i]);
				if (preturn->ppstr[i] == nullptr) {
					while (i-- > 0)
						free(preturn->ppstr[i]);
					free(preturn->ppstr);
					free(preturn);
					return NULL;
				}
			}
		}
		return preturn;
	}
	case PT_MV_CLSID: {
		auto preturn = static_cast<GUID_ARRAY *>(malloc(sizeof(GUID_ARRAY)));
		auto psrc = static_cast<GUID_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pguid = nullptr;
		} else {
			preturn->pguid = static_cast<GUID *>(malloc(sizeof(GUID) * psrc->count));
			if (preturn->pguid == nullptr) {
				free(preturn);
				return NULL;
			}
			memcpy(preturn->pguid, psrc->pguid, sizeof(GUID) * psrc->count);
		}
		return preturn;
	}
	case PT_MV_BINARY: {
		auto preturn = static_cast<BINARY_ARRAY *>(malloc(sizeof(BINARY_ARRAY)));
		auto psrc = static_cast<BINARY_ARRAY *>(pvi);
		if (NULL == preturn) {
			return NULL;
		}
		preturn->count = psrc->count;
		if (psrc->count == 0) {
			preturn->pbin = nullptr;
		} else {
			preturn->pbin = static_cast<BINARY *>(malloc(sizeof(BINARY) * psrc->count));
			if (preturn->pbin == nullptr) {
				free(preturn);
				return NULL;
			}
			for (size_t i = 0; i < psrc->count; ++i) {
				preturn->pbin[i].cb = psrc->pbin[i].cb;
				if (psrc->pbin[i].cb == 0) {
					preturn->pbin[i].pb = NULL;
					continue;
				}
				preturn->pbin[i].pv = malloc(psrc->pbin[i].cb);
				if (preturn->pbin[i].pv == nullptr) {
					while (i > 0)
						free(preturn->pbin[--i].pv);
					free(preturn->pbin);
					free(preturn);
					return NULL;
				}
				memcpy(preturn->pbin[i].pv, psrc->pbin[i].pv, psrc->pbin[i].cb);
			}
		}
		return preturn;
	}
	}
	return NULL;
}

void propval_free(uint16_t type, void *pvalue)
{
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
	case PT_SYSTIME:
	case PT_CLSID:
		break;
	case PT_SRESTRICTION:
		restriction_free(static_cast<RESTRICTION *>(pvalue));
		return;
	case PT_ACTIONS:
		rule_actions_free(static_cast<RULE_ACTIONS *>(pvalue));
		return;
	case PT_SVREID:
		if (NULL != ((SVREID*)pvalue)->pbin) {
			free(((SVREID*)pvalue)->pbin->pb);
			free(((SVREID*)pvalue)->pbin);
		}
		break;
	case PT_BINARY:
	case PT_OBJECT:
		free(((BINARY*)pvalue)->pb);
		break;
	case PT_MV_SHORT:
		free(((SHORT_ARRAY*)pvalue)->ps);
		break;
	case PT_MV_LONG:
		free(((LONG_ARRAY*)pvalue)->pl);
		break;
	case PT_MV_I8:
		free(((LONGLONG_ARRAY*)pvalue)->pll);
		break;
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			free(sa->ppstr[i]);
		free(sa->ppstr);
		break;
	}
	case PT_MV_CLSID:
		free(((GUID_ARRAY*)pvalue)->pguid);
		break;
	case PT_MV_BINARY: {
		auto ba = static_cast<BINARY_ARRAY *>(pvalue);
		for (size_t i = 0; i < ba->count; ++i)
			free(ba->pbin[i].pb);
		free(ba->pbin);
		break;
	}
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
	case PT_SYSTIME:
		return sizeof(uint64_t);
	case PT_STRING8:
		return strlen(static_cast<char *>(pvalue)) + 1;
	case PT_UNICODE:
		return propval_utf16_len(static_cast<char *>(pvalue));
	case PT_CLSID:
		return 16;
	case PT_SVREID:
		if (NULL != ((SVREID*)pvalue)->pbin) {
			return ((SVREID*)pvalue)->pbin->cb + 1;
		}
		return 21;
	case PT_SRESTRICTION:
		return restriction_size(static_cast<RESTRICTION *>(pvalue));
	case PT_ACTIONS:
		return rule_actions_size(static_cast<RULE_ACTIONS *>(pvalue));
	case PT_MV_SHORT:
		return sizeof(uint16_t)*((SHORT_ARRAY*)pvalue)->count;
	case PT_MV_LONG:
		return sizeof(uint32_t)*((LONG_ARRAY*)pvalue)->count;
	case PT_MV_I8:
		return sizeof(uint64_t)*((LONGLONG_ARRAY*)pvalue)->count;
	case PT_MV_STRING8: {
		length = 0;
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			length += strlen(sa->ppstr[i]) + 1;
		return length;
	}
	case PT_MV_UNICODE: {
		length = 0;
		auto sa = static_cast<STRING_ARRAY *>(pvalue);
		for (size_t i = 0; i < sa->count; ++i)
			length += propval_utf16_len(sa->ppstr[i]);
		return length;
	}
	case PT_MV_CLSID:
		return 16*((GUID_ARRAY*)pvalue)->count;
	case PT_MV_BINARY: {
		length = 0;
		auto ba = static_cast<BINARY_ARRAY *>(pvalue);
		for (size_t i = 0; i < ba->count; ++i)
			length += ba->pbin[i].cb;
		return length;
	}
	}
	return 0;
}

BOOL propval_compare_relop(uint8_t relop,
	uint16_t proptype, void *pvalue1, void *pvalue2)
{
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
			return FALSE;
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
	case PT_SYSTIME:
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
	case PT_UNICODE: {
		auto s1 = static_cast<char *>(pvalue1), s2 = static_cast<char *>(pvalue2);
		switch (relop) {
		case RELOP_LT:
			if (strcasecmp(s1, s2) < 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (strcasecmp(s1, s2) <= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (strcasecmp(s1, s2) > 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (strcasecmp(s1, s2) >= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (strcasecmp(s1, s2) == 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (strcasecmp(s1, s2) != 0) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	}
	case PT_CLSID: {
		auto g1 = static_cast<GUID *>(pvalue1);
		auto g2 = static_cast<GUID *>(pvalue2);
		switch (relop) {
		case RELOP_LT:
			if (guid_compare(g1, g2) < 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (guid_compare(g1, g2) <= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (guid_compare(g1, g2) > 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (guid_compare(g1, g2) >= 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (guid_compare(g1, g2) == 0) {
				return TRUE;
			}
			return FALSE;
		case RELOP_NE:
			if (guid_compare(g1, g2) != 0) {
				return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	}
	case PT_BINARY: {
		auto bv1 = static_cast<BINARY *>(pvalue1);
		auto bv2 = static_cast<BINARY *>(pvalue2);
		switch (relop) {
		case RELOP_LT:
			if (bv1->cb == 0 && bv2->cb != 0)
				return TRUE;
			if (bv1->cb == 0 || bv2->cb == 0)
				return FALSE;	
			if (bv1->cb > bv2->cb) {
				if (memcmp(bv1->pv, bv2->pv, bv2->cb) < 0)
					return TRUE;
			} else {
				if (memcmp(bv1->pv, bv2->pv, bv1->cb) < 0)
					return TRUE;
			}
			return FALSE;
		case RELOP_LE:
			if (bv1->cb == 0)
				return TRUE;
			if (bv2->cb == 0)
				return FALSE;
			if (bv1->cb > bv2->cb) {
				if (memcmp(bv1->pv, bv2->pv, bv2->cb) <= 0)
					return TRUE;
			} else {
				if (memcmp(bv1->pv, bv2->pv, bv1->cb) <= 0)
					return TRUE;
			}
			return FALSE;
		case RELOP_GT:
			if (bv1->cb != 0 && bv2->cb == 0)
				return TRUE;
			if (bv1->cb == 0 || bv2->cb == 0)
				return FALSE;	
			if (bv1->cb > bv2->cb) {
				if (memcmp(bv1->pv, bv2->pv, bv2->cb) > 0)
					return TRUE;
			} else {
				if (memcmp(bv1->pv, bv2->pv, bv1->cb) > 0)
					return TRUE;
			}
			return FALSE;
		case RELOP_GE:
			if (bv2->cb == 0)
				return TRUE;
			if (bv1->cb == 0)
				return FALSE;	
			if (bv1->cb > bv2->cb) {
				if (memcmp(bv1->pv, bv2->pv, bv2->cb) >= 0)
					return TRUE;
			} else {
				if (memcmp(bv1->pv, bv2->pv, bv1->cb) >= 0)
					return TRUE;
			}
			return FALSE;
		case RELOP_EQ:
			if (bv1->cb != bv2->cb)
				return FALSE;
			if (bv1->pv == nullptr)
				return TRUE;
			if (memcmp(bv1->pv, bv2->pv, bv1->cb) == 0)
				return TRUE;
			return FALSE;
		case RELOP_NE:
			if (bv1->cb != bv2->cb)
				return TRUE;
			if (bv1->pv == nullptr)
				return FALSE;
			if (memcmp(bv1->pv, bv2->pv, bv1->cb) != 0)
				return TRUE;
			return FALSE;
		}
		return FALSE;
	}
	case PT_SVREID: {
		auto sv1 = static_cast<SVREID *>(pvalue1);
		auto sv2 = static_cast<SVREID *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if ((sv1->pbin == nullptr && sv2->pbin != nullptr) ||
			    (sv1->pbin != nullptr && sv2->pbin == nullptr)) {
				return FALSE;	
			} else if (NULL != sv1->pbin && NULL != sv2->pbin) {
				if (sv1->pbin->cb != sv2->pbin->cb)
					return FALSE;	
				if (sv1->pbin->cb == 0)
					return TRUE;
				if (memcmp(sv1->pbin->pv, sv2->pbin->pv, sv1->pbin->cb) == 0)
					return TRUE;	
				return FALSE;
			}
			if (sv1->folder_id != sv2->folder_id)
				return FALSE;
			if (sv1->message_id != sv2->message_id)
				return FALSE;
			if (sv1->instance != sv2->instance)
				return FALSE;
			return TRUE;
		case RELOP_NE:
			if ((sv1->pbin == nullptr && sv2->pbin != nullptr) ||
			    (sv1->pbin != nullptr && sv2->pbin == nullptr)) {
				return TRUE;	
			} else if (sv1->pbin != nullptr && sv2->pbin != nullptr) {
				if (sv1->pbin->cb != sv2->pbin->cb)
					return TRUE;	
				if (sv1->pbin->cb == 0)
					return FALSE;
				if (memcmp(sv1->pbin->pv, sv2->pbin->pv, sv1->pbin->cb) != 0)
					return TRUE;	
				return FALSE;
			}
			if (sv1->folder_id == sv2->folder_id)
				return FALSE;
			if (sv1->message_id == sv2->message_id)
				return FALSE;
			if (sv1->instance == sv2->instance)
				return FALSE;
			return TRUE;
		}
		return FALSE;
	}
	case PT_MV_SHORT: {
		auto sa1 = static_cast<SHORT_ARRAY *>(pvalue1);
		auto sa2 = static_cast<SHORT_ARRAY *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if (sa1->count != sa2->count)
				return FALSE;
			if (memcmp(sa1->ps, sa2->ps, sizeof(uint16_t) * sa1->count) != 0)
				return FALSE;
			return TRUE;
		case RELOP_NE:
			if (sa1->count != sa2->count)
				return TRUE;
			if (memcmp(sa1->ps, sa2->ps, sizeof(uint16_t) * sa1->count) != 0)
				return TRUE;
			return FALSE;
		}
		return FALSE;
	}
	case PT_MV_LONG: {
		auto la1 = static_cast<LONG_ARRAY *>(pvalue1);
		auto la2 = static_cast<LONG_ARRAY *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if (la1->count != la2->count)
				return FALSE;
			if (memcmp(la1->pl, la2->pl, sizeof(uint32_t) * la1->count) != 0)
				return FALSE;
			return TRUE;
		case RELOP_NE:
			if (la1->count != la2->count)
				return TRUE;
			if (memcmp(la1->pl, la2->pl, sizeof(uint32_t) * la1->count) != 0)
				return TRUE;
			return FALSE;
		}
		return FALSE;
	}
	case PT_MV_I8: {
		auto la1 = static_cast<LONGLONG_ARRAY *>(pvalue1);
		auto la2 = static_cast<LONGLONG_ARRAY *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if (la1->count != la2->count)
				return FALSE;
			if (memcmp(la1->pll, la2->pll, sizeof(uint64_t) * la1->count) != 0)
				return FALSE;
			return TRUE;
		case RELOP_NE:
			if (la1->count != la2->count)
				return TRUE;
			if (memcmp(la1->pll, la2->pll, sizeof(uint64_t) * la1->count) != 0)
				return TRUE;
			return FALSE;
		}
		return FALSE;
	}
	case PT_MV_STRING8:
	case PT_MV_UNICODE: {
		auto sa1 = static_cast<STRING_ARRAY *>(pvalue1);
		auto sa2 = static_cast<STRING_ARRAY *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if (sa1->count != sa2->count)
				return FALSE;
			for (size_t i = 0; i < sa1->count; ++i)
				if (strcasecmp(sa1->ppstr[i], sa2->ppstr[i]) != 0)
					return FALSE;	
			return TRUE;
		case RELOP_NE:
			if (sa1->count != sa2->count)
				return TRUE;
			for (size_t i = 0; i < sa1->count; ++i)
				if (strcasecmp(sa1->ppstr[i], sa2->ppstr[i]) != 0)
					return TRUE;	
			return FALSE;
		}
		return FALSE;
	}
	case PT_MV_BINARY: {
		auto bv1 = static_cast<BINARY_ARRAY *>(pvalue1);
		auto bv2 = static_cast<BINARY_ARRAY *>(pvalue2);
		switch (relop) {
		case RELOP_EQ:
			if (bv1->count != bv2->count)
				return FALSE;
			for (size_t i = 0; i < bv1->count; ++i) {
				if (bv1->pbin[i].cb != bv2->pbin[i].cb)
					return FALSE;	
				if (memcmp(bv1->pbin[i].pv, bv2->pbin[i].pv, bv1->pbin[i].cb) != 0)
					return FALSE;
			}
			return TRUE;
		case RELOP_NE:
			if (bv1->count != bv2->count)
				return TRUE;
			for (size_t i = 0; i < bv1->count; ++i) {
				if (bv1->pbin[i].cb != bv2->pbin[i].cb)
					return TRUE;	
				if (memcmp(bv1->pbin[i].pv, bv2->pbin[i].pv, bv1->pbin[i].cb) != 0)
					return TRUE;
			}
			return FALSE;
		}
		return FALSE;
	}
	}
	return FALSE;
}


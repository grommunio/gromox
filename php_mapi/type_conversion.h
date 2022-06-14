#pragma once
#include "php.h"
#undef slprintf
#undef vslprintf
#undef snprintf
#undef vsnprintf
#undef vasprintf
#undef asprintf

uint64_t unix_to_nttime(time_t unix_time);
time_t nttime_to_unix(uint64_t nt_time);
uint32_t proptag_to_phptag(uint32_t proptag);
uint32_t phptag_to_proptag(uint32_t proptag);
extern zend_bool php_to_binary_array(zval *, BINARY_ARRAY *);
extern zend_bool binary_array_to_php(const BINARY_ARRAY *, zval *);
extern zend_bool php_to_sortorder_set(zval *, SORTORDER_SET *);
extern zend_bool php_to_proptag_array(zval *, PROPTAG_ARRAY *);
extern zend_bool php_to_tpropval_array(zval *, TPROPVAL_ARRAY *);
extern zend_bool php_to_tarray_set(zval *, TARRAY_SET *);
extern zend_bool php_to_rule_list(zval *, RULE_LIST *);
extern zend_bool php_to_restriction(zval *pzval, RESTRICTION *);
extern zend_bool restriction_to_php(const RESTRICTION *, zval *);
extern zend_bool proptag_array_to_php(const PROPTAG_ARRAY *, zval *);
extern zend_bool tpropval_array_to_php(const TPROPVAL_ARRAY *, zval *);
extern zend_bool tarray_set_to_php(const TARRAY_SET *, zval *);
extern zend_bool state_array_to_php(const STATE_ARRAY *, zval *);
extern zend_bool php_to_state_array(zval *, STATE_ARRAY *);
extern zend_bool znotification_array_to_php(ZNOTIFICATION_ARRAY *, zval *);
extern zend_bool php_to_propname_array(zval *names, zval *guids, PROPNAME_ARRAY *);

/* Wrap this so cov-scan only complains once (hopefully) */
static inline void zarray_init(zval *x)
{
	array_init(x);
}

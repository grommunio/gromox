#ifndef _H_TYPE_CONVERSION_
#define _H_TYPE_CONVERSION_
#include "php.h"
#include "types.h"

zend_bool utf16_to_utf8(const char *src,
	size_t src_len, char *dst, size_t len);

uint64_t unix_to_nttime(time_t unix_time);

time_t nttime_to_unix(uint64_t nt_time);

uint32_t proptag_to_phptag(uint32_t proptag);

uint32_t phptag_to_proptag(uint32_t proptag);

zend_bool php_to_binary_array(zval *pzval,
	BINARY_ARRAY *pbins TSRMLS_DC);

zend_bool binary_array_to_php(const BINARY_ARRAY *pbins,
	zval **ppzval TSRMLS_DC);

zend_bool php_to_sortorder_set(zval *pzval,
	SORTORDER_SET *pset TSRMLS_DC);

zend_bool php_to_proptag_array(zval *pzval,
	PROPTAG_ARRAY *pproptags TSRMLS_DC);

zend_bool php_to_tpropval_array(zval *pzval,
	TPROPVAL_ARRAY *ppropvals TSRMLS_DC);

zend_bool php_to_tarray_set(zval *pzval,
	TARRAY_SET *pset TSRMLS_DC);

zend_bool php_to_rule_list(zval *pzval,
	RULE_LIST *plist TSRMLS_DC);

zend_bool php_to_restriction(zval *pzval,
	RESTRICTION *pres TSRMLS_DC);

zend_bool restriction_to_php(const RESTRICTION *pres,
	zval **ppret TSRMLS_DC);

zend_bool proptag_array_to_php(const PROPTAG_ARRAY *pproptags,
	zval **ppret TSRMLS_DC);

zend_bool tpropval_array_to_php(const TPROPVAL_ARRAY *ppropvals,
	zval **ppret TSRMLS_DC);
	
zend_bool tarray_set_to_php(const TARRAY_SET *pset,
	zval **ppret TSRMLS_DC);

zend_bool state_array_to_php(const STATE_ARRAY *pstates,
	zval **ppret TSRMLS_DC);

zend_bool php_to_state_array(zval *pzval,
	STATE_ARRAY *pstates TSRMLS_DC);

zend_bool znotification_array_to_php(
	ZNOTIFICATION_ARRAY *pnotifications, zval **ppret TSRMLS_DC);

zend_bool php_to_propname_array(zval *pzval_names,
	zval *pzval_guids, PROPNAME_ARRAY *ppropnames TSRMLS_DC);

#endif /* _H_TYPE_CONVERSION_ */

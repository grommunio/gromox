#ifndef STPHP_EXT_HPP
#define STPHP_EXT_HPP 1

#include "php.h"
#include <memory>

struct zstr_delete {
	public:
	void operator()(zend_string *s) { zend_string_release(s); };
};

using zstrplus = std::unique_ptr<zend_string, zstr_delete>;

template<typename T> T *st_malloc() { return static_cast<T *>(emalloc(sizeof(T))); }
template<typename T> T *sta_malloc(size_t elem) { return static_cast<T *>(emalloc(sizeof(T) * elem)); }
template<typename T> T *sta_realloc(T *orig, size_t elem) { return static_cast<T *>(erealloc(orig, sizeof(T) * elem)); }
template<typename T> T *st_calloc() { return static_cast<T *>(ecalloc(1, sizeof(T))); }

#endif

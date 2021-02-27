#pragma once
template<typename T> T *ndr_stack_anew(unsigned int dir) { return static_cast<T *>(ndr_stack_alloc(dir, sizeof(T))); }
template<typename T> T *ndr_stack_anew(unsigned int dir, size_t elem) { return static_cast<T *>(ndr_stack_alloc(dir, sizeof(T) * elem)); }
//template<typename T> static inline T *ndr_stack_anew(unsigned int dir) { return static_cast<T *>(ndr_stack_alloc(dir, sizeof(T))); }
//template<typename T> static inline T *ndr_stack_anew(unsigned int dir, size_t n) { return static_cast<T *>(ndr_stack_alloc(dir, n * sizeof(T))); }

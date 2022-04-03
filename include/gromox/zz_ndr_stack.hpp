#pragma once
/*
 * You need to have either proc_common.h or svc_common.h included previously.
 * This is also why this file has a zz_ prefix so it sorts in include lists.
 */
template<typename T> T *ndr_stack_anew(unsigned int dir) { return static_cast<T *>(ndr_stack_alloc(dir, sizeof(T))); }
template<typename T> T *ndr_stack_anew(unsigned int dir, size_t elem) { return static_cast<T *>(ndr_stack_alloc(dir, sizeof(T) * elem)); }

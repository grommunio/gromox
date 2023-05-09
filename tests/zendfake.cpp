// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2022 grommunio GmbH
// This file is part of Gromox.
/*
 * Symbols required by mapi.so are not provided by any library, which is why
 * the dynamic link check with lddcheck does not work on mapi.so. Instead, the
 * symbols are provided by the php main program (export via -rdynamic). To
 * replicate lddcheck functionality, we can do a static link with this fake
 * program providing the same symbols and mapi.so code constituents (hence
 * libmapi4zf.la).
 */
int main() { return 0; }
using voidp = void *;
extern "C" {
__attribute__((unused,visibility("default"))) voidp
__zend_malloc,
_call_user_function_ex,
_call_user_function_impl,
_ecalloc,
_efree,
_emalloc,
_emalloc_16,
_emalloc_24,
_emalloc_32,
_emalloc_40,
_emalloc_48,
_emalloc_56,
_emalloc_64,
_emalloc_80,
_emalloc_8,
_emalloc_large,
_erealloc,
_estrdup,
_zend_new_array_0,
add_assoc_bool_ex,
add_assoc_double_ex,
add_assoc_long_ex,
add_assoc_string_ex,
add_assoc_stringl_ex,
add_assoc_zval_ex,
add_index_zval,
add_next_index_long,
add_next_index_stringl,
add_next_index_zval,
compiler_globals,
core_globals,
executor_globals,
module_registry,
php_error_docref,
php_info_print_table_end,
php_info_print_table_row,
php_info_print_table_start,
php_sprintf,
zend_fetch_resource,
zend_get_constant,
zend_hash_find,
zend_hash_get_current_data_ex,
zend_hash_index_find,
zend_hash_index_update,
zend_hash_internal_pointer_reset_ex,
zend_hash_move_forward_ex,
zend_hash_next_index_insert,
zend_ini_string,
zend_is_auto_global,
zend_is_true,
zend_parse_parameters,
zend_register_constant,
zend_register_ini_entries,
zend_register_ini_entries_ex,
zend_register_list_destructors_ex,
zend_register_resource,
zend_unregister_ini_entries,
zend_unregister_ini_entries_ex,
zend_throw_exception,
zval_get_double_func,
zval_get_long_func,
zval_get_string_func,
zval_ptr_dtor;
}

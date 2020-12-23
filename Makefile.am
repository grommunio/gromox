# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I build-aux
AM_CPPFLAGS = -D_GNU_SOURCE -I${top_srcdir}/include -I${top_srcdir}/LIBRARY/common/include -I${top_srcdir}/LIBRARY/epoll_scheduler/include -I${top_srcdir}/LIBRARY/mapi_lib/include -I${top_srcdir}/LIBRARY/webkit_lib/include -I${top_srcdir}/LIBRARY/rpc_lib/include -I${top_srcdir}/LIBRARY/email_lib/include ${HX_CFLAGS} ${gumbo_CFLAGS} ${crypto_CFLAGS} ${ssl_CFLAGS} ${mysql_CFLAGS} ${sqlite_CFLAGS} ${zlib_CFLAGS}
AM_CFLAGS = ${my_CFLAGS} -fvisibility=default
AM_CXXFLAGS = ${my_CXXFLAGS}

lib_LTLIBRARIES = libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_epoll.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la libgromox_webkit.la
noinst_DATA = libgromox_common.ldd libgromox_epoll.ldd libgromox_email.ldd libgromox_webkit.ldd libgromox_rpc.ldd libgromox_mapi.ldd
pkglibexec_PROGRAMS = ${mta_system} ${mra_system} ${exchange_progs} ${agent_service_progs} ${system_admin_progs} ${system_admin_tools}
pkglib_LTLIBRARIES = ${mta_plugins} ${mra_plugins} ${exchange_plugins}
default_sym = ${srcdir}/default.sym
default_SYFLAGS = -Wl,--version-script=${default_sym}
plugin_LDFLAGS = -avoid-version -module ${default_SYFLAGS${NO_VSYM}}
pamlibdir = ${libdir}/security
if HAVE_PAM
pamlib_LTLIBRARIES = pam_gromox.la
noinst_DATA += pam_gromox.ldd
endif
phplibdir = ${PHP_EXTENSION_DIR}
phplib_LTLIBRARIES = mapi.la
unit_services = system/gromox-adaptor.service system/gromox-delivery.service system/gromox-event.service system/gromox-http.service system/gromox-imap.service system/gromox-locker.service system/gromox-midb.service system/gromox-pop3.service system/gromox-smtp.service system/gromox-timer.service system/gromox-zcore.service
unit_targets = system/gromox-exch.target system/gromox-mra.target system/gromox-mta.target system/gromox-sa.target
unit_DATA = ${unit_services} ${unit_targets}

mta_system = delivery smtp
mta_plugins = \
	libmtaflh_message_enqueue.la \
	libmtahook_alias_translator.la \
	libmtahook_exmdb_local.la \
	libmtahook_from_replace.la \
	libmtahook_mlist_expand.la \
	libmtasvc_boundary_list.la \
	libmtasvc_delivery_console_control.la \
	libmtasvc_domain_list.la \
	libmtasvc_domain_whitelist.la \
	libmtasvc_forbidden_domain.la \
	libmtasvc_forbidden_from.la \
	libmtasvc_forbidden_rcpt.la \
	libmtasvc_inmail_frequency_audit.la \
	libmtasvc_invalid_user.la \
	libmtasvc_ip_container.la \
	libmtasvc_ip_filter.la \
	libmtasvc_ip_whitelist.la \
	libmtasvc_lang_charset.la \
	libmtasvc_log_plugin.la \
	libmtasvc_mail_from_audit.la \
	libmtasvc_mail_subject_audit.la \
	libmtasvc_midb_agent.la \
	libmtasvc_mime_extension.la \
	libmtasvc_ms_locale.la \
	libmtasvc_multiple_retrying.la \
	libmtasvc_outmail_frequency_audit.la \
	libmtasvc_outmail_limitation_audit.la \
	libmtasvc_protection_ip_audit.la \
	libmtasvc_relay_domains.la \
	libmtasvc_relay_list.la \
	libmtasvc_remote_delivery_audit.la \
	libmtasvc_remote_delivery_forbidden.la \
	libmtasvc_remote_mx_hello.la \
	libmtasvc_retrying_table.la \
	libmtasvc_single_rcpt.la \
	libmtasvc_smtp_console_control.la \
	libmtasvc_special_protection_audit.la \
	libmtasvc_tagging_table.la \
	libmtasvc_user_filter.la
noinst_DATA += \
	libmtaflh_message_enqueue.ldd \
	libmtahook_alias_translator.ldd \
	libmtahook_exmdb_local.ldd \
	libmtahook_from_replace.ldd \
	libmtahook_mlist_expand.ldd \
	libmtasvc_boundary_list.ldd \
	libmtasvc_delivery_console_control.ldd \
	libmtasvc_domain_list.ldd \
	libmtasvc_domain_whitelist.ldd \
	libmtasvc_forbidden_domain.ldd \
	libmtasvc_forbidden_from.ldd \
	libmtasvc_forbidden_rcpt.ldd \
	libmtasvc_inmail_frequency_audit.ldd \
	libmtasvc_invalid_user.la \
	libmtasvc_ip_container.la \
	libmtasvc_ip_filter.la \
	libmtasvc_ip_whitelist.ldd \
	libmtasvc_lang_charset.la \
	libmtasvc_log_plugin.la \
	libmtasvc_mail_from_audit.ldd \
	libmtasvc_mail_subject_audit.ldd \
	libmtasvc_midb_agent.la \
	libmtasvc_mime_extension.la \
	libmtasvc_ms_locale.la \
	libmtasvc_multiple_retrying.la \
	libmtasvc_outmail_frequency_audit.ldd \
	libmtasvc_outmail_limitation_audit.ldd \
	libmtasvc_protection_ip_audit.ldd \
	libmtasvc_relay_domains.ldd \
	libmtasvc_relay_list.ldd \
	libmtasvc_remote_delivery_audit.ldd \
	libmtasvc_remote_delivery_forbidden.ldd \
	libmtasvc_remote_mx_hello.ldd \
	libmtasvc_retrying_table.la \
	libmtasvc_single_rcpt.ldd \
	libmtasvc_smtp_console_control.ldd \
	libmtasvc_special_protection_audit.ldd \
	libmtasvc_tagging_table.ldd \
	libmtasvc_user_filter.ldd
mra_system = pop3 imap
mra_plugins = \
	libgxsvc_event_proxy.la \
	libmrasvc_event_stub.la \
	libmrasvc_ip_container.la \
	libmrasvc_ip_filter.la \
	libmrasvc_log_plugin.la \
	libmrasvc_midb_agent.la \
	libmrasvc_user_filter.la
noinst_DATA += \
	libgxsvc_event_proxy.ldd \
	libmrasvc_event_stub.ldd \
	libmrasvc_ip_container.ldd \
	libmrasvc_ip_filter.ldd \
	libmrasvc_log_plugin.ldd \
	libmrasvc_midb_agent.ldd \
	libmrasvc_user_filter.ldd
exchange_progs = http midb zcore
exchange_plugins = \
	libexsvc_codepage_lang.la \
	libexsvc_exmdb_provider.la \
	libexsvc_ip_container.la \
	libexsvc_ip_filter.la \
	libexsvc_lang_charset.la \
	libexsvc_log_plugin.la \
	libexsvc_mime_extension.la \
	libexsvc_ms_locale.la \
	libexsvc_user_filter.la \
	libexsvc_timer_agent.la \
	libexproc_exchange_emsmdb.la \
	libexproc_exchange_nsp.la \
	libexproc_exchange_rfr.la \
	libexhpm_proxy.la \
	libgxsvc_abktplug.la \
	libgxsvc_at_client.la \
	libgxsvc_authmgr.la \
	libgxsvc_ldap_adaptor.la \
	libgxsvc_localemap.la \
	libgxsvc_mysql_adaptor.la
noinst_DATA += \
	libexsvc_codepage_lang.ldd \
	libexsvc_exmdb_provider.ldd \
	libexsvc_ip_container.ldd \
	libexsvc_ip_filter.ldd \
	libexsvc_lang_charset.ldd \
	libexsvc_log_plugin.ldd \
	libexsvc_mime_extension.ldd \
	libexsvc_ms_locale.ldd \
	libexsvc_user_filter.ldd \
	libexsvc_timer_agent.ldd \
	libexproc_exchange_emsmdb.ldd \
	libexproc_exchange_nsp.ldd \
	libexproc_exchange_rfr.ldd \
	libexhpm_proxy.ldd \
	libgxsvc_abktplug.ldd \
	libgxsvc_at_client.ldd \
	libgxsvc_authmgr.ldd \
	libgxsvc_ldap_adaptor.ldd \
	libgxsvc_localemap.ldd \
	libgxsvc_mysql_adaptor.ldd
agent_service_progs = digest freebusy rtf2html
system_admin_progs = adaptor event locker timer
system_admin_tools = mkmidb mkprivate mkpublic rebuild
sbin_PROGRAMS = gromox-dbop gromox-mailq
pkglibexec_SCRIPTS = SYSTEM_ADMIN/scripts/sa_format_area.sh

# LIBRARY
BUILT_SOURCES = include/gromox/paths.h
libgromox_common_la_CXXFLAGS = ${AM_CXXFLAGS} -fvisibility=default
libgromox_common_la_SOURCES = LIBRARY/common/alloc_context.c LIBRARY/common/array.c LIBRARY/common/config_file.c LIBRARY/common/dir_tree.c LIBRARY/common/double_list.c LIBRARY/common/files_allocator.c LIBRARY/common/guid.c LIBRARY/common/int_hash.c LIBRARY/common/ip4_hash.c LIBRARY/common/lib_buffer.c LIBRARY/common/list_file.c LIBRARY/common/long_hash.c LIBRARY/common/mail_func.c LIBRARY/common/mem_file.c LIBRARY/common/simple_tree.c LIBRARY/common/single_list.c LIBRARY/common/stream.c LIBRARY/common/str_hash.c LIBRARY/common/timezone.c LIBRARY/common/util.c LIBRARY/common/vstack.c LIBRARY/common/xarray.c lib/errno.cpp lib/rfbl.cpp lib/socket.cpp
libgromox_common_la_LIBADD = -lcrypt ${HX_LIBS}
libgromox_cplus_la_SOURCES = lib/fileio.cpp lib/localemap.cpp lib/oxoabkt.cpp
libgromox_cplus_la_LIBADD = -lpthread ${HX_LIBS} ${jsoncpp_LIBS}
libgromox_dbop_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_dbop_la_SOURCES = lib/dbop_mysql.cpp
libgromox_dbop_la_LIBADD = ${mysql_LIBS}
libgromox_email_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_email_la_SOURCES = LIBRARY/email_lib/mime.c LIBRARY/email_lib/mime_pool.c LIBRARY/email_lib/mjson.c LIBRARY/email_lib/vcard.c LIBRARY/email_lib/mail.c LIBRARY/email_lib/ical.c LIBRARY/email_lib/dsn.c
libgromox_email_la_LIBADD = ${HX_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_epoll_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_epoll_la_SOURCES = LIBRARY/epoll_scheduler/contexts_pool.c LIBRARY/epoll_scheduler/threads_pool.c
libgromox_epoll_la_LIBADD = -lpthread -lrt libgromox_common.la
libgromox_mapi_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_mapi_la_SOURCES = LIBRARY/mapi_lib/apple_util.c LIBRARY/mapi_lib/applefile.c LIBRARY/mapi_lib/binhex.c LIBRARY/mapi_lib/eid_array.c LIBRARY/mapi_lib/element_data.c LIBRARY/mapi_lib/ext_buffer.c LIBRARY/mapi_lib/html.cpp LIBRARY/mapi_lib/idset.c LIBRARY/mapi_lib/macbinary.c LIBRARY/mapi_lib/oxcical.c LIBRARY/mapi_lib/oxcmail.cpp LIBRARY/mapi_lib/oxvcard.c LIBRARY/mapi_lib/pcl.c LIBRARY/mapi_lib/proptag_array.c LIBRARY/mapi_lib/propval.c LIBRARY/mapi_lib/restriction.c LIBRARY/mapi_lib/rop_util.c LIBRARY/mapi_lib/rtf.cpp LIBRARY/mapi_lib/rtfcp.cpp LIBRARY/mapi_lib/rule_actions.c LIBRARY/mapi_lib/sortorder_set.c LIBRARY/mapi_lib/tarray_set.c LIBRARY/mapi_lib/tnef.c LIBRARY/mapi_lib/tpropval_array.c
libgromox_mapi_la_LIBADD = ${gumbo_LIBS} ${HX_LIBS} libgromox_common.la libgromox_email.la
libgromox_rpc_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_rpc_la_SOURCES = LIBRARY/rpc_lib/ntlmssp.c LIBRARY/rpc_lib/ntlmdes.c LIBRARY/rpc_lib/ndr.c LIBRARY/rpc_lib/hmacmd5.c LIBRARY/rpc_lib/crc32.c LIBRARY/rpc_lib/arcfour.c
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} libgromox_common.la
libgromox_webkit_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_webkit_la_SOURCES = LIBRARY/webkit_lib/request_parser.c LIBRARY/webkit_lib/lang_resource.c LIBRARY/webkit_lib/idx_array.c LIBRARY/webkit_lib/cookie_parser.c LIBRARY/webkit_lib/assoc_array.c
libgromox_webkit_la_LIBADD = ${HX_LIBS} libgromox_common.la

# MTA_SYSTEM
delivery_SOURCES = EXCHANGE_SYSTEM/http/service.cpp MTA_SYSTEM/delivery_app/console_server.c MTA_SYSTEM/delivery_app/console_cmd_handler.c MTA_SYSTEM/delivery_app/main.cpp MTA_SYSTEM/delivery_app/message_dequeue.c MTA_SYSTEM/delivery_app/system_services.c MTA_SYSTEM/delivery_app/transporter.c
delivery_LDADD = -ldl -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
smtp_SOURCES = EXCHANGE_SYSTEM/http/service.cpp MTA_SYSTEM/smtp/blocks_allocator.c MTA_SYSTEM/smtp/bndstack_allocator.c MTA_SYSTEM/smtp/console_server.c MTA_SYSTEM/smtp/console_cmd_handler.c MTA_SYSTEM/smtp/flusher.c MTA_SYSTEM/smtp/listener.c MTA_SYSTEM/smtp/main.cpp MTA_SYSTEM/smtp/resource.c MTA_SYSTEM/smtp/smtp_parser.c MTA_SYSTEM/smtp/smtp_cmd_handler.c MTA_SYSTEM/smtp/system_services.c
smtp_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
libmtaflh_message_enqueue_la_SOURCES = MTA_SYSTEM/flusher_plugins/message_enqueue/main.c MTA_SYSTEM/flusher_plugins/message_enqueue/message_enqueue.c
libmtaflh_message_enqueue_la_LDFLAGS = ${plugin_LDFLAGS}
libmtaflh_message_enqueue_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmtaflh_message_enqueue_la_DEPENDENCIES = ${default_sym}
libmtahook_alias_translator_la_SOURCES = MTA_SYSTEM/mpc_plugins/alias_translator.cpp
libmtahook_alias_translator_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_alias_translator_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtahook_alias_translator_la_DEPENDENCIES = ${default_sym}
libmtahook_exmdb_local_la_SOURCES = MTA_SYSTEM/mpc_plugins/exmdb_local/auto_response.c MTA_SYSTEM/mpc_plugins/exmdb_local/bounce_audit.c MTA_SYSTEM/mpc_plugins/exmdb_local/bounce_producer.c MTA_SYSTEM/mpc_plugins/exmdb_local/cache_queue.c MTA_SYSTEM/mpc_plugins/exmdb_local/exmdb_client.c MTA_SYSTEM/mpc_plugins/exmdb_local/exmdb_local.cpp MTA_SYSTEM/mpc_plugins/exmdb_local/main.c MTA_SYSTEM/mpc_plugins/exmdb_local/net_failure.c
libmtahook_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libmtahook_exmdb_local_la_DEPENDENCIES = ${default_sym}
libmtahook_from_replace_la_SOURCES = MTA_SYSTEM/mpc_plugins/from_replace.c
libmtahook_from_replace_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_from_replace_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtahook_from_replace_la_DEPENDENCIES = ${default_sym}
libmtahook_mlist_expand_la_SOURCES = MTA_SYSTEM/mpc_plugins/mlist_expand/bounce_producer.c MTA_SYSTEM/mpc_plugins/mlist_expand/main.cpp
libmtahook_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mlist_expand_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
EXTRA_libmtahook_mlist_expand_la_DEPENDENCIES = ${default_sym}
libmtasvc_boundary_list_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/str_table/main.c EXCHANGE_SYSTEM/service_plugins/str_table/str_table.c
libmtasvc_boundary_list_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_boundary_list_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_boundary_list_la_DEPENDENCIES = ${default_sym}
libmtasvc_delivery_console_control_la_SOURCES = MTA_SYSTEM/service_plugins/console_control.c
libmtasvc_delivery_console_control_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_delivery_console_control_la_LIBADD = ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_delivery_console_control_la_DEPENDENCIES = ${default_sym}
libmtasvc_domain_list_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_domain_list_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_domain_list_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_domain_list_la_DEPENDENCIES = ${default_sym}
libmtasvc_domain_whitelist_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_domain_whitelist_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_domain_whitelist_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_domain_whitelist_la_DEPENDENCIES = ${default_sym}
libmtasvc_forbidden_from_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_forbidden_from_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_forbidden_from_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_forbidden_from_la_DEPENDENCIES = ${default_sym}
libmtasvc_forbidden_domain_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_forbidden_domain_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_forbidden_domain_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_forbidden_domain_la_DEPENDENCIES = ${default_sym}
libmtasvc_forbidden_rcpt_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_forbidden_rcpt_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_forbidden_rcpt_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_forbidden_rcpt_la_DEPENDENCIES = ${default_sym}
libmtasvc_inmail_frequency_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_inmail_frequency_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_inmail_frequency_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
EXTRA_libmtasvc_inmail_frequency_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_invalid_user_la_SOURCES = MTA_SYSTEM/service_plugins/invalid_user/invalid_user.c MTA_SYSTEM/service_plugins/invalid_user/main.c
libmtasvc_invalid_user_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_invalid_user_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_invalid_user_la_DEPENDENCIES = ${default_sym}
libmtasvc_ip_container_la_SOURCES = ${libexsvc_ip_container_la_SOURCES}
libmtasvc_ip_container_la_LDFLAGS = ${libexsvc_ip_container_la_LDFLAGS}
libmtasvc_ip_container_la_LIBADD = ${libexsvc_ip_container_la_LIBADD}
EXTRA_libmtasvc_ip_container_la_DEPENDENCIES = ${default_sym}
libmtasvc_ip_filter_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_ip_filter_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_ip_filter_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
EXTRA_libmtasvc_ip_filter_la_DEPENDENCIES = ${default_sym}
libmtasvc_ip_whitelist_la_SOURCES = MTA_SYSTEM/service_plugins/ip_table/ip_table.c MTA_SYSTEM/service_plugins/ip_table/main.c
libmtasvc_ip_whitelist_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_ip_whitelist_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmtasvc_ip_whitelist_la_DEPENDENCIES = ${default_sym}
libmtasvc_lang_charset_la_SOURCES = ${libexsvc_lang_charset_la_SOURCES}
libmtasvc_lang_charset_la_LDFLAGS = ${libexsvc_lang_charset_la_LDFLAGS}
libmtasvc_lang_charset_la_LIBADD = ${libexsvc_lang_charset_la_LIBADD}
EXTRA_libmtasvc_lang_charset_la_DEPENDENCIES = ${default_sym}
libmtasvc_log_plugin_la_SOURCES = ${libexsvc_log_plugin_la_SOURCES}
libmtasvc_log_plugin_la_LDFLAGS = ${libexsvc_log_plugin_la_LDFLAGS}
libmtasvc_log_plugin_la_LIBADD = ${libexsvc_log_plugin_la_LIBADD}
EXTRA_libmtasvc_log_plugin_la_DEPENDENCIES = ${default_sym}
libmtasvc_mail_from_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_mail_from_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_mail_from_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_mail_from_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_mail_subject_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_mail_subject_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_mail_subject_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_mail_subject_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_midb_agent_la_SOURCES = MTA_SYSTEM/service_plugins/midb_agent.c
libmtasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmtasvc_midb_agent_la_DEPENDENCIES = ${default_sym}
libmtasvc_mime_extension_la_SOURCES = ${libexsvc_mime_extension_la_SOURCES}
libmtasvc_mime_extension_la_LDFLAGS = ${libexsvc_mime_extension_la_LDFLAGS}
libmtasvc_mime_extension_la_LIBADD = ${libexsvc_mime_extension_la_LIBADD}
EXTRA_libmtasvc_mime_extension_la_DEPENDENCIES = ${default_sym}
libmtasvc_ms_locale_la_SOURCES = ${libexsvc_ms_locale_la_SOURCES}
libmtasvc_ms_locale_la_LDFLAGS = ${libexsvc_ms_locale_la_LDFLAGS}
libmtasvc_ms_locale_la_LIBADD = ${libexsvc_ms_locale_la_LIBADD}
EXTRA_libmtasvc_ms_locale_la_DEPENDENCIES = ${default_sym}
libmtasvc_multiple_retrying_la_SOURCES = MTA_SYSTEM/service_plugins/multiple_retrying/main.c MTA_SYSTEM/service_plugins/multiple_retrying/multiple_retrying.c MTA_SYSTEM/service_plugins/multiple_retrying/proxy_retrying.c MTA_SYSTEM/service_plugins/multiple_retrying/retrying_table.c MTA_SYSTEM/service_plugins/multiple_retrying/stub_retrying.c
libmtasvc_multiple_retrying_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_multiple_retrying_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_multiple_retrying_la_DEPENDENCIES = ${default_sym}
libmtasvc_outmail_frequency_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_outmail_frequency_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_outmail_frequency_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_outmail_frequency_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_outmail_limitation_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_outmail_limitation_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_outmail_limitation_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_outmail_limitation_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_protection_ip_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_protection_ip_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_protection_ip_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
EXTRA_libmtasvc_protection_ip_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_relay_domains_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_relay_domains_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_relay_domains_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_relay_domains_la_DEPENDENCIES = ${default_sym}
libmtasvc_relay_list_la_SOURCES = ${libmtasvc_ip_whitelist_la_SOURCES}
libmtasvc_relay_list_la_LDFLAGS = ${libmtasvc_ip_whitelist_la_LDFLAGS}
libmtasvc_relay_list_la_LIBADD = ${libmtasvc_ip_whitelist_la_LIBADD}
EXTRA_libmtasvc_relay_list_la_DEPENDENCIES = ${default_sym}
libmtasvc_remote_delivery_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_remote_delivery_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_remote_delivery_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
EXTRA_libmtasvc_remote_delivery_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_remote_mx_hello_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_remote_mx_hello_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_remote_mx_hello_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_remote_mx_hello_la_DEPENDENCIES = ${default_sym}
libmtasvc_single_rcpt_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_single_rcpt_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_single_rcpt_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_single_rcpt_la_DEPENDENCIES = ${default_sym}
libmtasvc_smtp_console_control_la_SOURCES = ${libmtasvc_delivery_console_control_la_SOURCES}
libmtasvc_smtp_console_control_la_LDFLAGS = ${libmtasvc_delivery_console_control_la_LDFLAGS}
libmtasvc_smtp_console_control_la_LIBADD = ${libmtasvc_delivery_console_control_la_LIBADD}
EXTRA_libmtasvc_smtp_console_control_la_DEPENDENCIES = ${default_sym}
libmtasvc_special_protection_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_special_protection_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_special_protection_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_special_protection_audit_la_DEPENDENCIES = ${default_sym}
libmtasvc_remote_delivery_forbidden_la_SOURCES = ${libmtasvc_ip_whitelist_la_SOURCES}
libmtasvc_remote_delivery_forbidden_la_LDFLAGS = ${libmtasvc_ip_whitelist_la_LDFLAGS}
libmtasvc_remote_delivery_forbidden_la_LIBADD = ${libmtasvc_ip_whitelist_la_LIBADD}
EXTRA_libmtasvc_remote_delivery_forbidden_la_DEPENDENCIES = ${default_sym}
libmtasvc_retrying_table_la_SOURCES = MTA_SYSTEM/service_plugins/retrying_table/main.c MTA_SYSTEM/service_plugins/retrying_table/retrying_table.c
libmtasvc_retrying_table_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_retrying_table_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_retrying_table_la_DEPENDENCIES = ${default_sym}
libmtasvc_tagging_table_la_SOURCES = MTA_SYSTEM/service_plugins/tagging_table/main.c MTA_SYSTEM/service_plugins/tagging_table/tagging_table.c
libmtasvc_tagging_table_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_tagging_table_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_tagging_table_la_DEPENDENCIES = ${default_sym}
libmtasvc_user_filter_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_user_filter_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_user_filter_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmtasvc_user_filter_la_DEPENDENCIES = ${default_sym}

# MRA_SYSTEM
pop3_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c EXCHANGE_SYSTEM/http/service.cpp MRA_SYSTEM/pop3/console_server.c MRA_SYSTEM/pop3/console_cmd_handler.c MRA_SYSTEM/pop3/pop3_parser.c MRA_SYSTEM/pop3/pop3_cmd_handler.c MRA_SYSTEM/pop3/resource.c MRA_SYSTEM/pop3/system_services.c MRA_SYSTEM/pop3/units_allocator.c MRA_SYSTEM/pop3/main.cpp MRA_SYSTEM/pop3/listener.c
pop3_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
imap_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c EXCHANGE_SYSTEM/http/service.cpp MRA_SYSTEM/imap/console_server.c MRA_SYSTEM/imap/console_cmd_handler.c MRA_SYSTEM/imap/imap_cmd_parser.c MRA_SYSTEM/imap/imap_parser.cpp MRA_SYSTEM/imap/listener.c MRA_SYSTEM/imap/main.cpp MRA_SYSTEM/imap/resource.c MRA_SYSTEM/imap/system_services.c
imap_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la
libgxsvc_event_proxy_la_SOURCES = MRA_SYSTEM/service_plugins/event_proxy.c
libgxsvc_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_event_proxy_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxsvc_event_proxy_la_DEPENDENCIES = ${default_sym}
libmrasvc_event_stub_la_SOURCES = MRA_SYSTEM/service_plugins/event_stub.c
libmrasvc_event_stub_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_event_stub_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmrasvc_event_stub_la_DEPENDENCIES = ${default_sym}
libmrasvc_ip_container_la_SOURCES = ${libexsvc_ip_container_la_SOURCES}
libmrasvc_ip_container_la_LDFLAGS = ${libexsvc_ip_container_la_LDFLAGS}
libmrasvc_ip_container_la_LIBADD = ${libexsvc_ip_container_la_LIBADD}
EXTRA_libmrasvc_ip_container_la_DEPENDENCIES = ${default_sym}
libmrasvc_ip_filter_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmrasvc_ip_filter_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmrasvc_ip_filter_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
EXTRA_libmrasvc_ip_filter_la_DEPENDENCIES = ${default_sym}
libmrasvc_log_plugin_la_SOURCES = ${libexsvc_log_plugin_la_SOURCES}
libmrasvc_log_plugin_la_LDFLAGS = ${libexsvc_log_plugin_la_LDFLAGS}
libmrasvc_log_plugin_la_LIBADD = ${libexsvc_log_plugin_la_LIBADD}
EXTRA_libmrasvc_log_plugin_la_DEPENDENCIES = ${default_sym}
libmrasvc_midb_agent_la_SOURCES = MRA_SYSTEM/service_plugins/midb_agent.c
libmrasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmrasvc_midb_agent_la_DEPENDENCIES = ${default_sym}
libmrasvc_user_filter_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmrasvc_user_filter_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmrasvc_user_filter_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
EXTRA_libmrasvc_user_filter_la_DEPENDENCIES = ${default_sym}

# EXCHANGE_SYSTEM
http_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c EXCHANGE_SYSTEM/http/console_server.c EXCHANGE_SYSTEM/http/console_cmd_handler.cpp EXCHANGE_SYSTEM/http/hpm_processor.cpp EXCHANGE_SYSTEM/http/http_parser.cpp EXCHANGE_SYSTEM/http/listener.cpp EXCHANGE_SYSTEM/http/main.cpp EXCHANGE_SYSTEM/http/mod_cache.cpp EXCHANGE_SYSTEM/http/mod_fastcgi.cpp EXCHANGE_SYSTEM/http/mod_rewrite.c EXCHANGE_SYSTEM/http/pdu_processor.cpp EXCHANGE_SYSTEM/http/pdu_ndr.c EXCHANGE_SYSTEM/http/service.cpp EXCHANGE_SYSTEM/http/system_services.c
http_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la libgromox_webkit.la
midb_SOURCES = EXCHANGE_SYSTEM/http/service.cpp EXCHANGE_SYSTEM/midb/cmd_parser.c EXCHANGE_SYSTEM/midb/common_util.c EXCHANGE_SYSTEM/midb/console_cmd_handler.c EXCHANGE_SYSTEM/midb/console_server.c EXCHANGE_SYSTEM/midb/exmdb_client.cpp EXCHANGE_SYSTEM/midb/exmdb_ext.cpp EXCHANGE_SYSTEM/midb/listener.c EXCHANGE_SYSTEM/midb/mail_engine.cpp EXCHANGE_SYSTEM/midb/main.cpp EXCHANGE_SYSTEM/midb/system_services.c
midb_LDADD = -ldl -lpthread -lresolv ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
zcore_SOURCES = EXCHANGE_SYSTEM/http/service.cpp EXCHANGE_SYSTEM/zcore/ab_tree.cpp EXCHANGE_SYSTEM/zcore/attachment_object.c EXCHANGE_SYSTEM/zcore/bounce_producer.cpp EXCHANGE_SYSTEM/zcore/common_util.cpp EXCHANGE_SYSTEM/zcore/console_cmd_handler.cpp EXCHANGE_SYSTEM/zcore/console_server.c EXCHANGE_SYSTEM/zcore/container_object.cpp EXCHANGE_SYSTEM/zcore/exmdb_client.cpp EXCHANGE_SYSTEM/zcore/exmdb_ext.cpp EXCHANGE_SYSTEM/zcore/folder_object.cpp EXCHANGE_SYSTEM/zcore/ics_state.c EXCHANGE_SYSTEM/zcore/icsdownctx_object.cpp EXCHANGE_SYSTEM/zcore/icsupctx_object.c EXCHANGE_SYSTEM/zcore/listener.c EXCHANGE_SYSTEM/zcore/main.cpp EXCHANGE_SYSTEM/zcore/message_object.cpp EXCHANGE_SYSTEM/zcore/msgchg_grouping.c EXCHANGE_SYSTEM/zcore/names.c EXCHANGE_SYSTEM/zcore/object_tree.cpp EXCHANGE_SYSTEM/zcore/rpc_ext.cpp EXCHANGE_SYSTEM/zcore/rpc_parser.cpp EXCHANGE_SYSTEM/zcore/store_object.cpp EXCHANGE_SYSTEM/zcore/system_services.cpp EXCHANGE_SYSTEM/zcore/table_object.cpp EXCHANGE_SYSTEM/zcore/user_object.cpp EXCHANGE_SYSTEM/zcore/zarafa_server.cpp
zcore_LDADD = -ldl -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libexsvc_codepage_lang_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/codepage_lang/codepage_lang.c EXCHANGE_SYSTEM/service_plugins/codepage_lang/main.c
libexsvc_codepage_lang_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_codepage_lang_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_codepage_lang_la_DEPENDENCIES = ${default_sym}
libexsvc_exmdb_provider_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/exmdb_provider/bounce_producer.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/common_util.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/db_engine.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_client.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_ext.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_listener.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_parser.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/notification_agent.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_server.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/folder.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/ics.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/instance.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/instbody.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/main.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/message.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/names.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/store.cpp EXCHANGE_SYSTEM/service_plugins/exmdb_provider/table.cpp
libexsvc_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libexsvc_exmdb_provider_la_DEPENDENCIES = ${default_sym}
libexsvc_ip_container_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ip_container/ip_container.c EXCHANGE_SYSTEM/service_plugins/ip_container/main.c
libexsvc_ip_container_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ip_container_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_ip_container_la_DEPENDENCIES = ${default_sym}
libexsvc_ip_filter_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ip_filter/audit_filter.c EXCHANGE_SYSTEM/service_plugins/ip_filter/grey_list.c EXCHANGE_SYSTEM/service_plugins/ip_filter/ip_filter.c EXCHANGE_SYSTEM/service_plugins/ip_filter/main.c EXCHANGE_SYSTEM/service_plugins/ip_filter/temp_list.c
libexsvc_ip_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ip_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libexsvc_ip_filter_la_DEPENDENCIES = ${default_sym}
libexsvc_lang_charset_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/lang_charset.c
libexsvc_lang_charset_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_lang_charset_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libexsvc_lang_charset_la_DEPENDENCIES = ${default_sym}
libexsvc_log_plugin_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/log_plugin/log_plugin.c EXCHANGE_SYSTEM/service_plugins/log_plugin/main.c
libexsvc_log_plugin_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_log_plugin_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_log_plugin_la_DEPENDENCIES = ${default_sym}
libexsvc_mime_extension_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/mime_extension.c
libexsvc_mime_extension_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_mime_extension_la_LIBADD = ${HX_LIBS} libgromox_common.la
EXTRA_libexsvc_mime_extension_la_DEPENDENCIES = ${default_sym}
libexsvc_ms_locale_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ms_locale.c
libexsvc_ms_locale_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ms_locale_la_LIBADD = ${HX_LIBS} libgromox_common.la
EXTRA_libexsvc_ms_locale_la_DEPENDENCIES = ${default_sym}
libexsvc_user_filter_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/str_filter/audit_filter.c EXCHANGE_SYSTEM/service_plugins/str_filter/grey_list.c EXCHANGE_SYSTEM/service_plugins/str_filter/main.c EXCHANGE_SYSTEM/service_plugins/str_filter/str_filter.c EXCHANGE_SYSTEM/service_plugins/str_filter/temp_list.c
libexsvc_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libexsvc_user_filter_la_DEPENDENCIES = ${default_sym}
libexsvc_timer_agent_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/timer_agent.c
libexsvc_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_timer_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_timer_agent_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_emsmdb_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/asyncemsmdb_interface.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/asyncemsmdb_ndr.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/attachment_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/aux_ext.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/bounce_producer.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/common_util.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/emsmdb_interface.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/emsmdb_ndr.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/exmdb_client.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/fastdownctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/fastupctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/folder_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ftstream_parser.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ftstream_producer.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ics_state.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/icsdownctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/icsupctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/logon_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/main.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/message_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/msgchg_grouping.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/names.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/notify_response.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcfold.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcfxics.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcmsg.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcnotif.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcperm.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcprpt.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcstore.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxctabl.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxomsg.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxorule.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_dispatch.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_ext.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_processor.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/stream_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/subscription_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/table_object.c LIBRARY/mapi_lib/lzxpress.c
libexproc_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libexproc_exchange_emsmdb_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_nsp_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/ab_tree.cpp EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/common_util.cpp EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/main.cpp EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/nsp_interface.cpp EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/nsp_ndr.c
libexproc_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libexproc_exchange_nsp_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_rfr_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_rfr.c
libexproc_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libexproc_exchange_rfr_la_DEPENDENCIES = ${default_sym}
libexhpm_proxy_la_SOURCES = EXCHANGE_SYSTEM/hpm_plugins/mod_proxy.c
libexhpm_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libexhpm_proxy_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexhpm_proxy_la_DEPENDENCIES = ${default_sym}
libgxsvc_abktplug_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/abktplug.cpp
libgxsvc_abktplug_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_abktplug_la_LIBADD = libgromox_cplus.la
EXTRA_libgxsvc_abktplug_la_DEPENDENCIES = ${default_sym}
libgxsvc_at_client_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/at_client.c
libgxsvc_at_client_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_at_client_la_LIBADD = ${HX_LIBS}
EXTRA_libgxsvc_at_client_la_DEPENDENCIES = ${default_sym}
libgxsvc_authmgr_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/authmgr.cpp
libgxsvc_authmgr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_authmgr_la_LIBADD = libgromox_common.la
EXTRA_libgxsvc_authmgr_la_DEPENDENCIES = ${default_sym}
libgxsvc_ldap_adaptor_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ldap_adaptor.cpp
libgxsvc_ldap_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_ldap_adaptor_la_LIBADD = libgromox_common.la -lldap_r
EXTRA_libgxsvc_ldap_adaptor_la_DEPENDENCIES = ${default_sym}
libgxsvc_localemap_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/localeplug.cpp
libgxsvc_localemap_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_localemap_la_LIBADD = libgromox_cplus.la
EXTRA_libgxsvc_localemap_la_DEPENDENCIES = ${default_sym}
libgxsvc_mysql_adaptor_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/mysql_adaptor/main.cpp EXCHANGE_SYSTEM/service_plugins/mysql_adaptor/mysql_adaptor.cpp
libgxsvc_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
EXTRA_libgxsvc_mysql_adaptor_la_DEPENDENCIES = ${default_sym}

# AGENT_SERVICE
digest_SOURCES = AGENT_SERVICE/digest.c
digest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
freebusy_SOURCES = AGENT_SERVICE/freebusy.c
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_webkit.la libgromox_mapi.la
pam_gromox_la_CPPFLAGS = ${AM_CPPFLAGS}
pam_gromox_la_SOURCES = AGENT_SERVICE/pam_gromox.cpp EXCHANGE_SYSTEM/http/service.cpp
pam_gromox_la_LIBADD = -lpam ${HX_LIBS} libgromox_common.la
pam_gromox_la_LDFLAGS = -avoid-version -module ${plugin_LDFLAGS}
rtf2html_SOURCES = AGENT_SERVICE/rtf2html.c
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la

# SYSTEM_ADMIN
saphpdir = ${pkgdatadir}/sa
saphp_DATA = SYSTEM_ADMIN/php/conf.php SYSTEM_ADMIN/php/db.php SYSTEM_ADMIN/php/submit.php
adaptor_SOURCES = LIBRARY/system_log.c SYSTEM_ADMIN/adaptor/data_source.c SYSTEM_ADMIN/adaptor/engine.c SYSTEM_ADMIN/adaptor/file_operation.c SYSTEM_ADMIN/adaptor/gateway_control.c SYSTEM_ADMIN/adaptor/main.c
adaptor_LDADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
event_SOURCES = SYSTEM_ADMIN/event.c LIBRARY/common/fifo.c
event_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la
gromox_dbop_SOURCES = lib/dbop_mysql.cpp SYSTEM_ADMIN/dbop_main.cpp
gromox_dbop_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
gromox_mailq_SOURCES = SYSTEM_ADMIN/mailq.cpp
locker_SOURCES = SYSTEM_ADMIN/locker.c
locker_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
mkmidb_SOURCES = SYSTEM_ADMIN/mkmidb.c
mkmidb_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la
mkprivate_SOURCES = SYSTEM_ADMIN/mkprivate.c
mkprivate_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
mkpublic_SOURCES = SYSTEM_ADMIN/mkpublic.c
mkpublic_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
rebuild_SOURCES = SYSTEM_ADMIN/rebuild.c
rebuild_LDADD = ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
timer_SOURCES = SYSTEM_ADMIN/timer.c
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la

# php_mapi
mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
mapi_la_SOURCES = AGENT_SERVICE/php_mapi/ext_pack.c AGENT_SERVICE/php_mapi/mapi.cpp AGENT_SERVICE/php_mapi/rpc_ext.cpp AGENT_SERVICE/php_mapi/type_conversion.cpp AGENT_SERVICE/php_mapi/zarafa_client.cpp
mapi_la_LDFLAGS = ${plugin_LDFLAGS} ${PHP_LDFLAGS}
mapi_la_LIBADD = ${HX_LIBS}
EXTRA_mapi_la_DEPENDENCIES = ${default_sym}

# tests
noinst_PROGRAMS = tests/abktconv tests/bodyconv
tests_abktconv_SOURCES = tests/abktconv.cpp
tests_abktconv_LDADD = libgromox_cplus.la
tests_bodyconv_SOURCES = tests/bodyconv.cpp
tests_bodyconv_LDADD = libgromox_common.la libgromox_mapi.la

# doc
man_MANS = \
	doc/adaptor.8gx doc/alias_translator.4gx doc/at_client.4gx \
	doc/authmgr.4gx doc/boundary_list.4gx doc/delivery.8gx \
	doc/digest.8gx doc/domain_list.4gx doc/domain_whitelist.4gx \
	doc/event.8gx doc/event_stub.4gx doc/event_proxy.4gx \
	doc/exchange_emsmdb.4gx \
	doc/exchange_nsp.4gx doc/exchange_rfr.4gx doc/exmdb_provider.4gx \
	doc/forbidden_domain.4gx doc/forbidden_from.4gx \
	doc/forbidden_rcpt.4gx doc/freebusy.8gx doc/gromox.7 \
	doc/gromox-dbop.8gx \
	doc/gromox-exch.target.8gx doc/gromox-mailq.8gx \
	doc/gromox-mra.target.8gx doc/gromox-mta.target.8gx \
	doc/gromox-sa.target.8gx doc/http.8gx \
	doc/imap.8gx doc/ldap_adaptor.4gx doc/localemap.4gx doc/locker.8gx \
	doc/mapi.4gx doc/message_enqueue.4gx doc/midb.8gx \
	doc/mkmidb.8gx doc/mkprivate.8gx doc/mkpublic.8gx \
	doc/mysql_adaptor.4gx \
	doc/pam_gromox.8gx doc/pop3.8gx \
	doc/rebuild.8gx doc/relay_domains.4gx doc/remote_mx_hello.4gx \
	doc/rtf2html.1gx doc/sa.cfg.5gx doc/single_rcpt.4gx doc/smtp.8gx \
	doc/str_table.4gx \
	doc/timer.8gx doc/timer_agent.4gx doc/zcore.8gx

include/gromox/paths.h: include/gromox/paths.h.in ${top_builddir}/config.status
	${AM_V_GEN}sed -e 's|#define PKGSYSCONFDIR .*|#define PKGSYSCONFDIR "${sysconfdir}/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLIBDIR .*|#define PKGLIBDIR "${pkglibdir}"|' \
	 -e 's|#define PKGDATADIR .*|#define PKGDATADIR "${pkgdatadir}"|' \
	 -e 's|#define PKGSTATEDIR .*|#define PKGSTATEDIR "${localstatedir}/lib/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLOGDIR .*|#define PKGLOGDIR "${localstatedir}/log/${PACKAGE_NAME}"|' \
		<$< >$@.tmp
	${AM_V_at}if ! cmp $@ $@.tmp 2>/dev/null; then mv $@.tmp $@; fi; rm -f $@.tmp

install-data-local:
	${MKDIR_P} ${DESTDIR}${pkgdatadir}
	install -pm0644 data/* ${DESTDIR}${pkgdatadir}/
	install -pm0644 data/*.abkt ${DESTDIR}${pkgdatadir}/

.la.ldd:
	${AM_V_GEN}${top_srcdir}/lddcheck ${top_builddir}/libtool $< $@
%.service: ${top_builddir}/config.status
.tps.service:
	${AM_V_GEN}${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

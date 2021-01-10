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
unit_services = system/gromox-adaptor.service system/gromox-delivery.service system/gromox-event.service system/gromox-http.service system/gromox-imap.service system/gromox-midb.service system/gromox-pop3.service system/gromox-smtp.service system/gromox-timer.service system/gromox-zcore.service
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
	libmtasvc_domain_list.la \
	libmtasvc_midb_agent.la
noinst_DATA += \
	libmtaflh_message_enqueue.ldd \
	libmtahook_alias_translator.ldd \
	libmtahook_exmdb_local.ldd \
	libmtahook_from_replace.ldd \
	libmtahook_mlist_expand.ldd \
	libmtasvc_boundary_list.ldd \
	libmtasvc_domain_list.ldd \
	libmtasvc_midb_agent.la
mra_system = pop3 imap
mra_plugins = \
	libgxsvc_event_proxy.la \
	libmrasvc_event_stub.la \
	libmrasvc_midb_agent.la
noinst_DATA += \
	libgxsvc_event_proxy.ldd \
	libmrasvc_event_stub.ldd \
	libmrasvc_midb_agent.ldd
exchange_progs = http midb zcore
exchange_plugins = \
	libexsvc_codepage_lang.la \
	libexsvc_exmdb_provider.la \
	libexsvc_timer_agent.la \
	libexproc_exchange_emsmdb.la \
	libexproc_exchange_nsp.la \
	libexproc_exchange_rfr.la \
	libexhpm_proxy.la \
	libgxsvc_abktplug.la \
	libgxsvc_at_client.la \
	libgxsvc_authmgr.la \
	libgxsvc_ip6_container.la libgxsvc_ip6_filter.la \
	libgxsvc_lang_charset.la \
	libgxsvc_ldap_adaptor.la \
	libgxsvc_localemap.la \
	libgxsvc_log_plugin.la \
	libgxsvc_mime_extension.la \
	libgxsvc_ms_locale.la \
	libgxsvc_mysql_adaptor.la \
	libgxsvc_user_filter.la
noinst_DATA += \
	libexsvc_codepage_lang.ldd \
	libexsvc_exmdb_provider.ldd \
	libexsvc_timer_agent.ldd \
	libexproc_exchange_emsmdb.ldd \
	libexproc_exchange_nsp.ldd \
	libexproc_exchange_rfr.ldd \
	libexhpm_proxy.ldd \
	libgxsvc_abktplug.ldd \
	libgxsvc_at_client.ldd \
	libgxsvc_authmgr.ldd \
	libgxsvc_ip6_container.ldd libgxsvc_ip6_filter.ldd \
	libgxsvc_lang_charset.ldd \
	libgxsvc_ldap_adaptor.ldd \
	libgxsvc_localemap.ldd \
	libgxsvc_log_plugin.ldd \
	libgxsvc_mime_extension.ldd \
	libgxsvc_ms_locale.ldd \
	libgxsvc_mysql_adaptor.ldd \
	libgxsvc_user_filter.ldd
agent_service_progs = digest freebusy rtf2html
system_admin_progs = adaptor event timer
system_admin_tools = mkmidb mkprivate mkpublic rebuild
sbin_PROGRAMS = gromox-dbop gromox-mailq
pkglibexec_SCRIPTS = SYSTEM_ADMIN/scripts/sa_format_area.sh

# LIBRARY
BUILT_SOURCES = include/gromox/paths.h AGENT_SERVICE/php_mapi/zarafa_rpc.cpp exch/midb/exmdb_rpc.cpp exch/zcore/exmdb_rpc.cpp exch/exmdb_provider/exmdb_rpc.cpp
CLEANFILES = ${BUILT_SOURCES}
libgromox_common_la_CXXFLAGS = ${AM_CXXFLAGS} -fvisibility=default
libgromox_common_la_SOURCES = LIBRARY/common/alloc_context.cpp LIBRARY/common/array.cpp LIBRARY/common/config_file.cpp LIBRARY/common/dir_tree.cpp LIBRARY/common/double_list.cpp LIBRARY/common/files_allocator.cpp LIBRARY/common/guid.cpp LIBRARY/common/int_hash.cpp LIBRARY/common/lib_buffer.cpp LIBRARY/common/list_file.cpp LIBRARY/common/mail_func.cpp LIBRARY/common/mem_file.cpp LIBRARY/common/simple_tree.cpp LIBRARY/common/single_list.cpp LIBRARY/common/str_hash.cpp LIBRARY/common/stream.cpp LIBRARY/common/timezone.cpp LIBRARY/common/util.cpp LIBRARY/common/xarray.cpp lib/errno.cpp lib/rfbl.cpp lib/socket.cpp
libgromox_common_la_LIBADD = -lcrypt ${HX_LIBS}
libgromox_cplus_la_SOURCES = lib/fileio.cpp lib/localemap.cpp lib/oxoabkt.cpp
libgromox_cplus_la_LIBADD = -lpthread ${HX_LIBS} ${jsoncpp_LIBS}
libgromox_dbop_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_dbop_la_SOURCES = lib/dbop_mysql.cpp
libgromox_dbop_la_LIBADD = ${mysql_LIBS}
libgromox_email_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_email_la_SOURCES = LIBRARY/email_lib/dsn.cpp LIBRARY/email_lib/ical.cpp LIBRARY/email_lib/mail.cpp LIBRARY/email_lib/mime.cpp LIBRARY/email_lib/mime_pool.cpp LIBRARY/email_lib/mjson.cpp LIBRARY/email_lib/vcard.cpp
libgromox_email_la_LIBADD = ${HX_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_epoll_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_epoll_la_SOURCES = LIBRARY/epoll_scheduler/contexts_pool.cpp LIBRARY/epoll_scheduler/threads_pool.cpp
libgromox_epoll_la_LIBADD = -lpthread -lrt libgromox_common.la
libgromox_mapi_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_mapi_la_SOURCES = LIBRARY/mapi_lib/apple_util.cpp LIBRARY/mapi_lib/applefile.cpp LIBRARY/mapi_lib/binhex.cpp LIBRARY/mapi_lib/eid_array.cpp LIBRARY/mapi_lib/element_data.cpp LIBRARY/mapi_lib/ext_buffer.cpp LIBRARY/mapi_lib/html.cpp LIBRARY/mapi_lib/idset.cpp LIBRARY/mapi_lib/macbinary.cpp LIBRARY/mapi_lib/oxcical.cpp LIBRARY/mapi_lib/oxcmail.cpp LIBRARY/mapi_lib/oxvcard.cpp LIBRARY/mapi_lib/pcl.cpp LIBRARY/mapi_lib/proptag_array.cpp LIBRARY/mapi_lib/propval.cpp LIBRARY/mapi_lib/restriction.cpp LIBRARY/mapi_lib/rop_util.cpp LIBRARY/mapi_lib/rtf.cpp LIBRARY/mapi_lib/rtfcp.cpp LIBRARY/mapi_lib/rule_actions.cpp LIBRARY/mapi_lib/sortorder_set.cpp LIBRARY/mapi_lib/tarray_set.cpp LIBRARY/mapi_lib/tnef.cpp LIBRARY/mapi_lib/tpropval_array.cpp
libgromox_mapi_la_LIBADD = ${gumbo_LIBS} ${HX_LIBS} libgromox_common.la libgromox_email.la
libgromox_rpc_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_rpc_la_SOURCES = LIBRARY/rpc_lib/arcfour.cpp LIBRARY/rpc_lib/crc32.cpp LIBRARY/rpc_lib/hmacmd5.cpp LIBRARY/rpc_lib/ndr.cpp LIBRARY/rpc_lib/ntlmdes.cpp LIBRARY/rpc_lib/ntlmssp.cpp
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} libgromox_common.la
libgromox_webkit_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_webkit_la_SOURCES = LIBRARY/webkit_lib/cookie_parser.cpp LIBRARY/webkit_lib/assoc_array.cpp
libgromox_webkit_la_LIBADD = ${HX_LIBS} libgromox_common.la

# MTA_SYSTEM
delivery_SOURCES = exch/http/service.cpp mda/delivery_app/console_cmd_handler.cpp mda/delivery_app/console_server.cpp mda/delivery_app/main.cpp mda/delivery_app/message_dequeue.cpp mda/delivery_app/system_services.cpp mda/delivery_app/transporter.cpp
delivery_LDADD = -ldl -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
smtp_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp mda/smtp/console_cmd_handler.cpp mda/smtp/console_server.cpp mda/smtp/flusher.cpp mda/smtp/listener.cpp mda/smtp/main.cpp mda/smtp/resource.cpp mda/smtp/smtp_cmd_handler.cpp mda/smtp/smtp_parser.cpp mda/smtp/system_services.cpp
smtp_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
libmtaflh_message_enqueue_la_SOURCES = mda/message_enqueue/main.cpp mda/message_enqueue/message_enqueue.cpp
libmtaflh_message_enqueue_la_LDFLAGS = ${plugin_LDFLAGS}
libmtaflh_message_enqueue_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmtaflh_message_enqueue_la_DEPENDENCIES = ${default_sym}
libmtahook_alias_translator_la_SOURCES = mda/alias_translator.cpp
libmtahook_alias_translator_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_alias_translator_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtahook_alias_translator_la_DEPENDENCIES = ${default_sym}
libmtahook_exmdb_local_la_SOURCES = mda/exmdb_local/auto_response.cpp mda/exmdb_local/bounce_audit.cpp mda/exmdb_local/bounce_producer.cpp mda/exmdb_local/cache_queue.cpp mda/exmdb_local/exmdb_client.cpp mda/exmdb_local/exmdb_local.cpp mda/exmdb_local/main.cpp mda/exmdb_local/net_failure.cpp
libmtahook_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libmtahook_exmdb_local_la_DEPENDENCIES = ${default_sym}
libmtahook_from_replace_la_SOURCES = mda/from_replace.cpp
libmtahook_from_replace_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_from_replace_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtahook_from_replace_la_DEPENDENCIES = ${default_sym}
libmtahook_mlist_expand_la_SOURCES = mda/mlist_expand/bounce_producer.cpp mda/mlist_expand/main.cpp
libmtahook_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mlist_expand_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
EXTRA_libmtahook_mlist_expand_la_DEPENDENCIES = ${default_sym}
libmtasvc_boundary_list_la_SOURCES = exch/str_table/main.cpp exch/str_table/str_table.cpp
libmtasvc_boundary_list_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_boundary_list_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libmtasvc_boundary_list_la_DEPENDENCIES = ${default_sym}
libmtasvc_domain_list_la_SOURCES = ${libmtasvc_boundary_list_la_SOURCES}
libmtasvc_domain_list_la_LDFLAGS = ${libmtasvc_boundary_list_la_LDFLAGS}
libmtasvc_domain_list_la_LIBADD = ${libmtasvc_boundary_list_la_LIBADD}
EXTRA_libmtasvc_domain_list_la_DEPENDENCIES = ${default_sym}
libmtasvc_midb_agent_la_SOURCES = mda/midb_agent.cpp
libmtasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmtasvc_midb_agent_la_DEPENDENCIES = ${default_sym}

# MRA_SYSTEM
pop3_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp mra/pop3/console_cmd_handler.cpp mra/pop3/console_server.cpp mra/pop3/listener.cpp mra/pop3/main.cpp mra/pop3/pop3_cmd_handler.cpp mra/pop3/pop3_parser.cpp mra/pop3/resource.cpp mra/pop3/system_services.cpp mra/pop3/units_allocator.cpp
pop3_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
imap_SOURCES = exch/http/blocks_allocator.cpp exch/http/service.cpp mra/imap/console_cmd_handler.cpp mra/imap/console_server.cpp mra/imap/imap_cmd_parser.cpp mra/imap/imap_parser.cpp mra/imap/listener.cpp mra/imap/main.cpp mra/imap/resource.cpp mra/imap/system_services.cpp
imap_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la
libgxsvc_event_proxy_la_SOURCES = mra/event_proxy.cpp
libgxsvc_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_event_proxy_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxsvc_event_proxy_la_DEPENDENCIES = ${default_sym}
libmrasvc_event_stub_la_SOURCES = mra/event_stub.cpp
libmrasvc_event_stub_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_event_stub_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmrasvc_event_stub_la_DEPENDENCIES = ${default_sym}
libmrasvc_midb_agent_la_SOURCES = mra/midb_agent.cpp
libmrasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libmrasvc_midb_agent_la_DEPENDENCIES = ${default_sym}

# exch
http_SOURCES = exch/http/blocks_allocator.cpp exch/http/console_cmd_handler.cpp exch/http/console_server.cpp exch/http/hpm_processor.cpp exch/http/http_parser.cpp exch/http/listener.cpp exch/http/main.cpp exch/http/mod_cache.cpp exch/http/mod_fastcgi.cpp exch/http/mod_rewrite.cpp exch/http/pdu_ndr.cpp exch/http/pdu_processor.cpp exch/http/service.cpp exch/http/system_services.cpp
http_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la libgromox_webkit.la
midb_SOURCES = exch/http/service.cpp exch/midb/cmd_parser.cpp exch/midb/common_util.cpp exch/midb/console_cmd_handler.cpp exch/midb/console_server.cpp exch/midb/exmdb_client.cpp exch/midb/exmdb_ext.cpp exch/midb/exmdb_rpc.cpp exch/midb/listener.cpp exch/midb/mail_engine.cpp exch/midb/main.cpp exch/midb/system_services.cpp
midb_LDADD = -ldl -lpthread -lresolv ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
zcore_SOURCES = exch/http/service.cpp exch/zcore/ab_tree.cpp exch/zcore/attachment_object.cpp exch/zcore/bounce_producer.cpp exch/zcore/common_util.cpp exch/zcore/console_cmd_handler.cpp exch/zcore/console_server.cpp exch/zcore/container_object.cpp exch/zcore/exmdb_client.cpp exch/zcore/exmdb_ext.cpp exch/zcore/exmdb_rpc.cpp exch/zcore/folder_object.cpp exch/zcore/ics_state.cpp exch/zcore/icsdownctx_object.cpp exch/zcore/icsupctx_object.cpp exch/zcore/listener.cpp exch/zcore/main.cpp exch/zcore/message_object.cpp exch/zcore/msgchg_grouping.cpp exch/zcore/names.cpp exch/zcore/object_tree.cpp exch/zcore/rpc_ext.cpp exch/zcore/rpc_parser.cpp exch/zcore/store_object.cpp exch/zcore/system_services.cpp exch/zcore/table_object.cpp exch/zcore/user_object.cpp exch/zcore/zarafa_server.cpp
zcore_LDADD = -ldl -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libexsvc_codepage_lang_la_SOURCES = exch/codepage_lang/codepage_lang.cpp exch/codepage_lang/main.cpp
libexsvc_codepage_lang_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_codepage_lang_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_codepage_lang_la_DEPENDENCIES = ${default_sym}
libexsvc_exmdb_provider_la_SOURCES = exch/exmdb_provider/bounce_producer.cpp exch/exmdb_provider/common_util.cpp exch/exmdb_provider/db_engine.cpp exch/exmdb_provider/exmdb_client.cpp exch/exmdb_provider/exmdb_ext.cpp exch/exmdb_provider/exmdb_listener.cpp exch/exmdb_provider/exmdb_parser.cpp exch/exmdb_provider/exmdb_rpc.cpp exch/exmdb_provider/notification_agent.cpp exch/exmdb_provider/exmdb_server.cpp exch/exmdb_provider/folder.cpp exch/exmdb_provider/ics.cpp exch/exmdb_provider/instance.cpp exch/exmdb_provider/instbody.cpp exch/exmdb_provider/main.cpp exch/exmdb_provider/message.cpp exch/exmdb_provider/names.cpp exch/exmdb_provider/store.cpp exch/exmdb_provider/table.cpp
libexsvc_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libexsvc_exmdb_provider_la_DEPENDENCIES = ${default_sym}
libexsvc_timer_agent_la_SOURCES = exch/timer_agent.cpp
libexsvc_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_timer_agent_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexsvc_timer_agent_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_emsmdb_la_SOURCES = exch/exchange_emsmdb/asyncemsmdb_interface.cpp exch/exchange_emsmdb/asyncemsmdb_ndr.cpp exch/exchange_emsmdb/attachment_object.cpp exch/exchange_emsmdb/aux_ext.cpp exch/exchange_emsmdb/bounce_producer.cpp exch/exchange_emsmdb/common_util.cpp exch/exchange_emsmdb/emsmdb_interface.cpp exch/exchange_emsmdb/emsmdb_ndr.cpp exch/exchange_emsmdb/exmdb_client.cpp exch/exchange_emsmdb/fastdownctx_object.cpp exch/exchange_emsmdb/fastupctx_object.cpp exch/exchange_emsmdb/folder_object.cpp exch/exchange_emsmdb/ftstream_parser.cpp exch/exchange_emsmdb/ftstream_producer.cpp exch/exchange_emsmdb/ics_state.cpp exch/exchange_emsmdb/icsdownctx_object.cpp exch/exchange_emsmdb/icsupctx_object.cpp exch/exchange_emsmdb/logon_object.cpp exch/exchange_emsmdb/main.cpp exch/exchange_emsmdb/message_object.cpp exch/exchange_emsmdb/msgchg_grouping.cpp exch/exchange_emsmdb/names.c exch/exchange_emsmdb/notify_response.cpp exch/exchange_emsmdb/oxcfold.cpp exch/exchange_emsmdb/oxcfxics.cpp exch/exchange_emsmdb/oxcmsg.cpp exch/exchange_emsmdb/oxcnotif.cpp exch/exchange_emsmdb/oxcperm.cpp exch/exchange_emsmdb/oxcprpt.cpp exch/exchange_emsmdb/oxcstore.cpp exch/exchange_emsmdb/oxctabl.cpp exch/exchange_emsmdb/oxomsg.cpp exch/exchange_emsmdb/oxorule.cpp exch/exchange_emsmdb/rop_dispatch.cpp exch/exchange_emsmdb/rop_ext.cpp exch/exchange_emsmdb/rop_processor.cpp exch/exchange_emsmdb/stream_object.cpp exch/exchange_emsmdb/subscription_object.cpp exch/exchange_emsmdb/table_object.cpp LIBRARY/mapi_lib/lzxpress.cpp
libexproc_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libexproc_exchange_emsmdb_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_nsp_la_SOURCES = exch/exchange_nsp/ab_tree.cpp exch/exchange_nsp/common_util.cpp exch/exchange_nsp/main.cpp exch/exchange_nsp/nsp_interface.cpp exch/exchange_nsp/nsp_ndr.cpp
libexproc_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libexproc_exchange_nsp_la_DEPENDENCIES = ${default_sym}
libexproc_exchange_rfr_la_SOURCES = exch/exchange_rfr.cpp
libexproc_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libexproc_exchange_rfr_la_DEPENDENCIES = ${default_sym}
libexhpm_proxy_la_SOURCES = exch/mod_proxy.cpp
libexhpm_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libexhpm_proxy_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libexhpm_proxy_la_DEPENDENCIES = ${default_sym}
libgxsvc_abktplug_la_SOURCES = exch/abktplug.cpp
libgxsvc_abktplug_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_abktplug_la_LIBADD = libgromox_cplus.la
EXTRA_libgxsvc_abktplug_la_DEPENDENCIES = ${default_sym}
libgxsvc_at_client_la_SOURCES = exch/at_client.cpp
libgxsvc_at_client_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_at_client_la_LIBADD = ${HX_LIBS}
EXTRA_libgxsvc_at_client_la_DEPENDENCIES = ${default_sym}
libgxsvc_authmgr_la_SOURCES = exch/authmgr.cpp
libgxsvc_authmgr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_authmgr_la_LIBADD = libgromox_common.la
EXTRA_libgxsvc_authmgr_la_DEPENDENCIES = ${default_sym}
libgxsvc_ip6_container_la_SOURCES = exch/ip6_container.cpp
libgxsvc_ip6_container_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_ip6_container_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxsvc_ip6_container_la_DEPENDENCIES = ${default_sym}
libgxsvc_ip6_filter_la_SOURCES = exch/ip6_filter.cpp
libgxsvc_ip6_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_ip6_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxsvc_ip6_filter_la_DEPENDENCIES = ${default_sym}
libgxsvc_lang_charset_la_SOURCES = exch/lang_charset.cpp
libgxsvc_lang_charset_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_lang_charset_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxsvc_lang_charset_la_DEPENDENCIES = ${default_sym}
libgxsvc_ldap_adaptor_la_SOURCES = exch/ldap_adaptor.cpp
libgxsvc_ldap_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_ldap_adaptor_la_LIBADD = libgromox_common.la -lldap_r
EXTRA_libgxsvc_ldap_adaptor_la_DEPENDENCIES = ${default_sym}
libgxsvc_localemap_la_SOURCES = exch/localeplug.cpp
libgxsvc_localemap_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_localemap_la_LIBADD = libgromox_cplus.la
EXTRA_libgxsvc_localemap_la_DEPENDENCIES = ${default_sym}
libgxsvc_log_plugin_la_SOURCES = exch/log_plugin/log_plugin.cpp exch/log_plugin/main.cpp
libgxsvc_log_plugin_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_log_plugin_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxsvc_log_plugin_la_DEPENDENCIES = ${default_sym}
libgxsvc_mime_extension_la_SOURCES = exch/mime_extension.cpp
libgxsvc_mime_extension_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_mime_extension_la_LIBADD = ${HX_LIBS} libgromox_common.la
EXTRA_libgxsvc_mime_extension_la_DEPENDENCIES = ${default_sym}
libgxsvc_ms_locale_la_SOURCES = exch/ms_locale.cpp
libgxsvc_ms_locale_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_ms_locale_la_LIBADD = ${HX_LIBS} libgromox_common.la
EXTRA_libgxsvc_ms_locale_la_DEPENDENCIES = ${default_sym}
libgxsvc_mysql_adaptor_la_SOURCES = exch/mysql_adaptor/main.cpp exch/mysql_adaptor/mysql_adaptor.cpp
libgxsvc_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
EXTRA_libgxsvc_mysql_adaptor_la_DEPENDENCIES = ${default_sym}
libgxsvc_user_filter_la_SOURCES = exch/str_filter/audit_filter.cpp exch/str_filter/grey_list.cpp exch/str_filter/main.cpp exch/str_filter/str_filter.cpp exch/str_filter/temp_list.cpp
libgxsvc_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxsvc_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxsvc_user_filter_la_DEPENDENCIES = ${default_sym}

# AGENT_SERVICE
digest_SOURCES = AGENT_SERVICE/digest.cpp
digest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
freebusy_SOURCES = AGENT_SERVICE/freebusy.cpp
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_webkit.la libgromox_mapi.la
pam_gromox_la_CPPFLAGS = ${AM_CPPFLAGS}
pam_gromox_la_SOURCES = AGENT_SERVICE/pam_gromox.cpp exch/http/service.cpp
pam_gromox_la_LIBADD = -lpam ${HX_LIBS} libgromox_common.la
pam_gromox_la_LDFLAGS = -avoid-version -module ${plugin_LDFLAGS}
rtf2html_SOURCES = AGENT_SERVICE/rtf2html.cpp
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la

# SYSTEM_ADMIN
saphpdir = ${pkgdatadir}/sa
saphp_DATA = SYSTEM_ADMIN/php/conf.php SYSTEM_ADMIN/php/db.php SYSTEM_ADMIN/php/submit.php
adaptor_SOURCES = LIBRARY/system_log.c SYSTEM_ADMIN/adaptor/data_source.cpp SYSTEM_ADMIN/adaptor/engine.cpp SYSTEM_ADMIN/adaptor/file_operation.cpp SYSTEM_ADMIN/adaptor/gateway_control.cpp SYSTEM_ADMIN/adaptor/main.cpp
adaptor_LDADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
event_SOURCES = SYSTEM_ADMIN/event.cpp LIBRARY/common/fifo.cpp
event_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la
gromox_dbop_SOURCES = lib/dbop_mysql.cpp SYSTEM_ADMIN/dbop_main.cpp
gromox_dbop_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
gromox_mailq_SOURCES = SYSTEM_ADMIN/mailq.cpp
mkmidb_SOURCES = SYSTEM_ADMIN/mkmidb.cpp
mkmidb_LDADD = ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la
mkprivate_SOURCES = SYSTEM_ADMIN/mkprivate.cpp
mkprivate_LDADD = ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
mkpublic_SOURCES = SYSTEM_ADMIN/mkpublic.cpp
mkpublic_LDADD = ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
rebuild_SOURCES = SYSTEM_ADMIN/rebuild.cpp
rebuild_LDADD = ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
timer_SOURCES = SYSTEM_ADMIN/timer.cpp
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la

# php_mapi
mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
mapi_la_SOURCES = AGENT_SERVICE/php_mapi/ext_pack.cpp AGENT_SERVICE/php_mapi/mapi.cpp AGENT_SERVICE/php_mapi/rpc_ext.cpp AGENT_SERVICE/php_mapi/type_conversion.cpp AGENT_SERVICE/php_mapi/zarafa_client.cpp AGENT_SERVICE/php_mapi/zarafa_rpc.cpp
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
	doc/digest.8gx doc/domain_list.4gx \
	doc/event.8gx doc/event_stub.4gx doc/event_proxy.4gx \
	doc/exchange_emsmdb.4gx \
	doc/exchange_nsp.4gx doc/exchange_rfr.4gx doc/exmdb_provider.4gx \
	doc/freebusy.8gx doc/gromox.7 \
	doc/gromox-dbop.8gx \
	doc/gromox-exch.target.8gx doc/gromox-mailq.8gx \
	doc/gromox-mra.target.8gx doc/gromox-mta.target.8gx \
	doc/gromox-sa.target.8gx doc/http.8gx \
	doc/imap.8gx doc/ip6_container.4gx \
	doc/ldap_adaptor.4gx doc/localemap.4gx \
	doc/mapi.4gx doc/message_enqueue.4gx doc/midb.8gx \
	doc/mkmidb.8gx doc/mkprivate.8gx doc/mkpublic.8gx \
	doc/mysql_adaptor.4gx \
	doc/pam_gromox.8gx doc/pop3.8gx doc/rebuild.8gx \
	doc/rtf2html.1gx doc/sa.cfg.5gx doc/smtp.8gx \
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

AGENT_SERVICE/php_mapi/zarafa_rpc.cpp: AGENT_SERVICE/php_mapi/zarafa_client.h zcidl
	${AM_V_GEN}${top_srcdir}/zcidl <$< >$@

exch/midb/exmdb_rpc.cpp: exch/midb/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl <$< >$@

exch/zcore/exmdb_rpc.cpp: exch/zcore/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl <$< >$@

exch/exmdb_provider/exmdb_rpc.cpp: exch/exmdb_provider/exmdb_client.h exmidl
	${AM_V_GEN}${top_srcdir}/exmidl -p <$< >$@

install-data-local:
	${MKDIR_P} ${DESTDIR}${pkgdatadir}
	install -pm0644 data/* ${DESTDIR}${pkgdatadir}/
	install -pm0644 data/*.abkt ${DESTDIR}${pkgdatadir}/

.la.ldd:
	${AM_V_GEN}${top_srcdir}/lddcheck ${top_builddir}/libtool $< $@
%.service: ${top_builddir}/config.status
.tps.service:
	${AM_V_GEN}${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

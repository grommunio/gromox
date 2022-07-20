# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I build-aux
AM_CPPFLAGS = -I${top_srcdir}/include ${HX_CFLAGS} ${gumbo_CFLAGS} ${crypto_CFLAGS} ${jsoncpp_CFLAGS} ${mysql_CFLAGS} ${sqlite_CFLAGS} ${ssl_CFLAGS} ${zlib_CFLAGS}
AM_CFLAGS = ${my_CFLAGS} -fvisibility=default
AM_CXXFLAGS = ${my_CXXFLAGS}

lib_LTLIBRARIES = libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_epoll.la libgromox_mapi.la libgromox_exrpc.la libgromox_rpc.la
noinst_LTLIBRARIES = libphp_mapi.la
noinst_DATA = libgromox_common.ldd libgromox_cplus.ldd libgromox_dbop.ldd libgromox_email.ldd libgromox_epoll.ldd libgromox_exrpc.la libgromox_mapi.ldd libgromox_rpc.ldd
pkglibexec_PROGRAMS = cgkrepair cleaner delivery delmsg delivery-queue event freebusy http imap midb pop3 rebuild rtf2html timer zcore
pkglib_LTLIBRARIES = libmapi4zf.la ${mta_plugins} ${mra_plugins} ${exchange_plugins}
default_sym = ${srcdir}/default.sym
default_SYFLAGS = -Wl,--version-script=${default_sym}
plugin_LDFLAGS = -avoid-version -module ${default_SYFLAGS${NO_VSYM}}
pamlibdir = ${libdir}/security
if HAVE_PAM
pamlib_LTLIBRARIES = pam_gromox.la
noinst_DATA += pam_gromox.ldd
endif
if HAVE_PHP
phpinidir = ${PHP_SYSCONF_DIR}
phpini_DATA = php_mapi/mapi.ini
phplibdir = ${PHP_EXTENSION_DIR}
phplib_LTLIBRARIES = mapi.la
endif
sysusers_DATA = system/sysusers-gromox.conf
tmpfiles_DATA = system/tmpfiles-gromox.conf
unit_DATA = system/gromox-delivery.service system/gromox-delivery-queue.service system/gromox-event.service system/gromox-http.service system/gromox-imap.service system/gromox-midb.service system/gromox-pop3.service system/gromox-timer.service system/gromox-zcore.service

mta_plugins = \
	libgxm_alias_resolve.la \
	libgxm_exmdb_local.la \
	libgxm_mlist_expand.la \
	libgxm_remote_delivery.la
noinst_DATA += \
	libgxm_alias_resolve.ldd \
	libgxm_exmdb_local.ldd \
	libgxm_mlist_expand.ldd \
	libgxm_remote_delivery.ldd
mra_plugins = \
	libgxs_event_proxy.la \
	libgxs_event_stub.la \
	libgxs_midb_agent.la
noinst_DATA += \
	libgxs_event_proxy.ldd \
	libgxs_event_stub.ldd \
	libgxs_midb_agent.ldd
exchange_plugins = \
	libgxs_codepage_lang.la \
	libgxs_exmdb_provider.la \
	libgxs_timer_agent.la \
	libgxp_exchange_emsmdb.la \
	libgxp_exchange_nsp.la \
	libgxp_exchange_rfr.la \
	libgxh_mh_emsmdb.la libgxh_mh_nsp.la \
	libgxs_abktplug.la \
	libgxs_at_client.la \
	libgxs_authmgr.la \
	libgxs_ip6_container.la libgxs_ip6_filter.la \
	libgxs_ldap_adaptor.la \
	libgxs_logthru.la \
	libgxs_mysql_adaptor.la \
	libgxs_textmaps.la \
	libgxs_user_filter.la
noinst_DATA += \
	libgxs_codepage_lang.ldd \
	libgxs_exmdb_provider.ldd \
	libgxs_timer_agent.ldd \
	libgxp_exchange_emsmdb.ldd \
	libgxp_exchange_nsp.ldd \
	libgxp_exchange_rfr.ldd \
	libgxh_mh_emsmdb.ldd libgxh_mh_nsp.ldd \
	libgxs_abktplug.ldd \
	libgxs_at_client.ldd \
	libgxs_authmgr.ldd \
	libgxs_ip6_container.ldd libgxs_ip6_filter.ldd \
	libgxs_ldap_adaptor.ldd \
	libgxs_logthru.ldd \
	libgxs_mysql_adaptor.ldd \
	libgxs_textmaps.ldd \
	libgxs_user_filter.ldd
sbin_PROGRAMS = gromox-abktconv gromox-dbop gromox-dscli gromox-e2ghelper gromox-eml2mt gromox-exm2eml gromox-mailq gromox-mbop gromox-mkmidb gromox-mkprivate gromox-mkpublic gromox-kdb2mt gromox-mt2exm
if HAVE_PFF
sbin_PROGRAMS += gromox-pff2mt
endif
sbin_SCRIPTS = gromox-abktpull tools/gromox-ical2mt tools/gromox-vcf2mt
pkglibexec_SCRIPTS = tools/create_queue.sh

BUILT_SOURCES = include/gromox/paths.h php_mapi/mapierr.cpp php_mapi/mapitags.cpp php_mapi/zrpc.cpp exch/exmdb_provider/exmdb_rpc.cpp lib/exmdb_rpc.cpp
CLEANFILES = ${BUILT_SOURCES}
libgromox_common_la_CXXFLAGS = ${AM_CXXFLAGS} -fvisibility=default
libgromox_common_la_SOURCES = lib/config_file.cpp lib/cookie_parser.cpp lib/double_list.cpp lib/errno.cpp lib/fopen.cpp lib/guid2.cpp lib/int_hash.cpp lib/list_file.cpp lib/mail_func.cpp lib/mem_file.cpp lib/rfbl.cpp lib/simple_tree.cpp lib/single_list.cpp lib/socket.cpp lib/str_hash.cpp lib/stream.cpp lib/timezone.cpp lib/util.cpp lib/mapi/ext_buffer.cpp
libgromox_common_la_LIBADD = -lcrypt ${HX_LIBS} ${vmime_LIBS}
libgromox_cplus_la_SOURCES = lib/cryptoutil.cpp lib/dbhelper.cpp lib/fileio.cpp lib/fopen.cpp lib/oxoabkt.cpp lib/textmaps.cpp
libgromox_cplus_la_LIBADD = -lpthread ${HX_LIBS} ${crypto_LIBS} ${jsoncpp_LIBS} ${sqlite_LIBS} ${ssl_LIBS} ${zstd_LIBS} libgromox_common.la
libgromox_dbop_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_dbop_la_SOURCES = lib/dbop_mysql.cpp lib/dbop_sqlite.cpp
libgromox_dbop_la_LIBADD = ${fmt_LIBS} ${mysql_LIBS} ${sqlite_LIBS} libgromox_cplus.la
libgromox_email_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_email_la_SOURCES = lib/email/dsn.cpp lib/email/ical.cpp lib/email/ical2.cpp lib/email/mail.cpp lib/email/mime.cpp lib/email/mime_pool.cpp lib/email/mjson.cpp lib/email/vcard.cpp
libgromox_email_la_LIBADD = ${HX_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_epoll_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_epoll_la_SOURCES = lib/contexts_pool.cpp lib/threads_pool.cpp
libgromox_epoll_la_LIBADD = -lpthread -lrt libgromox_common.la
libgromox_exrpc_la_SOURCES = lib/exmdb_client.cpp lib/exmdb_ext.cpp lib/exmdb_rpc.cpp
libgromox_exrpc_la_LIBADD = libgromox_mapi.la
libgromox_mapi_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_mapi_la_SOURCES = lib/mapi/apple_util.cpp lib/mapi/applefile.cpp lib/mapi/binhex.cpp lib/mapi/eid_array.cpp lib/mapi/element_data.cpp lib/mapi/html.cpp lib/mapi/idset.cpp lib/mapi/lzxpress.cpp lib/mapi/macbinary.cpp lib/mapi/msgchg_grouping.cpp lib/mapi/oxcical.cpp lib/mapi/oxcmail.cpp lib/mapi/oxvcard.cpp lib/mapi/pcl.cpp lib/mapi/proptag_array.cpp lib/mapi/propval.cpp lib/mapi/restriction.cpp lib/mapi/restriction2.cpp lib/mapi/rop_util.cpp lib/mapi/rtf.cpp lib/mapi/rtfcp.cpp lib/mapi/rule_actions.cpp lib/mapi/sortorder_set.cpp lib/mapi/tarray_set.cpp lib/mapi/tnef.cpp lib/mapi/tpropval_array.cpp
libgromox_mapi_la_LIBADD = ${gumbo_LIBS} ${HX_LIBS} ${vmime_LIBS} libgromox_common.la libgromox_email.la
libgromox_rpc_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_rpc_la_SOURCES = lib/rpc/arcfour.cpp lib/rpc/crc32.cpp lib/rpc/ndr.cpp lib/rpc/ntlmssp.cpp
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_cplus.la

delivery_SOURCES = lib/svc_loader.cpp mda/delivery_app/main.cpp mda/delivery_app/message_dequeue.cpp mda/delivery_app/system_services.cpp mda/delivery_app/transporter.cpp
delivery_LDADD = -ldl -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
delivery_queue_SOURCES = lib/svc_loader.cpp mda/message_enqueue.cpp mda/smtp/flusher.cpp mda/smtp/listener.cpp mda/smtp/main.cpp mda/smtp/resource.cpp mda/smtp/smtp_cmd_handler.cpp mda/smtp/smtp_parser.cpp mda/smtp/system_services.cpp
delivery_queue_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la
libgxm_alias_resolve_la_SOURCES = mda/alias_resolve.cpp
libgxm_alias_resolve_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_alias_resolve_la_LIBADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
EXTRA_libgxm_alias_resolve_la_DEPENDENCIES = ${default_sym}
libgxm_exmdb_local_la_SOURCES = mda/exmdb_local/auto_response.cpp mda/exmdb_local/bounce_audit.cpp mda/exmdb_local/bounce_producer.cpp mda/exmdb_local/cache_queue.cpp mda/exmdb_local/exmdb_local.cpp mda/exmdb_local/main.cpp mda/exmdb_local/net_failure.cpp
libgxm_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
EXTRA_libgxm_exmdb_local_la_DEPENDENCIES = ${default_sym}
libgxm_mlist_expand_la_SOURCES = mda/mlist_expand/bounce_producer.cpp mda/mlist_expand/main.cpp
libgxm_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_mlist_expand_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
EXTRA_libgxm_mlist_expand_la_DEPENDENCIES = ${default_sym}
libgxm_remote_delivery_la_SOURCES = mda/remote_delivery.cpp
libgxm_remote_delivery_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_remote_delivery_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
EXTRA_libgxm_remote_delivery_la_DEPENDENCIES = ${default_sym}

pop3_SOURCES = lib/svc_loader.cpp mra/pop3/listener.cpp mra/pop3/main.cpp mra/pop3/pop3_cmd_handler.cpp mra/pop3/pop3_parser.cpp mra/pop3/resource.cpp mra/pop3/system_services.cpp
pop3_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la
imap_SOURCES = lib/svc_loader.cpp mra/imap/dir_tree.cpp mra/imap/imap_cmd_parser.cpp mra/imap/imap_parser.cpp mra/imap/listener.cpp mra/imap/main.cpp mra/imap/resource.cpp mra/imap/system_services.cpp
imap_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la libgromox_email.la
libgxs_event_proxy_la_SOURCES = mra/event_proxy.cpp
libgxs_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_event_proxy_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_event_proxy_la_DEPENDENCIES = ${default_sym}
libgxs_event_stub_la_SOURCES = mra/event_stub.cpp
libgxs_event_stub_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_event_stub_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_event_stub_la_DEPENDENCIES = ${default_sym}
libgxs_midb_agent_la_SOURCES = mra/midb_agent.cpp
libgxs_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_midb_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_midb_agent_la_DEPENDENCIES = ${default_sym}

http_SOURCES = exch/http/hpm_processor.cpp exch/http/http_parser.cpp exch/http/listener.cpp exch/http/main.cpp exch/http/mod_cache.cpp exch/http/mod_fastcgi.cpp exch/http/mod_rewrite.cpp exch/http/pdu_ndr.cpp exch/http/pdu_processor.cpp exch/http/system_services.cpp lib/svc_loader.cpp
http_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la
midb_SOURCES = exch/midb/cmd_parser.cpp exch/midb/common_util.cpp exch/midb/exmdb_client.cpp exch/midb/listener.cpp exch/midb/mail_engine.cpp exch/midb/main.cpp exch/midb/system_services.cpp lib/svc_loader.cpp
midb_LDADD = -ldl -lpthread -lresolv ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
zcore_SOURCES = exch/zcore/ab_tree.cpp exch/zcore/attachment_object.cpp exch/zcore/bounce_producer.cpp exch/zcore/common_util.cpp exch/zcore/container_object.cpp exch/zcore/exmdb_client.cpp exch/zcore/folder_object.cpp exch/zcore/ics_state.cpp exch/zcore/icsdownctx_object.cpp exch/zcore/icsupctx_object.cpp exch/zcore/listener.cpp exch/zcore/main.cpp exch/zcore/message_object.cpp exch/zcore/names.cpp exch/zcore/object_tree.cpp exch/zcore/rpc_ext.cpp exch/zcore/rpc_parser.cpp exch/zcore/store_object.cpp exch/zcore/system_services.cpp exch/zcore/table_object.cpp exch/zcore/user_object.cpp exch/zcore/zarafa_server.cpp lib/svc_loader.cpp
zcore_LDADD = -ldl -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
libgxs_codepage_lang_la_SOURCES = exch/codepage_lj.cpp
libgxs_codepage_lang_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_codepage_lang_la_LIBADD = ${HX_LIBS} ${jsoncpp_LIBS} libgromox_common.la
EXTRA_libgxs_codepage_lang_la_DEPENDENCIES = ${default_sym}
libgxs_exmdb_provider_la_SOURCES = exch/exmdb_provider/bounce_producer.cpp exch/exmdb_provider/common_util.cpp exch/exmdb_provider/db_engine.cpp exch/exmdb_provider/exmdb_client.cpp exch/exmdb_provider/exmdb_listener.cpp exch/exmdb_provider/exmdb_parser.cpp exch/exmdb_provider/exmdb_rpc.cpp exch/exmdb_provider/notification_agent.cpp exch/exmdb_provider/exmdb_server.cpp exch/exmdb_provider/folder.cpp exch/exmdb_provider/ics.cpp exch/exmdb_provider/instance.cpp exch/exmdb_provider/instbody.cpp exch/exmdb_provider/main.cpp exch/exmdb_provider/message.cpp exch/exmdb_provider/names.cpp exch/exmdb_provider/store.cpp exch/exmdb_provider/table.cpp
libgxs_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
EXTRA_libgxs_exmdb_provider_la_DEPENDENCIES = ${default_sym}
libgxs_timer_agent_la_SOURCES = exch/timer_agent.cpp
libgxs_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_timer_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_timer_agent_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_emsmdb_la_SOURCES = exch/emsmdb/asyncemsmdb_interface.cpp exch/emsmdb/asyncemsmdb_ndr.cpp exch/emsmdb/attachment_object.cpp exch/emsmdb/aux_ext.cpp exch/emsmdb/bounce_producer.cpp exch/emsmdb/common_util.cpp exch/emsmdb/emsmdb_interface.cpp exch/emsmdb/emsmdb_ndr.cpp exch/emsmdb/exmdb_client.cpp exch/emsmdb/fastdownctx_object.cpp exch/emsmdb/fastupctx_object.cpp exch/emsmdb/folder_object.cpp exch/emsmdb/ftstream_parser.cpp exch/emsmdb/ftstream_producer.cpp exch/emsmdb/ics_state.cpp exch/emsmdb/icsdownctx_object.cpp exch/emsmdb/icsupctx_object.cpp exch/emsmdb/logon_object.cpp exch/emsmdb/main.cpp exch/emsmdb/message_object.cpp exch/emsmdb/names.cpp exch/emsmdb/notify_response.cpp exch/emsmdb/oxcfold.cpp exch/emsmdb/oxcfxics.cpp exch/emsmdb/oxcmsg.cpp exch/emsmdb/oxcnotif.cpp exch/emsmdb/oxcperm.cpp exch/emsmdb/oxcprpt.cpp exch/emsmdb/oxcstore.cpp exch/emsmdb/oxctabl.cpp exch/emsmdb/oxomsg.cpp exch/emsmdb/oxorule.cpp exch/emsmdb/rop_dispatch.cpp exch/emsmdb/rop_ext.cpp exch/emsmdb/rop_processor.cpp exch/emsmdb/stream_object.cpp exch/emsmdb/subscription_object.cpp exch/emsmdb/table_object.cpp
libgxp_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libgxp_exchange_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_nsp_la_SOURCES = exch/nsp/ab_tree.cpp exch/nsp/common_util.cpp exch/nsp/main.cpp exch/nsp/nsp_interface.cpp exch/nsp/nsp_ndr.cpp
libgxp_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libgxp_exchange_nsp_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_rfr_la_SOURCES = exch/rfr.cpp
libgxp_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libgxp_exchange_rfr_la_DEPENDENCIES = ${default_sym}
libgxh_mh_emsmdb_la_SOURCES = exch/mh/emsmdb.cpp exch/mh/mh_common.cpp
libgxh_mh_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_mh_emsmdb_la_LIBADD = -lpthread libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_mh_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxh_mh_nsp_la_SOURCES = exch/mh/mh_common.cpp exch/mh/nsp.cpp exch/mh/nsp_bridge.cpp exch/mh/nsp_common.cpp exch/mh/nsp_ops.cpp
libgxh_mh_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_mh_nsp_la_LIBADD = -lpthread libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_mh_nsp_la_DEPENDENCIES = ${default_sym}
libgxs_abktplug_la_SOURCES = exch/abktplug.cpp
libgxs_abktplug_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_abktplug_la_LIBADD = libgromox_cplus.la
EXTRA_libgxs_abktplug_la_DEPENDENCIES = ${default_sym}
libgxs_at_client_la_SOURCES = exch/at_client.cpp
libgxs_at_client_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_at_client_la_LIBADD = ${HX_LIBS}
EXTRA_libgxs_at_client_la_DEPENDENCIES = ${default_sym}
libgxs_authmgr_la_SOURCES = exch/authmgr.cpp exch/authmgr.hpp
libgxs_authmgr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_authmgr_la_LIBADD = libgromox_common.la
EXTRA_libgxs_authmgr_la_DEPENDENCIES = ${default_sym}
libgxs_ip6_container_la_SOURCES = exch/ip6_container.cpp
libgxs_ip6_container_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ip6_container_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxs_ip6_container_la_DEPENDENCIES = ${default_sym}
libgxs_ip6_filter_la_SOURCES = exch/ip6_filter.cpp
libgxs_ip6_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ip6_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_ip6_filter_la_DEPENDENCIES = ${default_sym}
libgxs_ldap_adaptor_la_SOURCES = exch/ldap_adaptor.cpp
libgxs_ldap_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ldap_adaptor_la_LIBADD = libgromox_common.la libgromox_cplus.la ${libldap_LIBS}
EXTRA_libgxs_ldap_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_logthru_la_SOURCES = exch/logthru.cpp
libgxs_logthru_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_logthru_la_LIBADD = -lpthread libgromox_common.la
EXTRA_libgxs_logthru_la_DEPENDENCIES = ${default_sym}
libgxs_mysql_adaptor_la_SOURCES = exch/mysql_adaptor/mysql_adaptor.cpp exch/mysql_adaptor/sql2.cpp
libgxs_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la
EXTRA_libgxs_mysql_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_textmaps_la_SOURCES = exch/textmapplug.cpp
libgxs_textmaps_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_textmaps_la_LIBADD = ${HX_LIBS} libgromox_cplus.la
EXTRA_libgxs_textmaps_la_DEPENDENCIES = ${default_sym}
libgxs_user_filter_la_SOURCES = exch/user_filter/audit_filter.cpp exch/user_filter/grey_list.cpp exch/user_filter/main.cpp exch/user_filter/str_filter.cpp exch/user_filter/temp_list.cpp
libgxs_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_user_filter_la_DEPENDENCIES = ${default_sym}

cgkrepair_SOURCES = tools/cgkrepair.cpp tools/genimport.cpp
cgkrepair_LDADD = ${gromox_mt2exm_LDADD}
cleaner_SOURCES = tools/cleaner.cpp
cleaner_LDADD = ${fmt_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_cplus.la
delmsg_SOURCES = tools/delmsg.cpp tools/genimport.cpp
delmsg_LDADD = ${gromox_mt2exm_LDADD}
freebusy_SOURCES = tools/freebusy.cpp
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
pam_gromox_la_CPPFLAGS = ${AM_CPPFLAGS}
pam_gromox_la_SOURCES = tools/pam_gromox.cpp lib/svc_loader.cpp
pam_gromox_la_LIBADD = -lpam ${HX_LIBS} libgromox_common.la
pam_gromox_la_LDFLAGS = -avoid-version -module ${plugin_LDFLAGS}
rtf2html_SOURCES = tools/rtf2html.cpp
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
saphpdir = ${pkgdatadir}/sa
saphp_DATA = tools/php/conf.php tools/php/db.php tools/php/submit.php
event_SOURCES = tools/event.cpp
event_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la
gromox_abktconv_SOURCES = tools/abktconv.cpp
gromox_abktconv_LDADD = ${HX_LIBS} libgromox_cplus.la
gromox_dbop_SOURCES = lib/dbop_mysql.cpp tools/dbop_main.cpp
gromox_dbop_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
gromox_dscli_SOURCES = tools/dscli.cpp
gromox_dscli_LDADD = ${curl_LIBS} ${HX_LIBS} ${tinyxml_LIBS}
gromox_e2ghelper_SOURCES = tools/e2ghelper.cpp
gromox_e2ghelper_LDADD = ${HX_LIBS}
gromox_eml2mt_SOURCES = tools/eml2mt.cpp tools/genimport.cpp lib/svc_loader.cpp
gromox_eml2mt_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la -ldl
gromox_exm2eml_SOURCES = tools/exm2eml.cpp tools/genimport.cpp lib/svc_loader.cpp
gromox_exm2eml_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la -ldl
gromox_mailq_SOURCES = tools/mailq.cpp
gromox_mbop_SOURCES = tools/mbop_main.cpp
gromox_mbop_LDADD = libgromox_exrpc.la
gromox_mkmidb_SOURCES = tools/mkmidb.cpp tools/mkshared.cpp
gromox_mkmidb_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_mapi.la
gromox_mkprivate_SOURCES = tools/mkprivate.cpp tools/mkshared.cpp
gromox_mkprivate_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_mapi.la
gromox_mkpublic_SOURCES = tools/mkpublic.cpp tools/mkshared.cpp
gromox_mkpublic_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_mapi.la
gromox_kdb2mt_SOURCES = tools/genimport.cpp tools/kdb2mt.cpp
gromox_kdb2mt_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${pff_LIBS} ${zlib_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_mt2exm_SOURCES = tools/genimport.cpp tools/mt2exm.cpp
gromox_mt2exm_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_pff2mt_SOURCES = tools/genimport.cpp tools/pff2mt.cpp
gromox_pff2mt_LDADD = ${HX_LIBS} ${mysql_LIBS} ${pff_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
rebuild_SOURCES = tools/rebuild2.cpp
rebuild_LDADD = ${HX_LIBS} ${sqlite_LIBS} libgromox_cplus.la
timer_SOURCES = tools/timer.cpp
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la

libphp_mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
libphp_mapi_la_SOURCES = php_mapi/ext_pack.cpp php_mapi/mapi.cpp php_mapi/rpc_ext.cpp php_mapi/type_conversion.cpp php_mapi/zarafa_client.cpp php_mapi/zrpc.cpp
libphp_mapi_la_LIBADD = ${HX_LIBS} libgromox_common.la
libmapi4zf_la_SOURCES =
libmapi4zf_la_LDFLAGS = ${PHP_LDFLAGS}
libmapi4zf_la_LIBADD = libphp_mapi.la
mapi_la_SOURCES =
mapi_la_LDFLAGS = ${plugin_LDFLAGS} ${PHP_LDFLAGS}
mapi_la_LIBADD = libphp_mapi.la
EXTRA_mapi_la_DEPENDENCIES = ${default_sym}

noinst_PROGRAMS = tests/bodyconv tests/cryptest tests/lzxpress tests/utiltest tests/zendfake
TESTS = tests/utiltest
tests_bodyconv_SOURCES = tests/bodyconv.cpp
tests_bodyconv_LDADD = libgromox_common.la libgromox_mapi.la
tests_cryptest_SOURCES = tests/cryptest.cpp
tests_cryptest_LDADD = libgromox_common.la
tests_lzxpress_SOURCES = tests/lzxpress.cpp
tests_lzxpress_LDADD = ${HX_LIBS} libgromox_mapi.la
tests_utiltest_SOURCES = tests/utiltest.cpp
tests_utiltest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
tests_zendfake_SOURCES = tests/zendfake.cpp
tests_zendfake_LDADD = libmapi4zf.la

man_MANS = \
	doc/alias_resolve.4gx doc/at_client.4gx \
	doc/authmgr.4gx doc/autodiscover.4gx \
	doc/cgkrepair.8gx doc/cleaner.8gx \
	doc/delivery.8gx doc/delivery-queue.8gx \
	doc/delmsg.8gx doc/event.8gx doc/event_stub.4gx doc/event_proxy.4gx \
	doc/exchange_emsmdb.4gx \
	doc/exchange_nsp.4gx doc/exchange_rfr.4gx \
	doc/exmdb_local.4gx doc/exmdb_provider.4gx \
	doc/freebusy.8gx doc/gromox.7 doc/gromox-abktconv.8gx \
	doc/gromox-abktpull.8gx doc/gromox-dbop.8gx doc/gromox-dscli.8gx \
	doc/gromox-eml2mt.8gx doc/gromox-exm2eml.8gx \
	doc/gromox-kdb2mt.8gx doc/gromox-mailq.8gx doc/gromox-mbop.8gx \
	doc/gromox-mkmidb.8gx doc/gromox-mkprivate.8gx doc/gromox-mkpublic.8gx \
	doc/gromox-mt2exm.8gx doc/http.8gx \
	doc/imap.8gx doc/ip6_container.4gx doc/ldap_adaptor.4gx \
	doc/logthru.4gx \
	doc/mapi.4gx doc/mapi.7gx doc/midb.8gx doc/midb_agent.4gx \
	doc/mh_emsmdb.4gx doc/mh_nsp.4gx \
	doc/mod_cache.4gx doc/mod_fastcgi.4gx doc/mod_rewrite.4gx \
	doc/mysql_adaptor.4gx \
	doc/pam_gromox.4gx doc/pop3.8gx doc/rebuild.8gx doc/rtf2html.1gx \
	doc/textmaps.4gx doc/user_filter.4gx \
	doc/timer.8gx doc/timer_agent.4gx doc/zcore.8gx
if HAVE_PFF
man_MANS += doc/gromox-pff2mt.8gx
endif

include/gromox/paths.h: include/gromox/paths.h.in ${top_builddir}/config.status
	${AM_V_GEN}sed -e 's|#define PKGSYSCONFDIR .*|#define PKGSYSCONFDIR "${sysconfdir}/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLIBDIR .*|#define PKGLIBDIR "${pkglibdir}"|' \
	 -e 's|#define PKGDATADIR .*|#define PKGDATADIR "${pkgdatadir}"|' \
	 -e 's|#define PKGSTATEDIR .*|#define PKGSTATEDIR "${localstatedir}/lib/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLOGDIR .*|#define PKGLOGDIR "${localstatedir}/log/${PACKAGE_NAME}"|' \
	 -e 's|#define DATADIR .*|#define DATADIR "${datadir}"|' \
		<include/gromox/paths.h.in >"$@.tmp"
	${AM_V_at}if ! cmp "$@" "$@.tmp" 2>/dev/null; then mv "$@.tmp" "$@"; fi; rm -f "$@.tmp"

php_mapi/mapierr.cpp: include/gromox/mapierr.hpp tools/defs2php.sh tools/defs2php.pl
	${AM_V_GEN}${top_srcdir}/tools/defs2php.sh -e <include/gromox/mapierr.hpp >$@

php_mapi/mapitags.cpp: include/gromox/mapitags.hpp tools/defs2php.sh tools/defs2php.pl
	${AM_V_GEN}${top_srcdir}/tools/defs2php.sh -t <include/gromox/mapitags.hpp >$@

php_mapi/zrpc.cpp: php_mapi/zarafa_client.h tools/zcidl.sh tools/zcidl.pl
	${AM_V_GEN}${top_srcdir}/tools/zcidl.sh <php_mapi/zarafa_client.h >"$@"

lib/exmdb_rpc.cpp: include/gromox/exmdb_idef.hpp tools/exmidl.sh tools/exmidl.pl
	${AM_V_GEN}${top_srcdir}/tools/exmidl.sh <include/gromox/exmdb_idef.hpp >"$@"

exch/exmdb_provider/exmdb_rpc.cpp: include/gromox/exmdb_idef.hpp tools/exmidl.sh tools/exmidl.pl
	${AM_V_GEN}${top_srcdir}/tools/exmidl.sh -p <include/gromox/exmdb_idef.hpp >$@

install-exec-hook:
	${MKDIR_P} ${DESTDIR}${sbindir}
	ln -s gromox-eml2mt ${DESTDIR}${sbindir}/gromox-ical2mt
	ln -s gromox-eml2mt ${DESTDIR}${sbindir}/gromox-vcf2mt
	rm -fv ${DESTDIR}${pkglibdir}/libmapi4zf.*

install-data-local:
	${MKDIR_P} ${DESTDIR}${mandir}/man8 ${DESTDIR}${pkgdatadir}/http/php
	ln -s gromox-eml2mt.8gx ${DESTDIR}${mandir}/man8/gromox-ical2mt.8gx
	ln -s gromox-eml2mt.8gx ${DESTDIR}${mandir}/man8/gromox-vcf2mt.8gx
	cp -av data/* ${DESTDIR}${pkgdatadir}/
	cp -av exch/php/* ${DESTDIR}${pkgdatadir}/http/php/

.la.ldd:
	${AM_V_GEN}${top_srcdir}/lddcheck ${top_builddir}/libtool $< $@
%.service: ${top_builddir}/config.status
.tps.service:
	${AM_V_GEN}${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

.PHONY: tarball
tarball:
	tmpdir=$$(mktemp -dtu); \
	mkdir $$tmpdir && \
	pushd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C $$tmpdir -x && popd; \
	pushd $$tmpdir/${PACKAGE_NAME}-${PACKAGE_VERSION} && autoreconf -fi && popd; \
	tar --use=zstd -C $$tmpdir -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.zst --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/; \
	rm -Rf $$tmpdir

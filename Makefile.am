# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I build-aux
AM_CPPFLAGS = -Iinclude -I${top_srcdir}/include ${crypto_CFLAGS} ${iconv_CPPFLAGS} ${HX_CFLAGS} ${jsoncpp_CFLAGS} ${mysql_CFLAGS} ${olecf_CFLAGS} ${pff_CFLAGS} ${sqlite_CFLAGS} ${ssl_CFLAGS} ${xml2_CFLAGS} ${zlib_CFLAGS}
AM_CFLAGS = ${my_CFLAGS} -fvisibility=default
AM_CXXFLAGS = ${my_CXXFLAGS}
AM_DISTCHECK_CONFIGURE_FLAGS = --with-dcprefix='$${prefix}'

lib_LTLIBRARIES = libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_epoll.la libgromox_mapi.la libgromox_exrpc.la libgromox_rpc.la
noinst_LTLIBRARIES = libphp_mapi.la
pkglibexec_PROGRAMS = cgkrepair delivery delivery-queue event freebusy gromox-snapshot http imap midb pop3 rtf2html timer zcore
pkglib_LTLIBRARIES = libmapi4zf.la ${mta_plugins} ${mra_plugins} ${exchange_plugins}
default_sym = ${srcdir}/default.sym
default_SYFLAGS = -Wl,--version-script=${default_sym}
plugin_LDFLAGS = -avoid-version -module ${default_SYFLAGS${NO_VSYM}}
pamlibdir = ${libdir}/security
if HAVE_PAM
pamlib_LTLIBRARIES = pam_gromox.la
endif
if HAVE_PHP
phpinidir = ${dcprefix}${PHP_SYSCONF_DIR}
phpini_DATA = php_mapi/mapi.ini
phplibdir = ${dcprefix}${PHP_EXTENSION_DIR}
phplib_LTLIBRARIES = mapi.la
endif
sysusers_DATA = system/sysusers-gromox.conf
tmpfiles_DATA = system/tmpfiles-gromox.conf
unit_DATA = system/gromox-delivery.service \
	system/gromox-delivery-queue.service system/gromox-event.service \
	system/gromox-http.service system/gromox-imap.service \
	system/gromox-midb.service system/gromox-pop3.service \
	system/gromox-snapshot.service system/gromox-snapshot.timer \
	system/gromox-timer.service system/gromox-zcore.service

mta_plugins = \
	libgxm_alias_resolve.la \
	libgxm_exmdb_local.la \
	libgxm_mlist_expand.la \
	libgxm_remote_delivery.la
mra_plugins = \
	libgxs_event_proxy.la \
	libgxs_event_stub.la \
	libgxs_midb_agent.la
exchange_plugins = \
	libgxs_exmdb_provider.la \
	libgxs_timer_agent.la \
	libgxp_exchange_emsmdb.la \
	libgxp_exchange_nsp.la \
	libgxp_exchange_rfr.la \
	libgxh_ews.la libgxh_mh_emsmdb.la libgxh_mh_nsp.la libgxh_oxdisco.la libgxh_oab.la \
	libgxs_authmgr.la libgxs_dnsbl_filter.la \
	libgxs_ldap_adaptor.la \
	libgxs_mysql_adaptor.la \
	libgxs_user_filter.la
sbin_PROGRAMS = gromox-abktconv gromox-compress gromox-dbop gromox-dscli gromox-e2ghelper gromox-eml2mbox gromox-eml2mt gromox-exm2eml gromox-mailq gromox-mbop gromox-mkmidb gromox-mkprivate gromox-mkpublic gromox-kdb2mt gromox-mt2exm
if HAVE_OLECF
sbin_PROGRAMS += gromox-oxm2mt
endif
if HAVE_PFF
sbin_PROGRAMS += gromox-pff2mt
endif
sbin_SCRIPTS = gromox-abktpull tools/gromox-ical2mt tools/gromox-vcf2mt
pkglibexec_SCRIPTS = tools/cleaner tools/create_queue.sh tools/kdb-uidextract tools/kdb-uidextract-limited
noinst_DATA = dldcheck.stamp

BUILT_SOURCES = include/exmdb_dispatch.cpp include/mapierr.cpp include/mapitags.cpp include/zrpc_dispatch.cpp include/gromox/paths.h \
	php_mapi/zrpc.cpp \
	exch/exmdb_provider/exmdb_rpc.cpp \
	lib/exmdb_rpc.cpp
CLEANFILES = ${BUILT_SOURCES} dldcheck.stamp
libgromox_common_la_CXXFLAGS = ${AM_CXXFLAGS} -fvisibility=default
libgromox_common_la_SOURCES = lib/bounce_gen.cpp lib/config_file.cpp lib/cookie_parser.cpp lib/double_list.cpp lib/fopen.cpp lib/guid2.cpp lib/int_hash.cpp lib/list_file.cpp lib/mail_func.cpp lib/rfbl.cpp lib/simple_tree.cpp lib/stream.cpp lib/timezone.cpp lib/tzfile.hpp lib/tzprivate.hpp lib/util.cpp lib/wintz.cpp lib/mapi/ext_buffer.cpp
libgromox_common_la_LIBADD = -lpthread ${crypt_LIBS} ${HX_LIBS} ${iconv_LIBS} ${jsoncpp_LIBS} ${tinyxml_LIBS} ${vmime_LIBS} ${zstd_LIBS}
libgromox_cplus_la_SOURCES = lib/cryptoutil.cpp lib/dbhelper.cpp lib/fileio.cpp lib/fopen.cpp lib/oxoabkt.cpp lib/textmaps.cpp
libgromox_cplus_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${iconv_LIBS} ${jsoncpp_LIBS} ${sqlite_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_dbop_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_dbop_la_SOURCES = lib/dbop_mysql.cpp lib/dbop_sqlite.cpp
libgromox_dbop_la_LIBADD = ${fmt_LIBS} ${mysql_LIBS} ${sqlite_LIBS} libgromox_cplus.la
libgromox_email_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_email_la_SOURCES = lib/email/dsn.cpp lib/email/ical.cpp lib/email/ical2.cpp lib/email/mail.cpp lib/email/mime.cpp lib/email/mime_pool.cpp lib/email/mjson.cpp lib/email/send.cpp lib/email/vcard.cpp
libgromox_email_la_LIBADD = ${fmt_LIBS} ${HX_LIBS} ${jsoncpp_LIBS} ${ssl_LIBS} ${vmime_LIBS} libgromox_common.la libgromox_cplus.la
libgromox_epoll_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_epoll_la_SOURCES = lib/contexts_pool.cpp lib/threads_pool.cpp
libgromox_epoll_la_LIBADD = -lpthread libgromox_common.la
libgromox_exrpc_la_SOURCES = lib/exmdb_client.cpp lib/exmdb_ext.cpp lib/exmdb_rpc.cpp lib/ruleproc.cpp
libgromox_exrpc_la_LIBADD = libgromox_mapi.la
libgromox_mapi_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_mapi_la_SOURCES = lib/mapi/apple_util.cpp lib/mapi/applefile.cpp lib/mapi/binhex.cpp lib/mapi/eid_array.cpp lib/mapi/element_data.cpp lib/mapi/html.cpp lib/mapi/idset.cpp lib/mapi/lzxpress.cpp lib/mapi/macbinary.cpp lib/mapi/msgchg_grouping.cpp lib/mapi/oxcical.cpp lib/mapi/oxcmail.cpp lib/mapi/oxvcard.cpp lib/mapi/pcl.cpp lib/mapi/proptag_array.cpp lib/mapi/propval.cpp lib/mapi/restriction.cpp lib/mapi/restriction2.cpp lib/mapi/rop_util.cpp lib/mapi/rtf.cpp lib/mapi/rtfcp.cpp lib/mapi/rule_actions.cpp lib/mapi/sortorder_set.cpp lib/mapi/tarray_set.cpp lib/mapi/tnef.cpp lib/mapi/tpropval_array.cpp
libgromox_mapi_la_LIBADD = ${fmt_LIBS} ${HX_LIBS} ${iconv_LIBS} ${vmime_LIBS} ${xml2_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la
libgromox_rpc_la_CXXFLAGS = ${libgromox_common_la_CXXFLAGS}
libgromox_rpc_la_SOURCES = lib/rpc/arcfour.cpp lib/rpc/ndr.cpp lib/rpc/ntlmssp.cpp
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} ${iconv_LIBS} libgromox_common.la libgromox_cplus.la

delivery_SOURCES = lib/svc_loader.cpp mda/delivery_app/delivery.hpp mda/delivery_app/main.cpp mda/delivery_app/message_dequeue.cpp mda/delivery_app/system_services.cpp mda/delivery_app/transporter.cpp
delivery_LDADD = -lpthread ${dl_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
delivery_queue_SOURCES = lib/svc_loader.cpp mda/message_enqueue.cpp mda/smtp/flusher.cpp mda/smtp/listener.cpp mda/smtp/main.cpp mda/smtp/resource.cpp mda/smtp/smtp_cmd_handler.cpp mda/smtp/smtp_cmd_handler.h mda/smtp/smtp_aux.hpp mda/smtp/smtp_parser.cpp mda/smtp/smtp_parser.h mda/smtp/system_services.cpp
delivery_queue_LDADD = -lpthread ${crypto_LIBS} ${dl_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la
libgxm_alias_resolve_la_SOURCES = mda/alias_resolve.cpp
libgxm_alias_resolve_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_alias_resolve_la_LIBADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
EXTRA_libgxm_alias_resolve_la_DEPENDENCIES = ${default_sym}
libgxm_exmdb_local_la_SOURCES = lib/bounce_mda.cpp mda/exmdb_local/auto_response.cpp mda/exmdb_local/bounce_audit.cpp mda/exmdb_local/bounce_producer.cpp mda/exmdb_local/cache_queue.cpp mda/exmdb_local/exmdb_local.cpp mda/exmdb_local/exmdb_local.hpp mda/exmdb_local/net_failure.cpp
libgxm_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} ${jsoncpp_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
EXTRA_libgxm_exmdb_local_la_DEPENDENCIES = ${default_sym}
libgxm_mlist_expand_la_SOURCES = lib/bounce_mda.cpp mda/mlist_expand/bounce_producer.cpp mda/mlist_expand/bounce_producer.h mda/mlist_expand/main.cpp
libgxm_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_mlist_expand_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la
EXTRA_libgxm_mlist_expand_la_DEPENDENCIES = ${default_sym}
libgxm_remote_delivery_la_SOURCES = mda/remote_delivery.cpp
libgxm_remote_delivery_la_LDFLAGS = ${plugin_LDFLAGS}
libgxm_remote_delivery_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
EXTRA_libgxm_remote_delivery_la_DEPENDENCIES = ${default_sym}

pop3_SOURCES = lib/svc_loader.cpp mra/midb_agent.hpp mra/pop3/listener.cpp mra/pop3/main.cpp mra/pop3/pop3.hpp mra/pop3/pop3_cmd_handler.cpp mra/pop3/pop3_parser.cpp mra/pop3/resource.cpp mra/pop3/system_services.cpp
pop3_LDADD = -lpthread ${crypto_LIBS} ${dl_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la libgromox_exrpc.la
imap_SOURCES = lib/svc_loader.cpp mra/midb_agent.hpp mra/imap/dir_tree.cpp mra/imap/imap.hpp mra/imap/imap_cmd_parser.cpp mra/imap/imap_parser.cpp mra/imap/listener.cpp mra/imap/main.cpp mra/imap/resource.cpp mra/imap/system_services.cpp
imap_LDADD = -lpthread ${crypto_LIBS} ${dl_LIBS} ${HX_LIBS} ${jsoncpp_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la libgromox_email.la libgromox_exrpc.la
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

http_SOURCES = exch/http/hpm_processor.cpp exch/http/hpm_processor.h exch/http/http_parser.cpp exch/http/http_parser.h exch/http/listener.cpp exch/http/listener.h exch/http/main.cpp exch/http/mod_cache.cpp exch/http/mod_cache.hpp exch/http/mod_fastcgi.cpp exch/http/mod_fastcgi.h exch/http/mod_rewrite.cpp exch/http/mod_rewrite.h exch/http/pdu_ndr.cpp exch/http/pdu_ndr.h exch/http/pdu_ndr_ids.hpp exch/http/pdu_processor.cpp exch/http/pdu_processor.h exch/http/resource.h exch/http/system_services.cpp exch/http/system_services.hpp lib/svc_loader.cpp
http_LDADD = -lpthread ${crypto_LIBS} ${dl_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la
midb_SOURCES = exch/midb/cmd_parser.cpp exch/midb/cmd_parser.h exch/midb/common_util.cpp exch/midb/common_util.h exch/midb/exmdb_client.cpp exch/midb/exmdb_client.h exch/midb/listener.cpp exch/midb/listener.h exch/midb/mail_engine.cpp exch/midb/mail_engine.hpp exch/midb/main.cpp exch/midb/system_services.cpp exch/midb/system_services.hpp lib/svc_loader.cpp
midb_LDADD = -lpthread ${HX_LIBS} ${dl_LIBS} ${iconv_LIBS} ${jsoncpp_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
zcore_SOURCES = exch/zcore/ab_tree.cpp exch/zcore/ab_tree.h exch/zcore/attachment_object.cpp exch/zcore/bounce_producer.hpp exch/zcore/common_util.cpp exch/zcore/common_util.h exch/zcore/container_object.cpp exch/zcore/exmdb_client.cpp exch/zcore/exmdb_client.h exch/zcore/folder_object.cpp exch/zcore/ics_state.cpp exch/zcore/ics_state.h exch/zcore/icsdownctx_object.cpp exch/zcore/icsupctx_object.cpp exch/zcore/listener.cpp exch/zcore/listener.hpp exch/zcore/main.cpp exch/zcore/message_object.cpp exch/zcore/names.cpp exch/zcore/object_tree.cpp exch/zcore/object_tree.h exch/zcore/objects.hpp exch/zcore/rpc_ext.cpp exch/zcore/rpc_ext.h exch/zcore/rpc_parser.cpp exch/zcore/rpc_parser.hpp exch/zcore/store_object.cpp exch/zcore/store_object.h exch/zcore/system_services.cpp exch/zcore/system_services.hpp exch/zcore/table_object.cpp exch/zcore/table_object.h exch/zcore/user_object.cpp exch/zcore/zserver.cpp exch/zcore/zserver.hpp lib/svc_loader.cpp
zcore_LDADD = -lpthread ${crypto_LIBS} ${dl_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
libgxs_exmdb_provider_la_SOURCES = exch/exmdb_provider/bounce_producer.cpp exch/exmdb_provider/common_util.cpp exch/exmdb_provider/db_engine.cpp exch/exmdb_provider/exmdb_client.cpp exch/exmdb_provider/exmdb_listener.cpp exch/exmdb_provider/exmdb_parser.cpp exch/exmdb_provider/exmdb_rpc.cpp exch/exmdb_provider/notification_agent.cpp exch/exmdb_provider/exmdb_server.cpp exch/exmdb_provider/folder.cpp exch/exmdb_provider/ics.cpp exch/exmdb_provider/instance.cpp exch/exmdb_provider/instbody.cpp exch/exmdb_provider/main.cpp exch/exmdb_provider/message.cpp exch/exmdb_provider/names.cpp exch/exmdb_provider/store.cpp exch/exmdb_provider/store2.cpp exch/exmdb_provider/table.cpp
libgxs_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${fmt_LIBS} ${HX_LIBS} ${iconv_LIBS} ${sqlite_LIBS} ${xxhash_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
EXTRA_libgxs_exmdb_provider_la_DEPENDENCIES = ${default_sym}
libgxs_timer_agent_la_SOURCES = exch/timer_agent.cpp
libgxs_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_timer_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_timer_agent_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_emsmdb_la_SOURCES = exch/emsmdb/asyncemsmdb_interface.cpp exch/emsmdb/asyncemsmdb_interface.h exch/emsmdb/attachment_object.cpp exch/emsmdb/attachment_object.h exch/emsmdb/aux_ext.cpp exch/emsmdb/aux_types.h exch/emsmdb/common_util.cpp exch/emsmdb/common_util.h exch/emsmdb/emsmdb_interface.cpp exch/emsmdb/emsmdb_interface.h exch/emsmdb/emsmdb_ndr.cpp exch/emsmdb/emsmdb_ndr.h exch/emsmdb/exmdb_client.cpp exch/emsmdb/exmdb_client.h exch/emsmdb/fastdownctx_object.cpp exch/emsmdb/fastdownctx_object.h exch/emsmdb/fastupctx_object.cpp exch/emsmdb/fastupctx_object.h exch/emsmdb/folder_object.cpp exch/emsmdb/folder_object.h exch/emsmdb/ftstream_parser.cpp exch/emsmdb/ftstream_parser.h exch/emsmdb/ftstream_producer.cpp exch/emsmdb/ftstream_producer.h exch/emsmdb/ics_state.cpp exch/emsmdb/ics_state.h exch/emsmdb/icsdownctx_object.cpp exch/emsmdb/icsdownctx_object.h exch/emsmdb/icsupctx_object.cpp exch/emsmdb/icsupctx_object.h exch/emsmdb/logon_object.cpp exch/emsmdb/logon_object.h exch/emsmdb/main.cpp exch/emsmdb/message_object.cpp exch/emsmdb/message_object.h exch/emsmdb/names.cpp exch/emsmdb/notify_response.cpp exch/emsmdb/notify_response.h exch/emsmdb/oxcfold.cpp exch/emsmdb/oxcfxics.cpp exch/emsmdb/oxcmsg.cpp exch/emsmdb/oxcnotif.cpp exch/emsmdb/oxcperm.cpp exch/emsmdb/oxcprpt.cpp exch/emsmdb/oxcstore.cpp exch/emsmdb/oxctabl.cpp exch/emsmdb/oxomsg.cpp exch/emsmdb/oxorule.cpp exch/emsmdb/processor_types.h exch/emsmdb/rop_dispatch.cpp exch/emsmdb/rop_dispatch.h exch/emsmdb/rop_ext.cpp exch/emsmdb/rop_ext.h exch/emsmdb/rop_funcs.hpp exch/emsmdb/rop_ids.hpp exch/emsmdb/rop_processor.cpp exch/emsmdb/rop_processor.h exch/emsmdb/stream_object.cpp exch/emsmdb/stream_object.h exch/emsmdb/subscription_object.cpp exch/emsmdb/subscription_object.h exch/emsmdb/table_object.cpp exch/emsmdb/table_object.h
libgxp_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} ${iconv_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libgxp_exchange_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_nsp_la_SOURCES = exch/nsp/ab_tree.cpp exch/nsp/ab_tree.h exch/nsp/common_util.cpp exch/nsp/common_util.h exch/nsp/main.cpp exch/nsp/nsp_interface.cpp exch/nsp/nsp_interface.hpp exch/nsp/nsp_ndr.cpp exch/nsp/nsp_ndr.hpp exch/nsp/nsp_types.h
libgxp_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${iconv_LIBS} libgromox_common.la libgromox_mapi.la libgromox_rpc.la
EXTRA_libgxp_exchange_nsp_la_DEPENDENCIES = ${default_sym}
libgxp_exchange_rfr_la_SOURCES = exch/rfr.cpp
libgxp_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxp_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
EXTRA_libgxp_exchange_rfr_la_DEPENDENCIES = ${default_sym}
libgxh_ews_la_SOURCES = exch/ews/context.cpp exch/ews/enums.hpp exch/ews/ews.cpp exch/ews/ews.hpp exch/ews/exceptions.hpp exch/ews/freebusy.cpp exch/ews/requests.cpp exch/ews/requests.hpp exch/ews/serialization.cpp exch/ews/serialization.hpp exch/ews/soaputil.cpp exch/ews/soaputil.hpp exch/ews/structures.cpp exch/ews/structures.hpp
libgxh_ews_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_ews_la_LIBADD = ${HX_LIBS} ${fmt_LIBS} ${tinyxml_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
EXTRA_libgxh_ews_la_DEPENDENCIES = ${default_sym}
libgxh_mh_emsmdb_la_SOURCES = exch/mh/emsmdb.cpp exch/mh/mh_common.cpp exch/mh/mh_common.hpp 
libgxh_mh_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_mh_emsmdb_la_LIBADD = -lpthread ${fmt_LIBS} libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_mh_emsmdb_la_DEPENDENCIES = ${default_sym}
libgxh_mh_nsp_la_SOURCES = exch/mh/mh_common.cpp exch/mh/mh_common.hpp exch/mh/nsp.cpp exch/mh/nsp_bridge.cpp exch/mh/nsp_bridge.hpp exch/mh/nsp_common.cpp exch/mh/nsp_common.hpp exch/mh/nsp_ops.cpp exch/mh/nsp_ops.hpp
libgxh_mh_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_mh_nsp_la_LIBADD = -lpthread ${fmt_LIBS} libgromox_common.la libgromox_mapi.la
EXTRA_libgxh_mh_nsp_la_DEPENDENCIES = ${default_sym}
libgxh_oxdisco_la_SOURCES = exch/oxdisco.cpp
libgxh_oxdisco_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_oxdisco_la_LIBADD = ${HX_LIBS} ${fmt_LIBS} ${tinyxml_LIBS} libgromox_common.la
EXTRA_libgxh_oxdisco_la_DEPENDENCIES = ${default_sym}
libgxh_oab_la_SOURCES = exch/oab.cpp
libgxh_oab_la_LDFLAGS = ${plugin_LDFLAGS}
libgxh_oab_la_LIBADD = libgromox_common.la
EXTRA_libgxh_oab_la_DEPENDENCIES = ${default_sym}
libgxs_authmgr_la_SOURCES = exch/authmgr.cpp exch/ldap_adaptor.hpp
libgxs_authmgr_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_authmgr_la_LIBADD = libgromox_common.la
EXTRA_libgxs_authmgr_la_DEPENDENCIES = ${default_sym}
libgxs_dnsbl_filter_la_SOURCES = exch/dnsbl_filter.cpp
libgxs_dnsbl_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_dnsbl_filter_la_LIBADD = -lresolv libgromox_common.la
EXTRA_libgxs_dnsbl_filter_la_DEPENDENCIES = ${default_sym}
libgxs_ldap_adaptor_la_SOURCES = exch/ldap_adaptor.cpp exch/ldap_adaptor.hpp
libgxs_ldap_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_ldap_adaptor_la_LIBADD = libgromox_common.la libgromox_cplus.la ${libldap_LIBS}
EXTRA_libgxs_ldap_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_mysql_adaptor_la_SOURCES = exch/mysql_adaptor/mysql_adaptor.cpp exch/mysql_adaptor/sql2.cpp exch/mysql_adaptor/sql2.hpp
libgxs_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_mysql_adaptor_la_LIBADD = -lpthread ${crypt_LIBS} ${HX_LIBS} ${fmt_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_mapi.la
EXTRA_libgxs_mysql_adaptor_la_DEPENDENCIES = ${default_sym}
libgxs_user_filter_la_SOURCES = exch/user_filter/audit_filter.cpp exch/user_filter/grey_list.cpp exch/user_filter/main.cpp exch/user_filter/str_filter.cpp exch/user_filter/temp_list.cpp exch/user_filter/user_filter.hpp
libgxs_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libgxs_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
EXTRA_libgxs_user_filter_la_DEPENDENCIES = ${default_sym}

cgkrepair_SOURCES = tools/cgkrepair.cpp tools/genimport.cpp tools/genimport.hpp
cgkrepair_LDADD = ${gromox_mt2exm_LDADD}
freebusy_SOURCES = tools/freebusy.cpp
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
pam_gromox_la_CPPFLAGS = ${AM_CPPFLAGS}
pam_gromox_la_SOURCES = tools/pam_gromox.cpp lib/svc_loader.cpp
pam_gromox_la_LIBADD = -lpam ${dl_LIBS} ${HX_LIBS} libgromox_common.la
pam_gromox_la_LDFLAGS = -avoid-version -module ${plugin_LDFLAGS}
rtf2html_SOURCES = tools/rtf2html.cpp
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
saphpdir = ${pkgdatadir}/sa
saphp_DATA = tools/php/submit.php
event_SOURCES = tools/event.cpp
event_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
gromox_abktconv_SOURCES = tools/abktconv.cpp
gromox_abktconv_LDADD = ${HX_LIBS} libgromox_cplus.la
gromox_compress_SOURCES = tools/compress.cpp
gromox_compress_LDADD = ${HX_LIBS} libgromox_common.la
gromox_dbop_SOURCES = lib/dbop_mysql.cpp tools/dbop_main.cpp
gromox_dbop_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_dbop.la
gromox_dscli_SOURCES = tools/dscli.cpp
gromox_dscli_LDADD = ${curl_LIBS} ${HX_LIBS} ${resolv_LIBS} ${tinyxml_LIBS}
gromox_e2ghelper_SOURCES = tools/e2ghelper.cpp
gromox_e2ghelper_LDADD = ${HX_LIBS}
gromox_eml2mbox_SOURCES = tools/eml2mbox.cpp
gromox_eml2mbox_LDADD = ${HX_LIBS}
gromox_eml2mt_SOURCES = lib/svc_loader.cpp tools/eml2mt.cpp tools/genimport.cpp tools/genimport.hpp
gromox_eml2mt_LDADD = ${dl_LIBS} ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
gromox_exm2eml_SOURCES = lib/svc_loader.cpp tools/exm2eml.cpp tools/genimport.cpp tools/genimport.hpp
gromox_exm2eml_LDADD = ${dl_LIBS} ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_email.la libgromox_exrpc.la libgromox_mapi.la
gromox_mailq_SOURCES = tools/mailq.cpp
gromox_mailq_LDADD = libgromox_common.la
gromox_mbop_SOURCES = tools/genimport.cpp tools/genimport.hpp tools/mbop_main.cpp
gromox_mbop_LDADD = ${gromox_mt2exm_LDADD}
gromox_mkmidb_SOURCES = tools/mkmidb.cpp tools/mkshared.cpp tools/mkshared.hpp
gromox_mkmidb_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_mapi.la
gromox_mkprivate_SOURCES = tools/mkprivate.cpp tools/mkshared.cpp tools/mkshared.hpp
gromox_mkprivate_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_mapi.la
gromox_mkpublic_SOURCES = tools/mkpublic.cpp tools/mkshared.cpp tools/mkshared.hpp
gromox_mkpublic_LDADD = ${fmt_LIBS} ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_cplus.la libgromox_dbop.la libgromox_email.la libgromox_mapi.la
gromox_kdb2mt_SOURCES = tools/genimport.cpp tools/genimport.hpp tools/kdb2mt.cpp
gromox_kdb2mt_LDADD = ${fmt_LIBS} ${HX_LIBS} ${jsoncpp_LIBS} ${mysql_LIBS} ${pff_LIBS} ${zlib_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_mt2exm_SOURCES = tools/genimport.cpp tools/genimport.hpp tools/mt2exm.cpp
gromox_mt2exm_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_oxm2mt_SOURCES = tools/genimport.cpp tools/genimport.hpp tools/oxm2mt.cpp
gromox_oxm2mt_LDADD = ${HX_LIBS} ${fmt_LIBS} ${iconv_LIBS} ${mysql_LIBS} ${olecf_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_pff2mt_SOURCES = tools/genimport.cpp tools/genimport.hpp tools/pff2mt.cpp
gromox_pff2mt_LDADD = ${HX_LIBS} ${iconv_LIBS} ${mysql_LIBS} ${pff_LIBS} libgromox_common.la libgromox_cplus.la libgromox_exrpc.la libgromox_mapi.la
gromox_snapshot_SOURCES = tools/snapshot.cpp
gromox_snapshot_LDADD = ${HX_LIBS} libgromox_common.la
timer_SOURCES = tools/timer.cpp
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la

libphp_mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
libphp_mapi_la_SOURCES = php_mapi/ext.hpp php_mapi/ext_pack.cpp php_mapi/mapi.cpp php_mapi/mapi_arginfo.hpp php_mapi/rpc_ext.cpp php_mapi/type_conversion.cpp php_mapi/type_conversion.hpp php_mapi/zclient.cpp php_mapi/zrpc.cpp
libphp_mapi_la_LIBADD = ${fmt_LIBS} ${HX_LIBS} libgromox_common.la
libmapi4zf_la_SOURCES =
libmapi4zf_la_LDFLAGS = ${PHP_LDFLAGS}
libmapi4zf_la_LIBADD = libphp_mapi.la
mapi_la_SOURCES =
mapi_la_LDFLAGS = ${plugin_LDFLAGS} ${PHP_LDFLAGS}
mapi_la_LIBADD = libphp_mapi.la
EXTRA_mapi_la_DEPENDENCIES = ${default_sym}

noinst_PROGRAMS = dldcheck tests/bdump tests/bodyconv tests/compress tests/cryptest tests/jsontest tests/lzxpress tests/utiltest tests/vcard tests/zendfake tools/tzdump
dldcheck_SOURCES = tools/dldcheck.cpp
dldcheck_LDADD = ${dl_LIBS}
TESTS = tests/utiltest
tests_bdump_SOURCES = tests/bdump.cpp
tests_bdump_LDADD = ${HX_LIBS} libgromox_common.la libgromox_mapi.la
tests_bodyconv_SOURCES = tests/bodyconv.cpp
tests_bodyconv_LDADD = libgromox_common.la libgromox_mapi.la
tests_compress_SOURCES = tests/compress.cpp
tests_compress_LDADD = libgromox_common.la
tests_cryptest_SOURCES = tests/cryptest.cpp
tests_cryptest_LDADD = libgromox_common.la
tests_jsontest_SOURCES = tests/jsontest.cpp
tests_jsontest_LDADD = ${jsoncpp_LIBS} libgromox_common.la libgromox_email.la
tests_lzxpress_SOURCES = tests/lzxpress.cpp
tests_lzxpress_LDADD = ${HX_LIBS} libgromox_mapi.la
tests_utiltest_SOURCES = tests/utiltest.cpp
tests_utiltest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
tests_vcard_SOURCES = tests/vcard.cpp
tests_vcard_LDADD = ${HX_LIBS} libgromox_email.la
tests_zendfake_SOURCES = tests/zendfake.cpp
tests_zendfake_LDADD = libmapi4zf.la
tools_tzdump_SOURCES = tools/tzdump.cpp
tools_tzdump_LDADD = ${HX_LIBS} libgromox_common.la

man_MANS = \
	doc/alias_resolve.4gx \
	doc/authmgr.4gx doc/autodiscover.4gx \
	doc/cgkrepair.8gx doc/cleaner.8gx doc/gromox-compress.8 \
	doc/delivery.8gx doc/delivery-queue.8gx doc/dnsbl_filter.4gx \
	doc/event.8gx doc/event_stub.4gx doc/event_proxy.4gx \
	doc/exchange_emsmdb.4gx \
	doc/exchange_nsp.4gx doc/exchange_rfr.4gx \
	doc/exmdb_local.4gx doc/exmdb_provider.4gx \
	doc/freebusy.8gx doc/gromox.7 doc/gromox.cfg.5 doc/gromox-abktconv.8 \
	doc/gromox-abktpull.8 doc/gromox-dbop.8 doc/gromox-dscli.8 \
	doc/gromox-eml2mbox.8 doc/gromox-eml2mt.8 doc/gromox-exm2eml.8 \
	doc/gromox-kdb2mt.8 doc/gromox-mailq.8 doc/gromox-mbop.8 \
	doc/gromox-mkmidb.8 doc/gromox-mkprivate.8 doc/gromox-mkpublic.8 \
	doc/gromox-mt2exm.8 doc/gromox-snapshot.8 doc/http.8gx \
	doc/imap.8gx \
	doc/kdb-uidextract.8 doc/kdb-uidextract-limited.8 \
	doc/ldap_adaptor.4gx \
	doc/mapi.4gx doc/mapi.7gx doc/midb.8gx doc/midb_agent.4gx \
	doc/mh_emsmdb.4gx doc/mh_nsp.4gx \
	doc/mod_cache.4gx doc/mod_fastcgi.4gx doc/mod_rewrite.4gx \
	doc/mysql_adaptor.4gx \
	doc/pam_gromox.4gx doc/pop3.8gx doc/rtf2html.1gx \
	doc/user_filter.4gx \
	doc/timer.8gx doc/timer_agent.4gx doc/zcore.8gx
if HAVE_OLECF
man_MANS += doc/gromox-oxm2mt.8
endif
if HAVE_PFF
man_MANS += doc/gromox-pff2mt.8
endif

abkt_files = data/401-0.abkt data/401-1.abkt data/401-2.abkt data/401-200.abkt data/401-3.abkt data/401-6.abkt data/402-0.abkt data/402-1.abkt data/402-2.abkt data/402-200.abkt data/402-3.abkt data/402-6.abkt data/403-0.abkt data/403-1.abkt data/403-2.abkt data/403-200.abkt data/403-3.abkt data/403-6.abkt data/404-0.abkt data/404-1.abkt data/404-2.abkt data/404-200.abkt data/404-3.abkt data/404-6.abkt data/405-0.abkt data/405-1.abkt data/405-2.abkt data/405-200.abkt data/405-3.abkt data/405-6.abkt data/406-0.abkt data/406-1.abkt data/406-2.abkt data/406-200.abkt data/406-3.abkt data/406-6.abkt data/407-0.abkt data/407-1.abkt data/407-2.abkt data/407-200.abkt data/407-3.abkt data/407-6.abkt data/408-0.abkt data/408-1.abkt data/408-2.abkt data/408-200.abkt data/408-3.abkt data/408-6.abkt data/409-0.abkt data/409-1.abkt data/409-2.abkt data/409-200.abkt data/409-3.abkt data/409-6.abkt data/40b-0.abkt data/40b-1.abkt data/40b-2.abkt data/40b-200.abkt data/40b-3.abkt data/40b-6.abkt
abkt_files += data/40c-0.abkt data/40c-1.abkt data/40c-2.abkt data/40c-200.abkt data/40c-3.abkt data/40c-6.abkt data/40d-0.abkt data/40d-1.abkt data/40d-2.abkt data/40d-200.abkt data/40d-3.abkt data/40d-6.abkt data/40e-0.abkt data/40e-1.abkt data/40e-2.abkt data/40e-200.abkt data/40e-3.abkt data/40e-6.abkt data/40f-0.abkt data/40f-1.abkt data/40f-2.abkt data/40f-200.abkt data/40f-3.abkt data/40f-6.abkt data/410-0.abkt data/410-1.abkt data/410-2.abkt data/410-200.abkt data/410-3.abkt data/410-6.abkt data/411-0.abkt data/411-1.abkt data/411-2.abkt data/411-200.abkt data/411-3.abkt data/411-6.abkt data/412-0.abkt data/412-1.abkt data/412-2.abkt data/412-200.abkt data/412-3.abkt data/412-6.abkt data/413-0.abkt data/413-1.abkt data/413-2.abkt data/413-200.abkt data/413-3.abkt data/413-6.abkt data/414-0.abkt data/414-1.abkt data/414-2.abkt data/414-200.abkt data/414-3.abkt data/414-6.abkt data/415-0.abkt data/415-1.abkt data/415-2.abkt data/415-200.abkt data/415-3.abkt data/415-6.abkt
abkt_files += data/416-0.abkt data/416-1.abkt data/416-2.abkt data/416-200.abkt data/416-3.abkt data/416-6.abkt data/418-0.abkt data/418-1.abkt data/418-2.abkt data/418-200.abkt data/418-3.abkt data/418-6.abkt data/419-0.abkt data/419-1.abkt data/419-2.abkt data/419-200.abkt data/419-3.abkt data/419-6.abkt data/41a-0.abkt data/41a-1.abkt data/41a-2.abkt data/41a-200.abkt data/41a-3.abkt data/41a-6.abkt data/41b-0.abkt data/41b-1.abkt data/41b-2.abkt data/41b-200.abkt data/41b-3.abkt data/41b-6.abkt data/41d-0.abkt data/41d-1.abkt data/41d-2.abkt data/41d-200.abkt data/41d-3.abkt data/41d-6.abkt data/41e-0.abkt data/41e-1.abkt data/41e-2.abkt data/41e-200.abkt data/41e-3.abkt data/41e-6.abkt data/41f-0.abkt data/41f-1.abkt data/41f-2.abkt data/41f-200.abkt data/41f-3.abkt data/41f-6.abkt data/420-0.abkt data/420-1.abkt data/420-2.abkt data/420-200.abkt data/420-3.abkt data/420-6.abkt data/421-0.abkt data/421-1.abkt data/421-2.abkt data/421-200.abkt data/421-3.abkt data/421-6.abkt
abkt_files += data/422-0.abkt data/422-1.abkt data/422-2.abkt data/422-200.abkt data/422-3.abkt data/422-6.abkt data/424-0.abkt data/424-1.abkt data/424-2.abkt data/424-200.abkt data/424-3.abkt data/424-6.abkt data/425-0.abkt data/425-1.abkt data/425-2.abkt data/425-200.abkt data/425-3.abkt data/425-6.abkt data/426-0.abkt data/426-1.abkt data/426-2.abkt data/426-200.abkt data/426-3.abkt data/426-6.abkt data/427-0.abkt data/427-1.abkt data/427-2.abkt data/427-200.abkt data/427-3.abkt data/427-6.abkt data/429-0.abkt data/429-1.abkt data/429-2.abkt data/429-200.abkt data/429-3.abkt data/429-6.abkt data/42a-0.abkt data/42a-1.abkt data/42a-2.abkt data/42a-200.abkt data/42a-3.abkt data/42a-6.abkt data/42d-0.abkt data/42d-1.abkt data/42d-2.abkt data/42d-200.abkt data/42d-3.abkt data/42d-6.abkt data/439-0.abkt data/439-1.abkt data/439-2.abkt data/439-200.abkt data/439-3.abkt data/439-6.abkt data/43e-0.abkt data/43e-1.abkt data/43e-2.abkt data/43e-200.abkt data/43e-3.abkt data/43e-6.abkt
abkt_files += data/43f-0.abkt data/43f-1.abkt data/43f-2.abkt data/43f-200.abkt data/43f-3.abkt data/43f-6.abkt data/456-0.abkt data/456-1.abkt data/456-2.abkt data/456-200.abkt data/456-3.abkt data/456-6.abkt data/464-0.abkt data/464-1.abkt data/464-2.abkt data/464-200.abkt data/464-3.abkt data/464-6.abkt data/804-0.abkt data/804-1.abkt data/804-2.abkt data/804-200.abkt data/804-3.abkt data/804-6.abkt data/816-0.abkt data/816-1.abkt data/816-2.abkt data/816-200.abkt data/816-3.abkt data/816-6.abkt data/81a-0.abkt data/81a-1.abkt data/81a-2.abkt data/81a-200.abkt data/81a-3.abkt data/81a-6.abkt data/8411-0.abkt data/8411-1.abkt data/8411-2.abkt data/8411-200.abkt data/8411-3.abkt data/8411-6.abkt data/c04-0.abkt data/c04-1.abkt data/c04-2.abkt data/c04-200.abkt data/c04-3.abkt data/c04-6.abkt data/c0a-0.abkt data/c0a-1.abkt data/c0a-2.abkt data/c0a-200.abkt data/c0a-3.abkt data/c0a-6.abkt data/c1a-0.abkt data/c1a-1.abkt data/c1a-2.abkt data/c1a-200.abkt data/c1a-3.abkt data/c1a-6.abkt
tzd_files = data/AUS_Central.tzd data/AUS_Eastern.tzd data/Afghanistan.tzd data/Alaskan.tzd data/Aleutian.tzd data/Altai.tzd data/Arab.tzd data/Arabian.tzd data/Arabic.tzd data/Argentina.tzd data/Astrakhan.tzd data/Atlantic.tzd data/Aus_Central_W_.tzd data/Azerbaijan.tzd data/Azores.tzd data/Bahia.tzd data/Bangladesh.tzd data/Belarus.tzd data/Bougainville.tzd data/Canada_Central.tzd data/Cape_Verde.tzd data/Caucasus.tzd data/Cen__Australia.tzd data/Central.tzd data/Central_America.tzd data/Central_Asia.tzd data/Central_Brazilian.tzd data/Central_Europe.tzd data/Central_European.tzd data/Central_Pacific.tzd data/Central__Mexico_.tzd data/Chatham_Islands.tzd data/China.tzd data/Cuba.tzd data/Dateline.tzd data/E__Africa.tzd data/E__Australia.tzd data/E__Europe.tzd data/E__South_America.tzd data/Easter_Island.tzd data/Eastern.tzd data/Eastern__Mexico_.tzd data/Egypt.tzd data/Ekaterinburg.tzd data/FLE.tzd data/Fiji.tzd data/GMT.tzd data/GTB.tzd data/Georgian.tzd data/Greenland.tzd data/Greenwich.tzd
tzd_files += data/Haiti.tzd data/Hawaiian.tzd data/India.tzd data/Iran.tzd data/Israel.tzd data/Jordan.tzd data/Kaliningrad.tzd data/Korea.tzd data/Libya.tzd data/Line_Islands.tzd data/Lord_Howe.tzd data/Magadan.tzd data/Magallanes.tzd data/Marquesas.tzd data/Mauritius.tzd data/Middle_East.tzd data/Montevideo.tzd data/Morocco.tzd data/Mountain.tzd data/Mountain__Mexico_.tzd data/Myanmar.tzd data/N__Central_Asia.tzd data/Namibia.tzd data/Nepal.tzd data/New_Zealand.tzd data/Newfoundland.tzd data/Norfolk.tzd data/North_Asia.tzd data/North_Asia_East.tzd data/North_Korea.tzd data/Omsk.tzd data/Pacific.tzd data/Pacific_SA.tzd data/Pacific__Mexico_.tzd data/Pakistan.tzd data/Paraguay.tzd data/Qyzylorda.tzd data/Romance.tzd data/Russia_Time_Zone_10.tzd data/Russia_Time_Zone_11.tzd data/Russia_Time_Zone_3.tzd data/Russian.tzd
tzd_files += data/SA_Eastern.tzd data/SA_Pacific.tzd data/SA_Western.tzd data/SE_Asia.tzd data/Saint_Pierre.tzd data/Sakhalin.tzd data/Samoa.tzd data/Sao_Tome.tzd data/Saratov.tzd data/Singapore.tzd data/South_Africa.tzd data/South_Sudan.tzd data/Sri_Lanka.tzd data/Sudan.tzd data/Syria.tzd data/Taipei.tzd data/Tasmania.tzd data/Tocantins.tzd data/Tokyo.tzd data/Tomsk.tzd data/Tonga.tzd data/Transbaikal.tzd data/Turkey.tzd data/Turks_And_Caicos.tzd data/US_Eastern.tzd data/US_Mountain.tzd data/UTC+12.tzd data/UTC+13.tzd data/UTC-02.tzd data/UTC-08.tzd data/UTC-09.tzd data/UTC-11.tzd data/UTC.tzd data/Ulaanbaatar.tzd data/Venezuela.tzd data/Vladivostok.tzd data/Volgograd.tzd data/W__Australia.tzd data/W__Central_Africa.tzd data/W__Europe.tzd data/W__Mongolia.tzd data/West_Asia.tzd data/West_Bank.tzd data/West_Pacific.tzd data/Yakutsk.tzd data/Yukon.tzd data/_GMT_+01_00_.tzd
header_files = include/gromox/ab_tree.hpp include/gromox/apple_util.hpp include/gromox/applefile.hpp include/gromox/arcfour.hpp include/gromox/atomic.hpp include/gromox/authmgr.hpp include/gromox/binhex.hpp include/gromox/binrdwr.hpp include/gromox/bounce_gen.hpp include/gromox/clock.hpp include/gromox/common_types.hpp include/gromox/config_file.hpp include/gromox/contexts_pool.hpp include/gromox/cookie_parser.hpp include/gromox/cryptoutil.hpp include/gromox/database.h include/gromox/database_mysql.hpp include/gromox/dbop.h include/gromox/dcerpc.hpp include/gromox/defs.h include/gromox/double_list.hpp include/gromox/dsn.hpp include/gromox/eid_array.hpp include/gromox/element_data.hpp include/gromox/endian.hpp include/gromox/exmdb_client.hpp include/gromox/exmdb_common_util.hpp include/gromox/exmdb_ext.hpp include/gromox/exmdb_idef.hpp include/gromox/exmdb_provider_client.hpp include/gromox/exmdb_rpc.hpp include/gromox/exmdb_server.hpp include/gromox/ext_buffer.hpp
header_files += include/gromox/fileio.h include/gromox/flusher_common.h include/gromox/generic_connection.hpp include/gromox/hook_common.h include/gromox/hpm_common.h include/gromox/html.hpp include/gromox/ical.hpp include/gromox/icase.hpp include/gromox/int_hash.hpp include/gromox/json.hpp include/gromox/list_file.hpp include/gromox/lzxpress.hpp include/gromox/macbinary.hpp include/gromox/mail.hpp include/gromox/mail_func.hpp include/gromox/mapi_types.hpp include/gromox/mapidefs.h include/gromox/mapierr.hpp include/gromox/mapitags.hpp include/gromox/mem_file.hpp include/gromox/midb.hpp include/gromox/mime.hpp include/gromox/mime_pool.hpp include/gromox/mjson.hpp include/gromox/msg_unit.hpp include/gromox/msgchg_grouping.hpp include/gromox/mysql_adaptor.hpp include/gromox/ndr.hpp include/gromox/ntlmssp.hpp include/gromox/oxcmail.hpp include/gromox/oxoabkt.hpp
header_files += include/gromox/paths.h.in include/gromox/pcl.hpp include/gromox/plugin.hpp include/gromox/proc_common.h include/gromox/proptag_array.hpp include/gromox/propval.hpp include/gromox/range_set.hpp include/gromox/resource_pool.hpp include/gromox/restriction.hpp include/gromox/rop_util.hpp include/gromox/rpc_types.hpp include/gromox/rtf.hpp include/gromox/rtfcp.hpp include/gromox/rule_actions.hpp include/gromox/safeint.hpp include/gromox/scope.hpp include/gromox/simple_tree.hpp include/gromox/sortorder_set.hpp include/gromox/stream.hpp include/gromox/svc_common.h include/gromox/svc_loader.hpp include/gromox/textmaps.hpp include/gromox/threads_pool.hpp include/gromox/tie.hpp include/gromox/timezone.hpp include/gromox/tnef.hpp include/gromox/util.hpp include/gromox/vcard.hpp include/gromox/xarray2.hpp include/gromox/zcore_client.hpp include/gromox/zcore_rpc.hpp include/gromox/zz_ndr_stack.hpp
dist_pkgdata_DATA = ${abkt_files} ${tzd_files}
toolprogs = tools/defs2php.pl tools/defs2php.sh tools/duplogid tools/enumsort tools/exmidl.pl tools/exmidl.sh tools/includesort tools/proptagsort tools/stackusage tools/warncount tools/zcidl.pl tools/zcidl.sh
EXTRA_DIST = ${header_files} ${toolprogs} default.sym exch/bounce_exch.cpp

include/gromox/paths.h: include/gromox/paths.h.in ${top_builddir}/config.status
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}sed -e 's|#define PKGSYSCONFDIR .*|#define PKGSYSCONFDIR "${sysconfdir}/${PACKAGE_NAME}"|' \
	 -e 's|#define PKGLIBDIR .*|#define PKGLIBDIR "${pkglibdir}"|' \
	 -e 's|#define PKGLIBEXECDIR .*|#define PKGLIBEXECDIR "${pkglibexecdir}"|' \
	 -e 's|#define DATADIR .*|#define DATADIR "${datadir}"|' \
	 -e 's|#define LOCALSTATEDIR .*|#define LOCALSTATEDIR "${localstatedir}"|' \
	 -e 's|#define PKGDATADIR .*|#define PKGDATADIR "${pkgdatadir}"|' \
		<${srcdir}/include/gromox/paths.h.in >"$@.tmp"
	${AM_V_at}if ! cmp "$@" "$@.tmp" 2>/dev/null; then mv "$@.tmp" "$@"; fi; rm -f "$@.tmp"

include/mapierr.cpp: include/gromox/mapierr.hpp tools/defs2php.sh tools/defs2php.pl
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}${srcdir}/tools/defs2php.sh -e <${srcdir}/include/gromox/mapierr.hpp >"$@"

include/mapitags.cpp: include/gromox/mapitags.hpp tools/defs2php.sh tools/defs2php.pl
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}${srcdir}/tools/defs2php.sh -t <${srcdir}/include/gromox/mapitags.hpp >"$@"

php_mapi/zrpc.cpp: include/gromox/zcore_client.hpp tools/zcidl.sh tools/zcidl.pl
	${AM_V_GEN}${MKDIR_P} php_mapi
	${AM_V_at}${srcdir}/tools/zcidl.sh -c <${srcdir}/include/gromox/zcore_client.hpp >"$@"

include/zrpc_dispatch.cpp: include/gromox/zcore_client.hpp tools/zcidl.sh tools/zcidl.pl
	${AM_V_GEN}${MKDIR_P} php_mapi
	${AM_V_at}${srcdir}/tools/zcidl.sh -d <${srcdir}/include/gromox/zcore_client.hpp >"$@"

lib/exmdb_rpc.cpp: include/gromox/exmdb_idef.hpp tools/exmidl.sh tools/exmidl.pl
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}${srcdir}/tools/exmidl.sh -c <${srcdir}/include/gromox/exmdb_idef.hpp >"$@"

include/exmdb_dispatch.cpp: include/gromox/exmdb_idef.hpp tools/exmidl.sh tools/exmidl.pl
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}${srcdir}/tools/exmidl.sh -d <${srcdir}/include/gromox/exmdb_idef.hpp >"$@"

exch/exmdb_provider/exmdb_rpc.cpp: include/gromox/exmdb_idef.hpp tools/exmidl.sh tools/exmidl.pl
	${AM_V_GEN}${MKDIR_P} include/gromox
	${AM_V_at}${srcdir}/tools/exmidl.sh -p <${srcdir}/include/gromox/exmdb_idef.hpp >"$@"

install-exec-hook:
	${MKDIR_P} ${DESTDIR}${sbindir}
	rm -fv ${DESTDIR}${pkglibdir}/libmapi4zf.*

install-data-local:
	${MKDIR_P} ${DESTDIR}${mandir}/man8 ${DESTDIR}${pkgdatadir}/http/php
	cp -av ${srcdir}/data/* ${DESTDIR}${pkgdatadir}/
	cp -av ${srcdir}/exch/php/* ${DESTDIR}${pkgdatadir}/http/php/

uninstall-hook:
	chmod -R u+w ${DESTDIR}${pkgdatadir}/
	rm -Rf ${DESTDIR}${pkgdatadir}/

# On cross-compilation, dldcheck may fail to run, so allow exit code 126 (e.g. Linux) to pass
dldcheck_files = ${lib_LTLIBRARIES} ${mta_plugins} ${mra_plugins} ${exchange_plugins} ${pamlib_LTLIBRARIES}
dldcheck.stamp: dldcheck ${dldcheck_files}
	${AM_V_GEN}LD_LIBRARY_PATH="${abs_builddir}/.libs:$$LD_LIBRARY_PATH" ./dldcheck "$@" ${dldcheck_files}; rv="$$?"; test "$$rv" != 2

%.service: ${top_builddir}/config.status
.tps.service:
	${AM_V_GEN}${MKDIR_P} system; ${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

.PHONY: tarball
tarball:
	tmpdir=$$(mktemp -dtu); \
	mkdir $$tmpdir && \
	pushd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C $$tmpdir -x && popd; \
	pushd $$tmpdir/${PACKAGE_NAME}-${PACKAGE_VERSION} && autoreconf -fi && rm -Rf autom4te*.cache && popd; \
	tar --use=zstd -C $$tmpdir -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.zst --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/; \
	rm -Rf $$tmpdir

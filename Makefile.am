# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I build-aux
AM_CPPFLAGS = -D_GNU_SOURCE -I${top_srcdir}/include -I${top_srcdir}/LIBRARY/common/include -I${top_srcdir}/LIBRARY/epoll_scheduler/include -I${top_srcdir}/LIBRARY/mapi_lib/include -I${top_srcdir}/LIBRARY/webkit_lib/include -I${top_srcdir}/LIBRARY/rpc_lib/include -I${top_srcdir}/LIBRARY/email_lib/include ${HX_CFLAGS} ${gumbo_CFLAGS} ${archive_CFLAGS} ${crypto_CFLAGS} ${ssl_CFLAGS} ${mysql_CFLAGS} ${spf2_CFLAGS} ${sqlite_CFLAGS} ${xls_CFLAGS} ${zlib_CFLAGS}
AM_CFLAGS = -Wall -Wwrite-strings
AM_CXXFLAGS = ${my_CXXFLAGS}

lib_LTLIBRARIES = libgromox_common.la libgromox_epoll.la libgromox_email.la libgromox_mapi.la libgromox_resolv.la libgromox_rpc.la libgromox_webkit.la
noinst_DATA = libgromox_common.ldd libgromox_epoll.ldd libgromox_email.ldd libgromox_webkit.ldd libgromox_rpc.ldd libgromox_mapi.ldd
pkglibexec_PROGRAMS = ${mta_system} ${mra_system} ${exchange_progs} ${agent_service_progs} ${domain_admin_progs} ${system_admin_progs} ${archiver_system_progs}
pkglib_LTLIBRARIES = ${mta_plugins} ${mra_plugins} ${exchange_plugins}
plugin_LDFLAGS = -avoid-version -module
phplibdir = ${PHP_EXTENSION_DIR}
phplib_LTLIBRARIES = mapi.la
unit_services = system/gromox-adaptor.service system/gromox-alock.service system/gromox-amidb.service system/gromox-amysql.service system/gromox-asensor.service system/gromox-asession.service system/gromox-cdnd.service system/gromox-cidb.service system/gromox-da_daemon.service system/gromox-delivery.service system/gromox-event.service system/gromox-fcgi_cgi.service system/gromox-http.service system/gromox-imap.service system/gromox-locker.service system/gromox-midb.service system/gromox-monitor.service system/gromox-pad.service system/gromox-pop3.service system/gromox-rsync.service system/gromox-sadaemon.service system/gromox-scanner.service system/gromox-sensor.service system/gromox-session.service system/gromox-smtp.service system/gromox-supervisor.service system/gromox-synchronizer.service system/gromox-timer.service system/gromox-zcore.service
unit_targets = system/gromox-agent.target system/gromox-archive.target system/gromox-da.target system/gromox-exch.target system/gromox-mra.target system/gromox-mta.target system/gromox-sa.target
unit_DATA = ${unit_services} ${unit_targets}

mta_system = delivery smtp herculiz
mta_plugins = \
	libmtapas_address_checker.la \
	libmtapas_anti_enum.la \
	libmtapas_attach_filter.la \
	libmtapas_attach_wildcard.la \
	libmtapas_auth_whitelist.la \
	libmtapas_base64_encoding.la \
	libmtapas_boundary_filter.la \
	libmtapas_content_filter.la \
	libmtapas_ddns_filter.la \
	libmtapas_dns_rbl.la \
	libmtapas_domain_filter.la \
	libmtapas_domain_keyword.la \
	libmtapas_domain_limit.la \
	libmtapas_from_auditor.la \
	libmtapas_from_filter.la \
	libmtapas_from_validator.la \
	libmtapas_header_filter.la \
	libmtapas_headerfrom_filter.la \
	libmtapas_hello_filter.la \
	libmtapas_inbound_auth.la \
	libmtapas_inmail_frequency.la \
	libmtapas_keyword_filter.la \
	libmtapas_multipart_check.la \
	libmtapas_outmail_frequency.la \
	libmtapas_precise_interception.la \
	libmtapas_property_001.la \
	libmtapas_property_002.la \
	libmtapas_property_003.la \
	libmtapas_property_004.la \
	libmtapas_property_005.la \
	libmtapas_property_006.la \
	libmtapas_property_007.la \
	libmtapas_property_008.la \
	libmtapas_property_009.la \
	libmtapas_property_010.la \
	libmtapas_property_011.la \
	libmtapas_property_012.la \
	libmtapas_property_013.la \
	libmtapas_property_014.la \
	libmtapas_property_015.la \
	libmtapas_property_016.la \
	libmtapas_property_017.la \
	libmtapas_property_018.la \
	libmtapas_property_019.la \
	libmtapas_property_020.la \
	libmtapas_property_021.la \
	libmtapas_property_022.la \
	libmtapas_property_023.la \
	libmtapas_property_024.la \
	libmtapas_property_025.la \
	libmtapas_property_026.la \
	libmtapas_property_027.la \
	libmtapas_property_028.la \
	libmtapas_property_029.la \
	libmtapas_property_030.la \
	libmtapas_property_031.la \
	libmtapas_property_032.la \
	libmtapas_property_033.la \
	libmtapas_property_034.la \
	libmtapas_property_035.la \
	libmtapas_property_036.la \
	libmtapas_property_037.la \
	libmtapas_property_038.la \
	libmtapas_property_039.la \
	libmtapas_property_040.la \
	libmtapas_property_041.la \
	libmtapas_property_042.la \
	libmtapas_property_043.la \
	libmtapas_property_044.la \
	libmtapas_property_045.la \
	libmtapas_property_046.la \
	libmtapas_property_047.la \
	libmtapas_property_048.la \
	libmtapas_property_049.la \
	libmtapas_property_050.la \
	libmtapas_property_051.la \
	libmtapas_property_052.la \
	libmtapas_property_053.la \
	libmtapas_property_054.la \
	libmtapas_property_055.la \
	libmtapas_property_056.la \
	libmtapas_property_057.la \
	libmtapas_property_058.la \
	libmtapas_property_059.la \
	libmtapas_rbl_check.la \
	libmtapas_rcpt_filter.la \
	libmtapas_rcpt_limit.la \
	libmtapas_sample.la \
	libmtapas_scamming_filter.la \
	libmtapas_site_protection.la \
	libmtapas_special_protection.la \
	libmtapas_spf_filter.la \
	libmtapas_subject_auditor.la \
	libmtapas_subject_dots.la \
	libmtapas_trojan_detector.la \
	libmtapas_xmailer_filter.la \
	libmtaflh_message_enqueue.la \
	libmtaflh_sample.la \
	libmtahook_alias_translator.la \
	libmtahook_anonymous_keyword.la \
	libmtahook_antivirus_processor.la \
	libmtahook_archive_agent.la \
	libmtahook_cdner_caching.la \
	libmtahook_domain_keyword.la \
	libmtahook_domain_mailbox.la \
	libmtahook_domain_monitor.la \
	libmtahook_domain_sign.la \
	libmtahook_domain_subsystem.la \
	libmtahook_exmdb_local.la \
	libmtahook_from_replace.la \
	libmtahook_gateway_dispatch.la \
	libmtahook_group_monitor.la \
	libmtahook_mail_approving.la \
	libmtahook_mail_forwarder.la \
	libmtahook_mailbox_collector.la \
	libmtahook_message_insulation.la \
	libmtahook_mlist_expand.la \
	libmtahook_os_inspection.la \
	libmtahook_redirect_agent.la \
	libmtahook_relay_agent.la \
	libmtahook_remote_postman.la \
	libmtahook_report_forms.la \
	libmtahook_sample.la \
	libmtahook_self_monitor.la \
	libmtahook_spam_complain.la \
	libmtahook_spam_tagging.la \
	libmtahook_status_forms.la \
	libmtahook_system_sign.la \
	libmtahook_system_updater.la \
	libmtahook_user_forwarder.la \
	libmtasvc_backup_list.la \
	libmtasvc_boundary_list.la \
	libmtasvc_delivery_console_control.la \
	libmtasvc_dns_adaptor.la \
	libmtasvc_domain_list.la \
	libmtasvc_domain_whitelist.la \
	libmtasvc_esmtp_auth.la \
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
	libmtasvc_monitor_domains.la \
	libmtasvc_ms_locale.la \
	libmtasvc_multiple_retrying.la \
	libmtasvc_mysql_adaptor.la \
	libmtasvc_outmail_frequency_audit.la \
	libmtasvc_outmail_limitation_audit.la \
	libmtasvc_protection_ip_audit.la \
	libmtasvc_relay_domains.la \
	libmtasvc_relay_list.la \
	libmtasvc_remote_delivery_audit.la \
	libmtasvc_remote_delivery_forbidden.la \
	libmtasvc_remote_mx_hello.la \
	libmtasvc_retrying_table.la \
	libmtasvc_sample.la \
	libmtasvc_service_auth.la \
	libmtasvc_single_rcpt.la \
	libmtasvc_smtp_console_control.la \
	libmtasvc_spam_statistic.la \
	libmtasvc_special_protection_audit.la \
	libmtasvc_sssp_agent.la \
	libmtasvc_tagging_table.la \
	libmtasvc_user_filter.la
noinst_DATA += \
	libmtapas_address_checker.ldd \
	libmtapas_anti_enum.ldd \
	libmtapas_attach_filter.ldd \
	libmtapas_attach_wildcard.ldd \
	libmtapas_auth_whitelist.ldd \
	libmtapas_base64_encoding.ldd \
	libmtapas_boundary_filter.ldd \
	libmtapas_content_filter.ldd \
	libmtapas_ddns_filter.ldd \
	libmtapas_dns_rbl.ldd \
	libmtapas_domain_filter.ldd \
	libmtapas_domain_keyword.ldd \
	libmtapas_domain_limit.ldd \
	libmtapas_from_auditor.ldd \
	libmtapas_from_filter.ldd \
	libmtapas_from_validator.ldd \
	libmtapas_header_filter.ldd \
	libmtapas_headerfrom_filter.ldd \
	libmtapas_hello_filter.ldd \
	libmtapas_inbound_auth.ldd \
	libmtapas_inmail_frequency.ldd \
	libmtapas_keyword_filter.ldd \
	libmtapas_multipart_check.ldd \
	libmtapas_outmail_frequency.ldd \
	libmtapas_precise_interception.ldd \
	libmtapas_property_001.ldd \
	libmtapas_property_002.ldd \
	libmtapas_property_003.ldd \
	libmtapas_property_004.ldd \
	libmtapas_property_005.ldd \
	libmtapas_property_006.ldd \
	libmtapas_property_007.ldd \
	libmtapas_property_008.ldd \
	libmtapas_property_009.ldd \
	libmtapas_property_010.ldd \
	libmtapas_property_011.ldd \
	libmtapas_property_012.ldd \
	libmtapas_property_013.ldd \
	libmtapas_property_014.ldd \
	libmtapas_property_015.ldd \
	libmtapas_property_016.ldd \
	libmtapas_property_017.ldd \
	libmtapas_property_018.ldd \
	libmtapas_property_019.ldd \
	libmtapas_property_020.ldd \
	libmtapas_property_021.ldd \
	libmtapas_property_022.ldd \
	libmtapas_property_023.ldd \
	libmtapas_property_024.ldd \
	libmtapas_property_025.ldd \
	libmtapas_property_026.ldd \
	libmtapas_property_027.ldd \
	libmtapas_property_028.ldd \
	libmtapas_property_029.ldd \
	libmtapas_property_030.ldd \
	libmtapas_property_031.ldd \
	libmtapas_property_032.ldd \
	libmtapas_property_033.ldd \
	libmtapas_property_034.ldd \
	libmtapas_property_035.ldd \
	libmtapas_property_036.ldd \
	libmtapas_property_037.ldd \
	libmtapas_property_038.ldd \
	libmtapas_property_039.ldd \
	libmtapas_property_040.ldd \
	libmtapas_property_041.ldd \
	libmtapas_property_042.ldd \
	libmtapas_property_043.ldd \
	libmtapas_property_044.ldd \
	libmtapas_property_045.ldd \
	libmtapas_property_046.ldd \
	libmtapas_property_047.ldd \
	libmtapas_property_048.ldd \
	libmtapas_property_049.ldd \
	libmtapas_property_050.ldd \
	libmtapas_property_051.ldd \
	libmtapas_property_052.ldd \
	libmtapas_property_053.ldd \
	libmtapas_property_054.ldd \
	libmtapas_property_055.ldd \
	libmtapas_property_056.ldd \
	libmtapas_property_057.ldd \
	libmtapas_property_058.ldd \
	libmtapas_property_059.ldd \
	libmtapas_rbl_check.ldd \
	libmtapas_rcpt_filter.ldd \
	libmtapas_rcpt_limit.ldd \
	libmtapas_sample.ldd \
	libmtapas_scamming_filter.ldd \
	libmtapas_site_protection.ldd \
	libmtapas_special_protection.ldd \
	libmtapas_spf_filter.ldd \
	libmtapas_subject_auditor.ldd \
	libmtapas_subject_dots.ldd \
	libmtapas_trojan_detector.ldd \
	libmtapas_xmailer_filter.ldd \
	libmtaflh_message_enqueue.ldd \
	libmtaflh_sample.ldd \
	libmtahook_alias_translator.ldd \
	libmtahook_anonymous_keyword.ldd \
	libmtahook_antivirus_processor.ldd \
	libmtahook_archive_agent.ldd \
	libmtahook_cdner_caching.ldd \
	libmtahook_domain_keyword.ldd \
	libmtahook_domain_mailbox.ldd \
	libmtahook_domain_monitor.ldd \
	libmtahook_domain_sign.ldd \
	libmtahook_domain_subsystem.ldd \
	libmtahook_exmdb_local.ldd \
	libmtahook_from_replace.ldd \
	libmtahook_gateway_dispatch.ldd \
	libmtahook_group_monitor.ldd \
	libmtahook_mail_approving.ldd \
	libmtahook_mail_forwarder.ldd \
	libmtahook_mailbox_collector.ldd \
	libmtahook_message_insulation.ldd \
	libmtahook_mlist_expand.ldd \
	libmtahook_os_inspection.ldd \
	libmtahook_redirect_agent.ldd \
	libmtahook_relay_agent.ldd \
	libmtahook_remote_postman.ldd \
	libmtahook_report_forms.ldd \
	libmtahook_sample.ldd \
	libmtahook_self_monitor.ldd \
	libmtahook_spam_complain.ldd \
	libmtahook_spam_tagging.ldd \
	libmtahook_status_forms.ldd \
	libmtahook_system_sign.ldd \
	libmtahook_system_updater.ldd \
	libmtahook_user_forwarder.ldd \
	libmtasvc_backup_list.ldd \
	libmtasvc_boundary_list.ldd \
	libmtasvc_delivery_console_control.ldd \
	libmtasvc_dns_adaptor.la \
	libmtasvc_domain_list.ldd \
	libmtasvc_domain_whitelist.ldd \
	libmtasvc_esmtp_auth.la \
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
	libmtasvc_monitor_domains.ldd \
	libmtasvc_ms_locale.la \
	libmtasvc_multiple_retrying.la \
	libmtasvc_mysql_adaptor.la \
	libmtasvc_outmail_frequency_audit.ldd \
	libmtasvc_outmail_limitation_audit.ldd \
	libmtasvc_protection_ip_audit.ldd \
	libmtasvc_relay_domains.ldd \
	libmtasvc_relay_list.ldd \
	libmtasvc_remote_delivery_audit.ldd \
	libmtasvc_remote_delivery_forbidden.ldd \
	libmtasvc_remote_mx_hello.ldd \
	libmtasvc_retrying_table.la \
	libmtasvc_sample.la \
	libmtasvc_service_auth.la \
	libmtasvc_single_rcpt.ldd \
	libmtasvc_smtp_console_control.ldd \
	libmtasvc_spam_statistic.la \
	libmtasvc_special_protection_audit.ldd \
	libmtasvc_sssp_agent.la \
	libmtasvc_tagging_table.ldd \
	libmtasvc_user_filter.ldd
mra_system = apollo pop3 imap
mra_plugins = \
	libmrasvc_cdner_agent.la \
	libmrasvc_event_proxy.la \
	libmrasvc_event_stub.la \
	libmrasvc_ip_container.la \
	libmrasvc_ip_filter.la \
	libmrasvc_log_plugin.la \
	libmrasvc_midb_agent.la \
	libmrasvc_mysql_adaptor.la \
	libmrasvc_sample.la \
	libmrasvc_user_filter.la
noinst_DATA += \
	libmrasvc_cdner_agent.ldd \
	libmrasvc_event_proxy.ldd \
	libmrasvc_event_stub.ldd \
	libmrasvc_ip_container.ldd \
	libmrasvc_ip_filter.ldd \
	libmrasvc_log_plugin.ldd \
	libmrasvc_midb_agent.ldd \
	libmrasvc_mysql_adaptor.ldd \
	libmrasvc_sample.ldd \
	libmrasvc_user_filter.ldd
exchange_progs = http medusa midb zcore
exchange_plugins = \
	libexsvc_codepage_lang.la \
	libexsvc_event_proxy.la \
	libexsvc_exmdb_provider.la \
	libexsvc_ip_container.la \
	libexsvc_ip_filter.la \
	libexsvc_lang_charset.la \
	libexsvc_log_plugin.la \
	libexsvc_mime_extension.la \
	libexsvc_ms_locale.la \
	libexsvc_mysql_adaptor.la \
	libexsvc_sample.la \
	libexsvc_user_filter.la \
	libexsvc_timer_agent.la \
	libexproc_exchange_emsmdb.la \
	libexproc_exchange_nsp.la \
	libexproc_exchange_rfr.la \
	libexproc_sample.la \
	libexhpm_proxy.la \
	libexhpm_sample.la
noinst_DATA += \
	libexsvc_codepage_lang.ldd \
	libexsvc_event_proxy.ldd \
	libexsvc_exmdb_provider.ldd \
	libexsvc_ip_container.ldd \
	libexsvc_ip_filter.ldd \
	libexsvc_lang_charset.ldd \
	libexsvc_log_plugin.ldd \
	libexsvc_mime_extension.ldd \
	libexsvc_ms_locale.ldd \
	libexsvc_mysql_adaptor.ldd \
	libexsvc_sample.ldd \
	libexsvc_user_filter.ldd \
	libexsvc_timer_agent.ldd \
	libexproc_exchange_emsmdb.ldd \
	libexproc_exchange_nsp.ldd \
	libexproc_exchange_rfr.ldd \
	libexproc_sample.ldd \
	libexhpm_proxy.ldd \
	libexhpm_sample.ldd
agent_service_progs = alock amidb amysql asensor asession digest freebusy pandora rtf2html
domain_admin_progs = da_daemon domain_approve domain_archive domain_binput domain_classes domain_folders domain_groups domain_info domain_keyword domain_limit domain_log domain_main domain_mlists domain_monitor domain_setup domain_sign domain_statistic domain_users fcgi_cgi group_archive group_binput group_classes group_clists group_info group_log group_main group_monitor group_users posidon synchronizer
system_admin_progs = adaptor admin_archive admin_insulation admin_log admin_main archiver_list area_list areadb athena bl_delete boundary_blacklist cdnd sa_daemon daily_statistic daily_status dispasswd dns_table domain_blacklist domain_list domain_mailbox domain_whitelist dynamic_dnslist enpasswd event forward_table from_blacklist from_replace ip_blacklist ip_whitelist ipdomain_table keyword_group keyword_statistic keyword_upload locker mensual_statistic message_sign mkmidb mkprivate mkpublic monitor org_list pad pop_porting rcpt_blacklist rebuild relay_allow relay_domains relay_table rsyncd rsyncer scanner sendmail sensor session single_rcpt status_rpc supervising_list supervising_statistic supervisor synchronization_rpc system_backup system_info system_password system_setup system_users tagging_whitelist timer userinfo xmailer_blacklist
archiver_system_progs = archive cidb migrator titan

# LIBRARY
libgromox_common_la_SOURCES = LIBRARY/common/alloc_context.c LIBRARY/common/array.c LIBRARY/common/config_file.c LIBRARY/common/dir_tree.c LIBRARY/common/double_list.c LIBRARY/common/fifo.c LIBRARY/common/files_allocator.c LIBRARY/common/guid.c LIBRARY/common/int_hash.c LIBRARY/common/ip4_hash.c LIBRARY/common/lib_buffer.c LIBRARY/common/list_file.c LIBRARY/common/long_hash.c LIBRARY/common/mail_func.c LIBRARY/common/mem_file.c LIBRARY/common/simple_tree.c LIBRARY/common/single_list.c LIBRARY/common/stream.c LIBRARY/common/str_hash.c LIBRARY/common/timezone.c LIBRARY/common/util.c LIBRARY/common/vstack.c LIBRARY/common/xarray.c lib/fileio.cpp
libgromox_common_la_LIBADD = -lcrypt ${HX_LIBS}
libgromox_email_la_SOURCES = LIBRARY/email_lib/mime.c LIBRARY/email_lib/mime_pool.c LIBRARY/email_lib/mjson.c LIBRARY/email_lib/vcard.c LIBRARY/email_lib/mail.c LIBRARY/email_lib/ical.c LIBRARY/email_lib/dsn.c
libgromox_email_la_LIBADD = ${HX_LIBS} ${ssl_LIBS} libgromox_common.la
libgromox_epoll_la_SOURCES = LIBRARY/epoll_scheduler/contexts_pool.c LIBRARY/epoll_scheduler/threads_pool.c
libgromox_epoll_la_LIBADD = -lpthread -lrt libgromox_common.la
libgromox_mapi_la_SOURCES = LIBRARY/mapi_lib/tpropval_array.c LIBRARY/mapi_lib/tnef.c LIBRARY/mapi_lib/tarray_set.c LIBRARY/mapi_lib/sortorder_set.c LIBRARY/mapi_lib/rule_actions.c LIBRARY/mapi_lib/rtfcp.c LIBRARY/mapi_lib/rtf.c LIBRARY/mapi_lib/rop_util.c LIBRARY/mapi_lib/restriction.c LIBRARY/mapi_lib/propval.c LIBRARY/mapi_lib/proptag_array.c LIBRARY/mapi_lib/pcl.c LIBRARY/mapi_lib/oxvcard.c LIBRARY/mapi_lib/oxcmail.c LIBRARY/mapi_lib/oxcical.c LIBRARY/mapi_lib/macbinary.c LIBRARY/mapi_lib/lzxpress.c LIBRARY/mapi_lib/idset.c LIBRARY/mapi_lib/html.c LIBRARY/mapi_lib/ext_buffer.c LIBRARY/mapi_lib/element_data.c LIBRARY/mapi_lib/eid_array.c LIBRARY/mapi_lib/binhex.c LIBRARY/mapi_lib/applefile.c LIBRARY/mapi_lib/apple_util.c
libgromox_mapi_la_LIBADD = ${gumbo_LIBS} ${HX_LIBS} libgromox_common.la libgromox_email.la
libgromox_resolv_la_SOURCES = lib/getmxbyname.c
libgromox_resolv_la_LIBADD = -lresolv ${HX_LIBS}
libgromox_rpc_la_SOURCES = LIBRARY/rpc_lib/ntlmssp.c LIBRARY/rpc_lib/ntlmdes.c LIBRARY/rpc_lib/ndr.c LIBRARY/rpc_lib/hmacmd5.c LIBRARY/rpc_lib/crc32.c LIBRARY/rpc_lib/arcfour.c
libgromox_rpc_la_LIBADD = ${crypto_LIBS} ${HX_LIBS} libgromox_common.la
libgromox_webkit_la_SOURCES = LIBRARY/webkit_lib/request_parser.c LIBRARY/webkit_lib/lang_resource.c LIBRARY/webkit_lib/idx_array.c LIBRARY/webkit_lib/cookie_parser.c LIBRARY/webkit_lib/assoc_array.c
libgromox_webkit_la_LIBADD = ${HX_LIBS} libgromox_common.la

# MTA_SYSTEM
herculiz_SOURCES = MTA_SYSTEM/herculiz.c
herculiz_LDADD = ${HX_LIBS}
delivery_SOURCES = MRA_SYSTEM/imap/service.c MTA_SYSTEM/delivery_app/console_server.c MTA_SYSTEM/delivery_app/console_cmd_handler.c MTA_SYSTEM/delivery_app/main.c MTA_SYSTEM/delivery_app/message_dequeue.c MTA_SYSTEM/delivery_app/resource.c MTA_SYSTEM/delivery_app/system_services.c MTA_SYSTEM/delivery_app/transporter.c
delivery_LDADD = -ldl -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
smtp_SOURCES = MRA_SYSTEM/imap/service.c MTA_SYSTEM/smtp/anti_spamming.c MTA_SYSTEM/smtp/blocks_allocator.c MTA_SYSTEM/smtp/bndstack_allocator.c MTA_SYSTEM/smtp/console_server.c MTA_SYSTEM/smtp/console_cmd_handler.c MTA_SYSTEM/smtp/flusher.c MTA_SYSTEM/smtp/listener.c MTA_SYSTEM/smtp/main.c MTA_SYSTEM/smtp/resource.c MTA_SYSTEM/smtp/smtp_parser.c MTA_SYSTEM/smtp/smtp_cmd_handler.c MTA_SYSTEM/smtp/system_services.c
smtp_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
libmtapas_address_checker_la_SOURCES = MTA_SYSTEM/as_plugins/address_checker.c
libmtapas_address_checker_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_address_checker_la_LIBADD = libgromox_common.la
libmtapas_anti_enum_la_SOURCES = MTA_SYSTEM/as_plugins/anti_enum.c
libmtapas_anti_enum_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_anti_enum_la_LIBADD = libgromox_common.la
libmtapas_attach_filter_la_SOURCES = MTA_SYSTEM/as_plugins/attach_filter.c
libmtapas_attach_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_attach_filter_la_LIBADD = ${archive_LIBS} ${HX_LIBS} libgromox_common.la
libmtapas_attach_wildcard_la_SOURCES = MTA_SYSTEM/as_plugins/attach_wildcard.c
libmtapas_attach_wildcard_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_attach_wildcard_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtapas_auth_whitelist_la_SOURCES = MTA_SYSTEM/as_plugins/auth_whitelist.c
libmtapas_auth_whitelist_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_auth_whitelist_la_LIBADD = libgromox_common.la
libmtapas_base64_encoding_la_SOURCES = MTA_SYSTEM/as_plugins/base64_encoding.c
libmtapas_base64_encoding_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_base64_encoding_la_LIBADD = libgromox_common.la
libmtapas_boundary_filter_la_SOURCES = MTA_SYSTEM/as_plugins/boundary_filter.c
libmtapas_boundary_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_boundary_filter_la_LIBADD = libgromox_common.la
libmtapas_content_filter_la_SOURCES = MTA_SYSTEM/as_plugins/content_filter/main.c MTA_SYSTEM/as_plugins/content_filter/uri_cache.c MTA_SYSTEM/as_plugins/content_filter/uri_rbl.c
libmtapas_content_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_content_filter_la_LIBADD = -lpthread -lresolv ${HX_LIBS} libgromox_common.la
libmtapas_ddns_filter_la_SOURCES = MTA_SYSTEM/as_plugins/ddns_filter.c
libmtapas_ddns_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_ddns_filter_la_LIBADD = -lpthread -lresolv libgromox_common.la
libmtapas_dns_rbl_la_SOURCES = MTA_SYSTEM/as_plugins/dns_rbl/dns_rbl.c MTA_SYSTEM/as_plugins/dns_rbl/main.c MTA_SYSTEM/as_plugins/dns_rbl/rbl_cache.c
libmtapas_dns_rbl_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_dns_rbl_la_LIBADD = -lpthread -lresolv libgromox_common.la
libmtapas_domain_filter_la_SOURCES = MTA_SYSTEM/as_plugins/domain_filter.c
libmtapas_domain_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_domain_filter_la_LIBADD = libgromox_common.la
libmtapas_domain_keyword_la_SOURCES = MTA_SYSTEM/as_plugins/domain_keyword/domain_keyword.c MTA_SYSTEM/as_plugins/domain_keyword/keyword_engine.c MTA_SYSTEM/as_plugins/domain_keyword/main.c
libmtapas_domain_keyword_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_domain_keyword_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtapas_domain_limit_la_SOURCES = MTA_SYSTEM/as_plugins/domain_limit/domain_limit.c MTA_SYSTEM/as_plugins/domain_limit/main.c
libmtapas_domain_limit_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_domain_limit_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtapas_from_auditor_la_SOURCES = MTA_SYSTEM/as_plugins/from_auditor.c
libmtapas_from_auditor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_from_auditor_la_LIBADD = libgromox_common.la
libmtapas_from_filter_la_SOURCES = MTA_SYSTEM/as_plugins/from_filter.c
libmtapas_from_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_from_filter_la_LIBADD = libgromox_common.la
libmtapas_from_validator_la_SOURCES = MTA_SYSTEM/as_plugins/from_validator.c
libmtapas_from_validator_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_from_validator_la_LIBADD = libgromox_common.la
libmtapas_header_filter_la_SOURCES = MTA_SYSTEM/as_plugins/header_filter.c
libmtapas_header_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_header_filter_la_LIBADD = libgromox_common.la
libmtapas_headerfrom_filter_la_SOURCES = MTA_SYSTEM/as_plugins/headerfrom_filter.c
libmtapas_headerfrom_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_headerfrom_filter_la_LIBADD = libgromox_common.la
libmtapas_hello_filter_la_SOURCES = MTA_SYSTEM/as_plugins/hello_filter.c
libmtapas_hello_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_hello_filter_la_LIBADD = libgromox_common.la
libmtapas_inbound_auth_la_SOURCES = MTA_SYSTEM/as_plugins/inbound_auth.c
libmtapas_inbound_auth_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_inbound_auth_la_LIBADD = libgromox_common.la
libmtapas_inmail_frequency_la_SOURCES = MTA_SYSTEM/as_plugins/inmail_frequency.c
libmtapas_inmail_frequency_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_inmail_frequency_la_LIBADD = libgromox_common.la
libmtapas_keyword_filter_la_SOURCES = MTA_SYSTEM/as_plugins/domain_keyword/keyword_engine.c MTA_SYSTEM/as_plugins/keyword_filter/main.c
libmtapas_keyword_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_keyword_filter_la_LIBADD = -lpthread libgromox_common.la
libmtapas_multipart_check_la_SOURCES = MTA_SYSTEM/as_plugins/multipart_check.c
libmtapas_multipart_check_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_multipart_check_la_LIBADD = libgromox_common.la
libmtapas_outmail_frequency_la_SOURCES = MTA_SYSTEM/as_plugins/outmail_frequency.c
libmtapas_outmail_frequency_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_outmail_frequency_la_LIBADD = libgromox_common.la
libmtapas_precise_interception_la_SOURCES = MTA_SYSTEM/as_plugins/precise_interception/main.c MTA_SYSTEM/as_plugins/precise_interception/precise_interception.c
libmtapas_precise_interception_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_precise_interception_la_LIBADD = -lpthread libgromox_common.la
libmtapas_property_001_la_SOURCES = MTA_SYSTEM/as_plugins/property_001.c
libmtapas_property_001_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_001_la_LIBADD = libgromox_common.la
libmtapas_property_002_la_SOURCES = MTA_SYSTEM/as_plugins/property_002.c
libmtapas_property_002_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_002_la_LIBADD = libgromox_common.la
libmtapas_property_003_la_SOURCES = MTA_SYSTEM/as_plugins/property_003.c
libmtapas_property_003_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_003_la_LIBADD = libgromox_common.la
libmtapas_property_004_la_SOURCES = MTA_SYSTEM/as_plugins/property_004.c
libmtapas_property_004_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_004_la_LIBADD = libgromox_common.la
libmtapas_property_005_la_SOURCES = MTA_SYSTEM/as_plugins/property_005.c
libmtapas_property_005_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_005_la_LIBADD = libgromox_common.la
libmtapas_property_006_la_SOURCES = MTA_SYSTEM/as_plugins/property_006.c
libmtapas_property_006_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_006_la_LIBADD = libgromox_common.la
libmtapas_property_007_la_SOURCES = MTA_SYSTEM/as_plugins/property_007.c
libmtapas_property_007_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_007_la_LIBADD = libgromox_common.la
libmtapas_property_008_la_SOURCES = MTA_SYSTEM/as_plugins/property_008.c
libmtapas_property_008_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_008_la_LIBADD = libgromox_common.la
libmtapas_property_009_la_SOURCES = MTA_SYSTEM/as_plugins/property_009.c
libmtapas_property_009_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_009_la_LIBADD = libgromox_common.la
libmtapas_property_010_la_SOURCES = MTA_SYSTEM/as_plugins/property_010.c
libmtapas_property_010_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_010_la_LIBADD = libgromox_common.la
libmtapas_property_011_la_SOURCES = MTA_SYSTEM/as_plugins/property_011.c
libmtapas_property_011_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_011_la_LIBADD = libgromox_common.la
libmtapas_property_012_la_SOURCES = MTA_SYSTEM/as_plugins/property_012.c
libmtapas_property_012_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_012_la_LIBADD = libgromox_common.la
libmtapas_property_013_la_SOURCES = MTA_SYSTEM/as_plugins/property_013.c
libmtapas_property_013_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_013_la_LIBADD = libgromox_common.la
libmtapas_property_014_la_SOURCES = MTA_SYSTEM/as_plugins/property_014.c
libmtapas_property_014_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_014_la_LIBADD = libgromox_common.la
libmtapas_property_015_la_SOURCES = MTA_SYSTEM/as_plugins/property_015.c
libmtapas_property_015_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_015_la_LIBADD = libgromox_common.la
libmtapas_property_016_la_SOURCES = MTA_SYSTEM/as_plugins/property_016.c
libmtapas_property_016_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_016_la_LIBADD = libgromox_common.la
libmtapas_property_017_la_SOURCES = MTA_SYSTEM/as_plugins/property_017.c
libmtapas_property_017_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_017_la_LIBADD = libgromox_common.la
libmtapas_property_018_la_SOURCES = MTA_SYSTEM/as_plugins/property_018.c
libmtapas_property_018_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_018_la_LIBADD = libgromox_common.la
libmtapas_property_019_la_SOURCES = MTA_SYSTEM/as_plugins/property_019.c
libmtapas_property_019_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_019_la_LIBADD = libgromox_common.la
libmtapas_property_020_la_SOURCES = MTA_SYSTEM/as_plugins/property_020.c
libmtapas_property_020_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_020_la_LIBADD = libgromox_common.la
libmtapas_property_021_la_SOURCES = MTA_SYSTEM/as_plugins/property_021.c
libmtapas_property_021_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_021_la_LIBADD = libgromox_common.la
libmtapas_property_022_la_SOURCES = MTA_SYSTEM/as_plugins/property_022.c
libmtapas_property_022_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_022_la_LIBADD = libgromox_common.la
libmtapas_property_023_la_SOURCES = MTA_SYSTEM/as_plugins/property_023.c
libmtapas_property_023_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_023_la_LIBADD = libgromox_common.la
libmtapas_property_024_la_SOURCES = MTA_SYSTEM/as_plugins/property_024.c
libmtapas_property_024_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_024_la_LIBADD = libgromox_common.la
libmtapas_property_025_la_SOURCES = MTA_SYSTEM/as_plugins/property_025.c
libmtapas_property_025_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_025_la_LIBADD = libgromox_common.la
libmtapas_property_026_la_SOURCES = MTA_SYSTEM/as_plugins/property_026.c
libmtapas_property_026_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_026_la_LIBADD = libgromox_common.la
libmtapas_property_027_la_SOURCES = MTA_SYSTEM/as_plugins/property_027.c
libmtapas_property_027_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_027_la_LIBADD = libgromox_common.la
libmtapas_property_028_la_SOURCES = MTA_SYSTEM/as_plugins/property_028.c
libmtapas_property_028_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_028_la_LIBADD = libgromox_common.la
libmtapas_property_029_la_SOURCES = MTA_SYSTEM/as_plugins/property_029.c
libmtapas_property_029_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_029_la_LIBADD = libgromox_common.la
libmtapas_property_030_la_SOURCES = MTA_SYSTEM/as_plugins/property_030.c
libmtapas_property_030_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_030_la_LIBADD = libgromox_common.la
libmtapas_property_031_la_SOURCES = MTA_SYSTEM/as_plugins/property_031.c
libmtapas_property_031_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_031_la_LIBADD = libgromox_common.la
libmtapas_property_032_la_SOURCES = MTA_SYSTEM/as_plugins/property_032.c
libmtapas_property_032_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_032_la_LIBADD = libgromox_common.la
libmtapas_property_033_la_SOURCES = MTA_SYSTEM/as_plugins/property_033.c
libmtapas_property_033_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_033_la_LIBADD = libgromox_common.la
libmtapas_property_034_la_SOURCES = MTA_SYSTEM/as_plugins/property_034.c
libmtapas_property_034_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_034_la_LIBADD = libgromox_common.la
libmtapas_property_035_la_SOURCES = MTA_SYSTEM/as_plugins/property_035.c
libmtapas_property_035_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_035_la_LIBADD = libgromox_common.la
libmtapas_property_036_la_SOURCES = MTA_SYSTEM/as_plugins/property_036.c
libmtapas_property_036_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_036_la_LIBADD = libgromox_common.la
libmtapas_property_037_la_SOURCES = MTA_SYSTEM/as_plugins/property_037.c
libmtapas_property_037_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_037_la_LIBADD = libgromox_common.la
libmtapas_property_038_la_SOURCES = MTA_SYSTEM/as_plugins/property_038.c
libmtapas_property_038_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_038_la_LIBADD = libgromox_common.la
libmtapas_property_039_la_SOURCES = MTA_SYSTEM/as_plugins/property_039.c
libmtapas_property_039_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_039_la_LIBADD = libgromox_common.la
libmtapas_property_040_la_SOURCES = MTA_SYSTEM/as_plugins/property_040.c
libmtapas_property_040_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_040_la_LIBADD = libgromox_common.la
libmtapas_property_041_la_SOURCES = MTA_SYSTEM/as_plugins/property_041.c
libmtapas_property_041_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_041_la_LIBADD = libgromox_common.la
libmtapas_property_042_la_SOURCES = MTA_SYSTEM/as_plugins/property_042.c
libmtapas_property_042_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_042_la_LIBADD = libgromox_common.la
libmtapas_property_043_la_SOURCES = MTA_SYSTEM/as_plugins/property_043.c
libmtapas_property_043_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_043_la_LIBADD = libgromox_common.la
libmtapas_property_044_la_SOURCES = MTA_SYSTEM/as_plugins/property_044.c
libmtapas_property_044_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_044_la_LIBADD = libgromox_common.la
libmtapas_property_045_la_SOURCES = MTA_SYSTEM/as_plugins/property_045.c
libmtapas_property_045_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_045_la_LIBADD = ${HX_LIBS} libgromox_common.la
libmtapas_property_046_la_SOURCES = MTA_SYSTEM/as_plugins/property_046.c
libmtapas_property_046_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_046_la_LIBADD = libgromox_common.la
libmtapas_property_047_la_SOURCES = MTA_SYSTEM/as_plugins/property_047.c
libmtapas_property_047_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_047_la_LIBADD = libgromox_common.la
libmtapas_property_048_la_SOURCES = MTA_SYSTEM/as_plugins/property_048.c
libmtapas_property_048_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_048_la_LIBADD = libgromox_common.la
libmtapas_property_049_la_SOURCES = MTA_SYSTEM/as_plugins/property_049.c
libmtapas_property_049_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_049_la_LIBADD = ${HX_LIBS} libgromox_common.la
libmtapas_property_050_la_SOURCES = MTA_SYSTEM/as_plugins/property_050.c
libmtapas_property_050_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_050_la_LIBADD = libgromox_common.la
libmtapas_property_051_la_SOURCES = MTA_SYSTEM/as_plugins/property_051.c
libmtapas_property_051_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_051_la_LIBADD = libgromox_common.la
libmtapas_property_052_la_SOURCES = MTA_SYSTEM/as_plugins/property_052.c
libmtapas_property_052_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_052_la_LIBADD = libgromox_common.la
libmtapas_property_053_la_SOURCES = MTA_SYSTEM/as_plugins/property_053.c
libmtapas_property_053_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_053_la_LIBADD = libgromox_common.la
libmtapas_property_054_la_SOURCES = MTA_SYSTEM/as_plugins/property_054.c
libmtapas_property_054_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_054_la_LIBADD = libgromox_common.la
libmtapas_property_055_la_SOURCES = MTA_SYSTEM/as_plugins/property_055.c
libmtapas_property_055_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_055_la_LIBADD = ${HX_LIBS} libgromox_common.la
libmtapas_property_056_la_SOURCES = MTA_SYSTEM/as_plugins/property_056.c
libmtapas_property_056_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_056_la_LIBADD = libgromox_common.la
libmtapas_property_057_la_SOURCES = MTA_SYSTEM/as_plugins/property_057.c
libmtapas_property_057_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_057_la_LIBADD = libgromox_common.la
libmtapas_property_058_la_SOURCES = MTA_SYSTEM/as_plugins/property_058.c
libmtapas_property_058_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_058_la_LIBADD = libgromox_common.la
libmtapas_property_059_la_SOURCES = MTA_SYSTEM/as_plugins/property_059.c
libmtapas_property_059_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_property_059_la_LIBADD = libgromox_common.la
libmtapas_rbl_check_la_SOURCES = MTA_SYSTEM/as_plugins/rbl_check.c
libmtapas_rbl_check_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_rcpt_filter_la_SOURCES = MTA_SYSTEM/as_plugins/rcpt_filter.c
libmtapas_rcpt_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_rcpt_filter_la_LIBADD = libgromox_common.la
libmtapas_rcpt_limit_la_SOURCES = MTA_SYSTEM/as_plugins/rcpt_limit.c
libmtapas_rcpt_limit_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_rcpt_limit_la_LIBADD = libgromox_common.la
libmtapas_sample_la_SOURCES = MTA_SYSTEM/as_plugins/sample.c
libmtapas_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_scamming_filter_la_SOURCES = MTA_SYSTEM/as_plugins/scamming_filter.c
libmtapas_scamming_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_scamming_filter_la_LIBADD = libgromox_common.la
libmtapas_site_protection_la_SOURCES = MTA_SYSTEM/as_plugins/site_protection/main.c MTA_SYSTEM/as_plugins/site_protection/site_protection.c
libmtapas_site_protection_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_site_protection_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtapas_special_protection_la_SOURCES = MTA_SYSTEM/as_plugins/special_protection.c
libmtapas_special_protection_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_special_protection_la_LIBADD = libgromox_common.la
libmtapas_spf_filter_la_SOURCES = MTA_SYSTEM/as_plugins/spf_filter.c
libmtapas_spf_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_spf_filter_la_LIBADD = ${spf_LIBS} libgromox_common.la
libmtapas_subject_auditor_la_SOURCES = MTA_SYSTEM/as_plugins/subject_auditor.c
libmtapas_subject_auditor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_subject_auditor_la_LIBADD = libgromox_common.la
libmtapas_subject_dots_la_SOURCES = MTA_SYSTEM/as_plugins/subject_dots.c
libmtapas_subject_dots_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_subject_dots_la_LIBADD = libgromox_common.la
libmtapas_trojan_detector_la_SOURCES = MTA_SYSTEM/as_plugins/trojan_detector.c
libmtapas_trojan_detector_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_trojan_detector_la_LIBADD = -lpthread libgromox_common.la
libmtapas_xmailer_filter_la_SOURCES = MTA_SYSTEM/as_plugins/xmailer_filter.c
libmtapas_xmailer_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libmtapas_xmailer_filter_la_LIBADD = -lpthread libgromox_common.la
libmtaflh_message_enqueue_la_SOURCES = MTA_SYSTEM/flusher_plugins/message_enqueue/main.c MTA_SYSTEM/flusher_plugins/message_enqueue/message_enqueue.c
libmtaflh_message_enqueue_la_LDFLAGS = ${plugin_LDFLAGS}
libmtaflh_message_enqueue_la_LIBADD = -lpthread libgromox_common.la
libmtaflh_sample_la_SOURCES = MTA_SYSTEM/flusher_plugins/sample.c
libmtaflh_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libmtaflh_sample_la_LIBADD = -lpthread
libmtahook_alias_translator_la_SOURCES = MTA_SYSTEM/mpc_plugins/alias_translator/main.c
libmtahook_alias_translator_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_alias_translator_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtahook_anonymous_keyword_la_SOURCES = MTA_SYSTEM/mpc_plugins/anonymous_keyword/anonymous_keyword.c MTA_SYSTEM/mpc_plugins/anonymous_keyword/main.c
libmtahook_anonymous_keyword_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_anonymous_keyword_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_antivirus_processor_la_SOURCES = MTA_SYSTEM/mpc_plugins/antivirus_processor.c
libmtahook_antivirus_processor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_antivirus_processor_la_LIBADD = libgromox_common.la libgromox_email.la
libmtahook_archive_agent_la_SOURCES = MTA_SYSTEM/mpc_plugins/archive_agent/main.c
libmtahook_archive_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_archive_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_cdner_caching_la_SOURCES = MTA_SYSTEM/mpc_plugins/cdner_caching.c
libmtahook_cdner_caching_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_cdner_caching_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_domain_keyword_la_SOURCES = MTA_SYSTEM/as_plugins/domain_keyword/keyword_engine.c MTA_SYSTEM/mpc_plugins/domain_keyword/bounce_producer.c MTA_SYSTEM/mpc_plugins/domain_keyword/domain_keyword.c MTA_SYSTEM/mpc_plugins/domain_keyword/main.c
libmtahook_domain_keyword_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_domain_keyword_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_domain_mailbox_la_SOURCES = MTA_SYSTEM/mpc_plugins/domain_mailbox/domain_mailbox.c MTA_SYSTEM/mpc_plugins/domain_mailbox/main.c
libmtahook_domain_mailbox_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_domain_mailbox_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtahook_domain_monitor_la_SOURCES = MTA_SYSTEM/mpc_plugins/domain_monitor/domain_monitor.c MTA_SYSTEM/mpc_plugins/domain_monitor/main.c
libmtahook_domain_monitor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_domain_monitor_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_domain_sign_la_SOURCES = MTA_SYSTEM/mpc_plugins/domain_sign/domain_sign.c MTA_SYSTEM/mpc_plugins/domain_sign/main.c
libmtahook_domain_sign_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_domain_sign_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_domain_subsystem_la_SOURCES = MTA_SYSTEM/mpc_plugins/domain_subsystem/address_list.c MTA_SYSTEM/mpc_plugins/domain_subsystem/clone_queue.c MTA_SYSTEM/mpc_plugins/domain_subsystem/domain_subsystem.c MTA_SYSTEM/mpc_plugins/domain_subsystem/main.c MTA_SYSTEM/mpc_plugins/domain_subsystem/smtp_clone.c
libmtahook_domain_subsystem_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_domain_subsystem_la_LIBADD = -lpthread ${HX_LIBS} libgromox_email.la
libmtahook_exmdb_local_la_SOURCES = MTA_SYSTEM/mpc_plugins/exmdb_local/auto_response.c MTA_SYSTEM/mpc_plugins/exmdb_local/bounce_audit.c MTA_SYSTEM/mpc_plugins/exmdb_local/bounce_producer.c MTA_SYSTEM/mpc_plugins/exmdb_local/cache_queue.c MTA_SYSTEM/mpc_plugins/exmdb_local/exmdb_client.c MTA_SYSTEM/mpc_plugins/exmdb_local/exmdb_local.c MTA_SYSTEM/mpc_plugins/exmdb_local/main.c MTA_SYSTEM/mpc_plugins/exmdb_local/net_failure.c
libmtahook_exmdb_local_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_exmdb_local_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libmtahook_from_replace_la_SOURCES = MTA_SYSTEM/mpc_plugins/from_replace.c
libmtahook_from_replace_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_from_replace_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtahook_gateway_dispatch_la_SOURCES = MTA_SYSTEM/mpc_plugins/gateway_dispatch/backend_list.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/bounce_producer.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/cache_queue.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/gateway_dispatch.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/main.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/net_failure.c MTA_SYSTEM/mpc_plugins/gateway_dispatch/smtp_dispatch.c
libmtahook_gateway_dispatch_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_gateway_dispatch_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_group_monitor_la_SOURCES = MTA_SYSTEM/mpc_plugins/group_monitor/group_monitor.c MTA_SYSTEM/mpc_plugins/group_monitor/main.c
libmtahook_group_monitor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_group_monitor_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_mail_approving_la_SOURCES = MTA_SYSTEM/mpc_plugins/mail_approving/bounce_producer.c MTA_SYSTEM/mpc_plugins/mail_approving/mail_approving.c MTA_SYSTEM/mpc_plugins/mail_approving/main.c
libmtahook_mail_approving_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mail_approving_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_mail_forwarder_la_SOURCES = MTA_SYSTEM/mpc_plugins/mail_forwarder/mail_forwarder.c MTA_SYSTEM/mpc_plugins/mail_forwarder/main.c
libmtahook_mail_forwarder_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mail_forwarder_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_mailbox_collector_la_SOURCES = MTA_SYSTEM/mpc_plugins/mailbox_collector.c
libmtahook_mailbox_collector_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mailbox_collector_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtahook_message_insulation_la_SOURCES = MTA_SYSTEM/mpc_plugins/message_insulation/bounce_producer.c MTA_SYSTEM/mpc_plugins/message_insulation/main.c MTA_SYSTEM/mpc_plugins/message_insulation/message_insulation.c
libmtahook_message_insulation_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_message_insulation_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_mlist_expand_la_SOURCES = MTA_SYSTEM/mpc_plugins/mlist_expand/bounce_producer.c MTA_SYSTEM/mpc_plugins/mlist_expand/main.c
libmtahook_mlist_expand_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_mlist_expand_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_os_inspection_la_SOURCES = MTA_SYSTEM/mpc_plugins/os_inspection.c
libmtahook_os_inspection_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_os_inspection_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_redirect_agent_la_SOURCES = MTA_SYSTEM/mpc_plugins/redirect_agent.c
libmtahook_redirect_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_redirect_agent_la_LIBADD = libgromox_common.la
libmtahook_relay_agent_la_SOURCES = MTA_SYSTEM/mpc_plugins/relay_agent/ip_range.c MTA_SYSTEM/mpc_plugins/relay_agent/main.c MTA_SYSTEM/mpc_plugins/relay_agent/relay_agent.c MTA_SYSTEM/mpc_plugins/relay_agent/relay_bridge.c
libmtahook_relay_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_relay_agent_la_LIBADD = -lpthread ${zlib_LIBS} libgromox_common.la libgromox_email.la
libmtahook_remote_postman_la_SOURCES = MTA_SYSTEM/mpc_plugins/remote_postman/bounce_producer.c MTA_SYSTEM/mpc_plugins/remote_postman/main.c MTA_SYSTEM/mpc_plugins/remote_postman/net_failure.c MTA_SYSTEM/mpc_plugins/remote_postman/remote_postman.c MTA_SYSTEM/mpc_plugins/remote_postman/sender_routing.c MTA_SYSTEM/mpc_plugins/remote_postman/smtp_deliverer.c MTA_SYSTEM/mpc_plugins/remote_postman/timer_queue.c
libmtahook_remote_postman_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_remote_postman_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la
libmtahook_report_forms_la_SOURCES = MTA_SYSTEM/mpc_plugins/report_forms.c
libmtahook_report_forms_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_report_forms_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_sample_la_SOURCES = MTA_SYSTEM/mpc_plugins/sample.c
libmtahook_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_self_monitor_la_SOURCES = MTA_SYSTEM/mpc_plugins/self_monitor.c
libmtahook_self_monitor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_self_monitor_la_LIBADD = -lpthread libgromox_common.la
libmtahook_spam_complain_la_SOURCES = MTA_SYSTEM/mpc_plugins/spam_complain/main.c MTA_SYSTEM/mpc_plugins/spam_complain/spam_complain.c
libmtahook_spam_complain_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_spam_complain_la_LIBADD = libgromox_common.la libgromox_email.la
libmtahook_spam_tagging_la_SOURCES = MTA_SYSTEM/mpc_plugins/spam_tagging.c
libmtahook_spam_tagging_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_spam_tagging_la_LIBADD = libgromox_email.la
libmtahook_status_forms_la_SOURCES = MTA_SYSTEM/mpc_plugins/status_forms.c
libmtahook_status_forms_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_status_forms_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_system_sign_la_SOURCES = MTA_SYSTEM/mpc_plugins/system_sign/main.c MTA_SYSTEM/mpc_plugins/system_sign/message_sign.c
libmtahook_system_sign_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_system_sign_la_LIBADD = -lpthread libgromox_common.la libgromox_email.la
libmtahook_system_updater_la_SOURCES = MTA_SYSTEM/mpc_plugins/system_updater.c
libmtahook_system_updater_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_system_updater_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
libmtahook_user_forwarder_la_SOURCES = MTA_SYSTEM/mpc_plugins/user_forwarder.c
libmtahook_user_forwarder_la_LDFLAGS = ${plugin_LDFLAGS}
libmtahook_user_forwarder_la_LIBADD = libgromox_common.la libgromox_email.la
libmtasvc_backup_list_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/str_table/main.c EXCHANGE_SYSTEM/service_plugins/str_table/str_table.c
libmtasvc_backup_list_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_backup_list_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_boundary_list_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_boundary_list_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_boundary_list_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_delivery_console_control_la_SOURCES = MTA_SYSTEM/service_plugins/console_control.c
libmtasvc_delivery_console_control_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_delivery_console_control_la_LIBADD = libgromox_common.la
libmtasvc_domain_list_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_domain_list_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_domain_list_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_domain_whitelist_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_domain_whitelist_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_domain_whitelist_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_dns_adaptor_la_SOURCES = MTA_SYSTEM/service_plugins/dns_adaptor/dns_adaptor.c MTA_SYSTEM/service_plugins/dns_adaptor/inbound_ips.c MTA_SYSTEM/service_plugins/dns_adaptor/main.c
libmtasvc_dns_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_dns_adaptor_la_LIBADD = -lpthread -lresolv ${HX_LIBS} libgromox_common.la libgromox_resolv.la
libmtasvc_esmtp_auth_la_SOURCES = MTA_SYSTEM/service_plugins/esmtp_auth/auth_cache.c MTA_SYSTEM/service_plugins/esmtp_auth/esmtp_auth.c MTA_SYSTEM/service_plugins/esmtp_auth/host_list.c MTA_SYSTEM/service_plugins/esmtp_auth/main.c MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.c
libmtasvc_esmtp_auth_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_esmtp_auth_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_forbidden_from_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_forbidden_from_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_forbidden_from_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_forbidden_domain_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_forbidden_domain_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_forbidden_domain_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_forbidden_rcpt_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_forbidden_rcpt_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_forbidden_rcpt_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_inmail_frequency_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_inmail_frequency_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_inmail_frequency_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
libmtasvc_invalid_user_la_SOURCES = MTA_SYSTEM/service_plugins/invalid_user/invalid_user.c MTA_SYSTEM/service_plugins/invalid_user/main.c
libmtasvc_invalid_user_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_invalid_user_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_ip_container_la_SOURCES = ${libexsvc_ip_container_la_SOURCES}
libmtasvc_ip_container_la_LDFLAGS = ${libexsvc_ip_container_la_LDFLAGS}
libmtasvc_ip_container_la_LIBADD = ${libexsvc_ip_container_la_LIBADD}
libmtasvc_ip_filter_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_ip_filter_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_ip_filter_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
libmtasvc_ip_whitelist_la_SOURCES = MTA_SYSTEM/service_plugins/ip_table/ip_table.c MTA_SYSTEM/service_plugins/ip_table/main.c
libmtasvc_ip_whitelist_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_ip_whitelist_la_LIBADD = -lpthread libgromox_common.la
libmtasvc_lang_charset_la_SOURCES = ${libexsvc_lang_charset_la_SOURCES}
libmtasvc_lang_charset_la_LDFLAGS = ${libexsvc_lang_charset_la_LDFLAGS}
libmtasvc_lang_charset_la_LIBADD = ${libexsvc_lang_charset_la_LIBADD}
libmtasvc_log_plugin_la_SOURCES = ${libexsvc_log_plugin_la_SOURCES}
libmtasvc_log_plugin_la_LDFLAGS = ${libexsvc_log_plugin_la_LDFLAGS}
libmtasvc_log_plugin_la_LIBADD = ${libexsvc_log_plugin_la_LIBADD}
libmtasvc_mail_from_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_mail_from_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_mail_from_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
libmtasvc_mail_subject_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_mail_subject_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_mail_subject_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
libmtasvc_midb_agent_la_SOURCES = MTA_SYSTEM/service_plugins/midb_agent.c
libmtasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
libmtasvc_mime_extension_la_SOURCES = ${libexsvc_mime_extension_la_SOURCES}
libmtasvc_mime_extension_la_LDFLAGS = ${libexsvc_mime_extension_la_LDFLAGS}
libmtasvc_mime_extension_la_LIBADD = ${libexsvc_mime_extension_la_LIBADD}
libmtasvc_monitor_domains_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_monitor_domains_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_monitor_domains_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_ms_locale_la_SOURCES = ${libexsvc_ms_locale_la_SOURCES}
libmtasvc_ms_locale_la_LDFLAGS = ${libexsvc_ms_locale_la_LDFLAGS}
libmtasvc_ms_locale_la_LIBADD = ${libexsvc_ms_locale_la_LIBADD}
libmtasvc_multiple_retrying_la_SOURCES = MTA_SYSTEM/service_plugins/multiple_retrying/main.c MTA_SYSTEM/service_plugins/multiple_retrying/multiple_retrying.c MTA_SYSTEM/service_plugins/multiple_retrying/proxy_retrying.c MTA_SYSTEM/service_plugins/multiple_retrying/retrying_table.c MTA_SYSTEM/service_plugins/multiple_retrying/stub_retrying.c
libmtasvc_multiple_retrying_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_multiple_retrying_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_mysql_adaptor_la_SOURCES = MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.c MTA_SYSTEM/service_plugins/mysql_adaptor/cdner_agent.c MTA_SYSTEM/service_plugins/mysql_adaptor/main.c MTA_SYSTEM/service_plugins/mysql_adaptor/mysql_adaptor.c MTA_SYSTEM/service_plugins/mysql_adaptor/uncheck_domains.c
libmtasvc_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
libmtasvc_outmail_frequency_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_outmail_frequency_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_outmail_frequency_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
libmtasvc_outmail_limitation_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_outmail_limitation_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_outmail_limitation_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
libmtasvc_protection_ip_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_protection_ip_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_protection_ip_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
libmtasvc_relay_domains_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_relay_domains_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_relay_domains_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_relay_list_la_SOURCES = ${libmtasvc_ip_whitelist_la_SOURCES}
libmtasvc_relay_list_la_LDFLAGS = ${libmtasvc_ip_whitelist_la_LDFLAGS}
libmtasvc_relay_list_la_LIBADD = ${libmtasvc_ip_whitelist_la_LIBADD}
libmtasvc_remote_delivery_audit_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmtasvc_remote_delivery_audit_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmtasvc_remote_delivery_audit_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
libmtasvc_remote_mx_hello_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_remote_mx_hello_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_remote_mx_hello_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_single_rcpt_la_SOURCES = ${libmtasvc_backup_list_la_SOURCES}
libmtasvc_single_rcpt_la_LDFLAGS = ${libmtasvc_backup_list_la_LDFLAGS}
libmtasvc_single_rcpt_la_LIBADD = ${libmtasvc_backup_list_la_LIBADD}
libmtasvc_smtp_console_control_la_SOURCES = ${libmtasvc_delivery_console_control_la_SOURCES}
libmtasvc_smtp_console_control_la_LDFLAGS = ${libmtasvc_delivery_console_control_la_LDFLAGS}
libmtasvc_smtp_console_control_la_LIBADD = ${libmtasvc_delivery_console_control_la_LIBADD}
libmtasvc_special_protection_audit_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_special_protection_audit_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_special_protection_audit_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}
libmtasvc_remote_delivery_forbidden_la_SOURCES = ${libmtasvc_ip_whitelist_la_SOURCES}
libmtasvc_remote_delivery_forbidden_la_LDFLAGS = ${libmtasvc_ip_whitelist_la_LDFLAGS}
libmtasvc_remote_delivery_forbidden_la_LIBADD = ${libmtasvc_ip_whitelist_la_LIBADD}
libmtasvc_retrying_table_la_SOURCES = MTA_SYSTEM/service_plugins/retrying_table/main.c MTA_SYSTEM/service_plugins/retrying_table/retrying_table.c
libmtasvc_retrying_table_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_retrying_table_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_sample_la_SOURCES = MTA_SYSTEM/service_plugins/sample.c
libmtasvc_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_service_auth_la_SOURCES = MTA_SYSTEM/service_plugins/esmtp_auth/service_auth.c MTA_SYSTEM/service_plugins/service_auth/main.c
libmtasvc_service_auth_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_service_auth_la_LIBADD = libgromox_common.la
libmtasvc_spam_statistic_la_SOURCES = MTA_SYSTEM/service_plugins/spam_statistic.c
libmtasvc_spam_statistic_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_spam_statistic_la_LIBADD = libgromox_common.la
libmtasvc_sssp_agent_la_SOURCES = MTA_SYSTEM/service_plugins/sssp_agent.c
libmtasvc_sssp_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_sssp_agent_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_tagging_table_la_SOURCES = MTA_SYSTEM/service_plugins/tagging_table/main.c MTA_SYSTEM/service_plugins/tagging_table/tagging_table.c
libmtasvc_tagging_table_la_LDFLAGS = ${plugin_LDFLAGS}
libmtasvc_tagging_table_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libmtasvc_user_filter_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmtasvc_user_filter_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmtasvc_user_filter_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}

# MRA_SYSTEM
pop3_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c MRA_SYSTEM/imap/service.c MRA_SYSTEM/pop3/console_server.c MRA_SYSTEM/pop3/console_cmd_handler.c MRA_SYSTEM/pop3/pop3_parser.c MRA_SYSTEM/pop3/pop3_cmd_handler.c MRA_SYSTEM/pop3/resource.c MRA_SYSTEM/pop3/system_services.c MRA_SYSTEM/pop3/units_allocator.c MRA_SYSTEM/pop3/main.c MRA_SYSTEM/pop3/listener.c
pop3_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la
imap_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c MRA_SYSTEM/imap/console_server.c MRA_SYSTEM/imap/console_cmd_handler.c MRA_SYSTEM/imap/imap_parser.c MRA_SYSTEM/imap/imap_cmd_parser.c MRA_SYSTEM/imap/listener.c MRA_SYSTEM/imap/main.c MRA_SYSTEM/imap/resource.c MRA_SYSTEM/imap/service.c MRA_SYSTEM/imap/system_services.c
imap_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la
apollo_SOURCES = MRA_SYSTEM/apollo.c
apollo_LDADD = ${HX_LIBS}
libmrasvc_cdner_agent_la_SOURCES = MRA_SYSTEM/service_plugins/cdner_agent.c
libmrasvc_cdner_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_cdner_agent_la_LIBADD = -lcrypt -lpthread libgromox_common.la
libmrasvc_event_proxy_la_SOURCES = MRA_SYSTEM/service_plugins/event_proxy.c
libmrasvc_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_event_proxy_la_LIBADD = -lpthread libgromox_common.la
libmrasvc_event_stub_la_SOURCES = MRA_SYSTEM/service_plugins/event_stub.c
libmrasvc_event_stub_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_event_stub_la_LIBADD = -lpthread libgromox_common.la
libmrasvc_ip_container_la_SOURCES = ${libexsvc_ip_container_la_SOURCES}
libmrasvc_ip_container_la_LDFLAGS = ${libexsvc_ip_container_la_LDFLAGS}
libmrasvc_ip_container_la_LIBADD = ${libexsvc_ip_container_la_LIBADD}
libmrasvc_ip_filter_la_SOURCES = ${libexsvc_ip_filter_la_SOURCES}
libmrasvc_ip_filter_la_LDFLAGS = ${libexsvc_ip_filter_la_LDFLAGS}
libmrasvc_ip_filter_la_LIBADD = ${libexsvc_ip_filter_la_LIBADD}
libmrasvc_log_plugin_la_SOURCES = ${libexsvc_log_plugin_la_SOURCES}
libmrasvc_log_plugin_la_LDFLAGS = ${libexsvc_log_plugin_la_LDFLAGS}
libmrasvc_log_plugin_la_LIBADD = ${libexsvc_log_plugin_la_LIBADD}
libmrasvc_midb_agent_la_SOURCES = MRA_SYSTEM/service_plugins/midb_agent.c
libmrasvc_midb_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_midb_agent_la_LIBADD = -lpthread libgromox_common.la
libmrasvc_mysql_adaptor_la_SOURCES = MRA_SYSTEM/service_plugins/mysql_adaptor/main.c MRA_SYSTEM/service_plugins/mysql_adaptor/mysql_adaptor.c
libmrasvc_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libmrasvc_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${mysql_LIBS} libgromox_common.la
libmrasvc_sample_la_SOURCES = ${libexsvc_sample_la_SOURCES}
libmrasvc_sample_la_LDFLAGS = ${libexsvc_sample_la_LDFLAGS}
libmrasvc_user_filter_la_SOURCES = ${libexsvc_user_filter_la_SOURCES}
libmrasvc_user_filter_la_LDFLAGS = ${libexsvc_user_filter_la_LDFLAGS}
libmrasvc_user_filter_la_LIBADD = ${libexsvc_user_filter_la_LIBADD}

# EXCHANGE_SYSTEM
http_SOURCES = EXCHANGE_SYSTEM/http/blocks_allocator.c EXCHANGE_SYSTEM/http/console_server.c EXCHANGE_SYSTEM/http/console_cmd_handler.c EXCHANGE_SYSTEM/http/hpm_processor.c EXCHANGE_SYSTEM/http/http_parser.c EXCHANGE_SYSTEM/http/listener.c EXCHANGE_SYSTEM/http/main.c EXCHANGE_SYSTEM/http/mod_cache.c EXCHANGE_SYSTEM/http/mod_fastcgi.c EXCHANGE_SYSTEM/http/mod_rewrite.c EXCHANGE_SYSTEM/http/pdu_processor.c EXCHANGE_SYSTEM/http/pdu_ndr.c EXCHANGE_SYSTEM/http/resource.c EXCHANGE_SYSTEM/http/service.c EXCHANGE_SYSTEM/http/system_services.c
http_LDADD = -ldl -lpthread -lresolv ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_epoll.la libgromox_email.la libgromox_rpc.la libgromox_mapi.la libgromox_webkit.la
medusa_SOURCES = EXCHANGE_SYSTEM/medusa.c
medusa_LDADD = ${HX_LIBS}
midb_SOURCES = EXCHANGE_SYSTEM/midb/cmd_parser.c EXCHANGE_SYSTEM/midb/common_util.c EXCHANGE_SYSTEM/midb/console_server.c EXCHANGE_SYSTEM/midb/console_cmd_handler.c EXCHANGE_SYSTEM/midb/exmdb_ext.c EXCHANGE_SYSTEM/midb/exmdb_client.c EXCHANGE_SYSTEM/midb/listener.c EXCHANGE_SYSTEM/midb/mail_engine.c EXCHANGE_SYSTEM/midb/main.c EXCHANGE_SYSTEM/midb/service.c EXCHANGE_SYSTEM/midb/system_services.c
midb_LDADD = -ldl -lpthread -lresolv ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
zcore_SOURCES = EXCHANGE_SYSTEM/midb/service.c EXCHANGE_SYSTEM/zcore/ab_tree.c EXCHANGE_SYSTEM/zcore/bounce_producer.c EXCHANGE_SYSTEM/zcore/common_util.c EXCHANGE_SYSTEM/zcore/console_server.c EXCHANGE_SYSTEM/zcore/console_cmd_handler.c EXCHANGE_SYSTEM/zcore/exmdb_ext.c EXCHANGE_SYSTEM/zcore/exmdb_client.c EXCHANGE_SYSTEM/zcore/listener.c EXCHANGE_SYSTEM/zcore/main.c EXCHANGE_SYSTEM/zcore/msgchg_grouping.c EXCHANGE_SYSTEM/zcore/table_object.c EXCHANGE_SYSTEM/zcore/object_tree.c EXCHANGE_SYSTEM/zcore/message_object.c EXCHANGE_SYSTEM/zcore/icsdownctx_object.c EXCHANGE_SYSTEM/zcore/folder_object.c EXCHANGE_SYSTEM/zcore/container_object.c EXCHANGE_SYSTEM/zcore/user_object.c EXCHANGE_SYSTEM/zcore/store_object.c EXCHANGE_SYSTEM/zcore/icsupctx_object.c EXCHANGE_SYSTEM/zcore/ics_state.c EXCHANGE_SYSTEM/zcore/attachment_object.c EXCHANGE_SYSTEM/zcore/rpc_parser.c EXCHANGE_SYSTEM/zcore/rpc_ext.c EXCHANGE_SYSTEM/zcore/system_services.c EXCHANGE_SYSTEM/zcore/zarafa_server.c
zcore_LDADD = -ldl -lpthread ${crypto_LIBS} ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libexsvc_codepage_lang_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/codepage_lang/codepage_lang.c EXCHANGE_SYSTEM/service_plugins/codepage_lang/main.c
libexsvc_codepage_lang_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_codepage_lang_la_LIBADD = -lpthread libgromox_common.la
libexsvc_event_proxy_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/event_proxy.c
libexsvc_event_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_event_proxy_la_LIBADD = -lpthread libgromox_common.la
libexsvc_exmdb_provider_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/exmdb_provider/bounce_producer.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/common_util.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/db_engine.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_client.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_ext.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_listener.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_parser.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/notification_agent.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/exmdb_server.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/folder.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/ics.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/instance.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/message.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/store.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/table.c EXCHANGE_SYSTEM/service_plugins/exmdb_provider/main.c
libexsvc_exmdb_provider_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_exmdb_provider_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
libexsvc_ip_container_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ip_container/ip_container.c EXCHANGE_SYSTEM/service_plugins/ip_container/main.c
libexsvc_ip_container_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ip_container_la_LIBADD = -lpthread libgromox_common.la
libexsvc_ip_filter_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ip_filter/audit_filter.c EXCHANGE_SYSTEM/service_plugins/ip_filter/grey_list.c EXCHANGE_SYSTEM/service_plugins/ip_filter/ip_filter.c EXCHANGE_SYSTEM/service_plugins/ip_filter/main.c EXCHANGE_SYSTEM/service_plugins/ip_filter/temp_list.c
libexsvc_ip_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ip_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libexsvc_lang_charset_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/lang_charset.c
libexsvc_lang_charset_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_lang_charset_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libexsvc_log_plugin_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/log_plugin/log_plugin.c EXCHANGE_SYSTEM/service_plugins/log_plugin/main.c
libexsvc_log_plugin_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_log_plugin_la_LIBADD = -lpthread libgromox_common.la
libexsvc_mime_extension_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/mime_extension.c
libexsvc_mime_extension_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_mime_extension_la_LIBADD = ${HX_LIBS} libgromox_common.la
libexsvc_ms_locale_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/ms_locale.c
libexsvc_ms_locale_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_ms_locale_la_LIBADD = ${HX_LIBS} libgromox_common.la
libexsvc_mysql_adaptor_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/mysql_adaptor/main.c EXCHANGE_SYSTEM/service_plugins/mysql_adaptor/mysql_adaptor.c
libexsvc_mysql_adaptor_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_mysql_adaptor_la_LIBADD = -lcrypt -lpthread ${mysql_LIBS} libgromox_common.la
libexsvc_sample_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/sample.c
libexsvc_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_user_filter_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/str_filter/audit_filter.c EXCHANGE_SYSTEM/service_plugins/str_filter/grey_list.c EXCHANGE_SYSTEM/service_plugins/str_filter/main.c EXCHANGE_SYSTEM/service_plugins/str_filter/str_filter.c EXCHANGE_SYSTEM/service_plugins/str_filter/temp_list.c
libexsvc_user_filter_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_user_filter_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la
libexsvc_timer_agent_la_SOURCES = EXCHANGE_SYSTEM/service_plugins/timer_agent.c
libexsvc_timer_agent_la_LDFLAGS = ${plugin_LDFLAGS}
libexsvc_timer_agent_la_LIBADD = -lpthread libgromox_common.la
libexproc_exchange_emsmdb_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/bounce_producer.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/common_util.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/asyncemsmdb_interface.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/asyncemsmdb_ndr.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/aux_ext.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/emsmdb_interface.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/emsmdb_ndr.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/notify_response.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/exmdb_client.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/main.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/msgchg_grouping.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/attachment_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/fastdownctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/fastupctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/folder_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ftstream_parser.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ftstream_producer.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/ics_state.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/icsdownctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/icsupctx_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/logon_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/message_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/stream_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/subscription_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/table_object.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_dispatch.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_ext.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/rop_processor.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcfold.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcfxics.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcmsg.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcnotif.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcperm.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcprpt.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxcstore.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxctabl.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxomsg.c EXCHANGE_SYSTEM/proc_plugins/exchange_emsmdb/oxorule.c
libexproc_exchange_emsmdb_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_emsmdb_la_LIBADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_rpc.la
libexproc_exchange_nsp_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/ab_tree.c EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/common_util.c EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/main.c EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/nsp_interface.c EXCHANGE_SYSTEM/proc_plugins/exchange_nsp/nsp_ndr.c
libexproc_exchange_nsp_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_nsp_la_LIBADD = -lpthread ${crypto_LIBS} ${HX_LIBS} libgromox_common.la libgromox_rpc.la
libexproc_exchange_rfr_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/exchange_rfr.c
libexproc_exchange_rfr_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_exchange_rfr_la_LIBADD = ${HX_LIBS} libgromox_common.la libgromox_rpc.la
libexproc_sample_la_SOURCES = EXCHANGE_SYSTEM/proc_plugins/sample.c
libexproc_sample_la_LDFLAGS = ${plugin_LDFLAGS}
libexproc_sample_la_LIBADD = libgromox_common.la
libexhpm_proxy_la_SOURCES = EXCHANGE_SYSTEM/hpm_plugins/mod_proxy.c
libexhpm_proxy_la_LDFLAGS = ${plugin_LDFLAGS}
libexhpm_proxy_la_LIBADD = -lpthread libgromox_common.la
libexhpm_sample_la_SOURCES = EXCHANGE_SYSTEM/hpm_plugins/sample.c
libexhpm_sample_la_LDFLAGS = ${plugin_LDFLAGS}

# AGENT_SERVICE
amidb_SOURCES = AGENT_SERVICE/amidb.c
amidb_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
amysql_SOURCES = AGENT_SERVICE/amysql.c
amysql_LDADD = -lcrypt -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
asession_SOURCES = AGENT_SERVICE/asession.c
asession_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
alock_SOURCES = AGENT_SERVICE/alock.c
alock_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
asensor_SOURCES = AGENT_SERVICE/asensor.c
asensor_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
digest_SOURCES = AGENT_SERVICE/digest.c
digest_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
freebusy_SOURCES = AGENT_SERVICE/freebusy.c
freebusy_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_webkit.la libgromox_mapi.la
pandora_SOURCES = AGENT_SERVICE/pandora.c
pandora_LDADD = ${HX_LIBS}
rtf2html_SOURCES = AGENT_SERVICE/rtf2html.c
rtf2html_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la

# DOMAIN_ADMIN
posidon_SOURCES = DOMAIN_ADMIN/posidon.c
posidon_LDADD = ${HX_LIBS}
fcgi_cgi_SOURCES = DOMAIN_ADMIN/fcgi_cgi.c
fcgi_cgi_LDADD = -lpthread ${HX_LIBS} ${ssl_LIBS} libgromox_common.la libgromox_rpc.la
da_daemon_SOURCES = DOMAIN_ADMIN/daemon/data_source.c DOMAIN_ADMIN/daemon/domain_classifier.c DOMAIN_ADMIN/daemon/item_sorter.c DOMAIN_ADMIN/daemon/log_flusher.c DOMAIN_ADMIN/daemon/main.c DOMAIN_ADMIN/daemon/smtp_sender.c LIBRARY/system_log.c
da_daemon_LDADD = -lresolv ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_resolv.la libgromox_webkit.la
domain_approve_SOURCES = DOMAIN_ADMIN/domain_approve/data_source.c DOMAIN_ADMIN/domain_approve/main.c DOMAIN_ADMIN/domain_approve/table_ui.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_approve_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_archive_SOURCES = DOMAIN_ADMIN/domain_archive/backup_ui.c DOMAIN_ADMIN/domain_archive/data_source.c DOMAIN_ADMIN/domain_archive/main.c DOMAIN_ADMIN/domain_archive/message_lookup.c DOMAIN_ADMIN/domain_archive/midb_client.c DOMAIN_ADMIN/domain_archive/session_client.c LIBRARY/system_log.c
domain_archive_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_binput_SOURCES = DOMAIN_ADMIN/domain_binput/exmdb_client.c DOMAIN_ADMIN/domain_binput/exmdb_tool.c DOMAIN_ADMIN/domain_binput/main.c DOMAIN_ADMIN/domain_binput/midb_tool.c DOMAIN_ADMIN/domain_binput/upload_ui.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_binput_LDADD = ${HX_LIBS} ${mysql_LIBS} ${sqlite_LIBS} ${xls_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la
domain_classes_SOURCES = DOMAIN_ADMIN/domain_classes/data_source.c DOMAIN_ADMIN/domain_classes/list_ui.c DOMAIN_ADMIN/domain_classes/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_classes_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_folders_SOURCES = DOMAIN_ADMIN/domain_folders/data_source.c DOMAIN_ADMIN/domain_folders/exmdb_client.c DOMAIN_ADMIN/domain_folders/list_ui.c DOMAIN_ADMIN/domain_folders/main.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_folders_LDADD = ${mysql_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la
domain_groups_SOURCES = DOMAIN_ADMIN/domain_groups/data_source.c DOMAIN_ADMIN/domain_groups/list_ui.c DOMAIN_ADMIN/domain_groups/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_groups_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_info_SOURCES = DOMAIN_ADMIN/domain_info/data_source.c DOMAIN_ADMIN/domain_info/info_ui.c DOMAIN_ADMIN/domain_info/main.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_info_LDADD = ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_keyword_SOURCES = DOMAIN_ADMIN/domain_keyword/data_source.c DOMAIN_ADMIN/domain_keyword/list_ui.c DOMAIN_ADMIN/domain_keyword/main.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_keyword_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_limit_SOURCES = DOMAIN_ADMIN/domain_keyword/data_source.c DOMAIN_ADMIN/domain_limit/gateway_control.c DOMAIN_ADMIN/domain_limit/limit_ui.c DOMAIN_ADMIN/domain_limit/main.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_limit_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_log_SOURCES = DOMAIN_ADMIN/domain_log/data_source.c DOMAIN_ADMIN/domain_log/main.c DOMAIN_ADMIN/domain_log/search_engine.c DOMAIN_ADMIN/domain_log/ui_center.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_log_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_main_SOURCES = DOMAIN_ADMIN/domain_main/data_source.c DOMAIN_ADMIN/domain_main/main.c DOMAIN_ADMIN/domain_main/ui_main.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_main_LDADD = ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_mlists_SOURCES = DOMAIN_ADMIN/domain_mlists/data_source.c DOMAIN_ADMIN/domain_mlists/list_ui.c DOMAIN_ADMIN/domain_mlists/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_mlists_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_monitor_SOURCES = DOMAIN_ADMIN/domain_monitor/data_source.c DOMAIN_ADMIN/domain_monitor/main.c DOMAIN_ADMIN/domain_monitor/table_ui.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_monitor_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_setup_SOURCES = DOMAIN_ADMIN/domain_setup/data_source.c DOMAIN_ADMIN/domain_setup/main.c DOMAIN_ADMIN/domain_setup/setup_ui.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_setup_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_sign_SOURCES = DOMAIN_ADMIN/domain_sign/data_source.c DOMAIN_ADMIN/domain_sign/list_ui.c DOMAIN_ADMIN/domain_sign/main.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_sign_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_statistic_SOURCES = DOMAIN_ADMIN/domain_keyword/data_source.c DOMAIN_ADMIN/domain_statistic/main.c DOMAIN_ADMIN/domain_statistic/statistic_ui.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_statistic_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
domain_users_SOURCES = DOMAIN_ADMIN/domain_binput/exmdb_tool.c DOMAIN_ADMIN/domain_binput/midb_tool.c DOMAIN_ADMIN/domain_users/data_source.c DOMAIN_ADMIN/domain_users/exmdb_client.c DOMAIN_ADMIN/domain_users/list_ui.c DOMAIN_ADMIN/domain_users/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
domain_users_LDADD = -lcrypt ${HX_LIBS} ${mysql_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la
group_archive_SOURCES = DOMAIN_ADMIN/domain_archive/message_lookup.c DOMAIN_ADMIN/domain_archive/midb_client.c DOMAIN_ADMIN/group_archive/backup_ui.c DOMAIN_ADMIN/group_archive/data_source.c DOMAIN_ADMIN/group_archive/main.c LIBRARY/session_client.c LIBRARY/system_log.c
group_archive_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_webkit.la
group_binput_SOURCES = DOMAIN_ADMIN/domain_binput/exmdb_client.c DOMAIN_ADMIN/domain_binput/exmdb_tool.c DOMAIN_ADMIN/domain_binput/midb_tool.c DOMAIN_ADMIN/group_binput/main.c DOMAIN_ADMIN/group_binput/upload_ui.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
group_binput_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la ${mysql_LIBS} ${sqlite_LIBS} ${xls_LIBS}
group_classes_SOURCES = DOMAIN_ADMIN/group_classes/data_source.c DOMAIN_ADMIN/group_classes/list_ui.c DOMAIN_ADMIN/group_classes/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
group_classes_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_clists_SOURCES = DOMAIN_ADMIN/group_clists/data_source.c DOMAIN_ADMIN/group_clists/list_ui.c DOMAIN_ADMIN/group_clists/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
group_clists_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_info_SOURCES = DOMAIN_ADMIN/group_info/data_source.c DOMAIN_ADMIN/group_info/info_ui.c DOMAIN_ADMIN/group_info/main.c LIBRARY/session_client.c LIBRARY/system_log.c
group_info_LDADD = libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_log_SOURCES = DOMAIN_ADMIN/group_log/data_source.c DOMAIN_ADMIN/group_log/main.c DOMAIN_ADMIN/group_log/search_engine.c DOMAIN_ADMIN/group_log/ui_center.c LIBRARY/session_client.c LIBRARY/system_log.c
group_log_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_main_SOURCES = DOMAIN_ADMIN/group_main/data_source.c DOMAIN_ADMIN/group_main/main.c DOMAIN_ADMIN/group_main/ui_main.c LIBRARY/session_client.c LIBRARY/system_log.c
group_main_LDADD = libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_monitor_SOURCES = DOMAIN_ADMIN/group_monitor/data_source.c DOMAIN_ADMIN/group_monitor/main.c DOMAIN_ADMIN/group_monitor/table_ui.c LIBRARY/gateway_control.c LIBRARY/session_client.c LIBRARY/system_log.c
group_monitor_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
group_users_SOURCES = DOMAIN_ADMIN/domain_users/exmdb_client.c DOMAIN_ADMIN/domain_binput/exmdb_tool.c DOMAIN_ADMIN/domain_binput/midb_tool.c DOMAIN_ADMIN/group_users/data_source.c DOMAIN_ADMIN/group_users/list_ui.c DOMAIN_ADMIN/group_users/main.c LIBRARY/locker_client.c LIBRARY/session_client.c LIBRARY/system_log.c
group_users_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la ${mysql_LIBS} ${sqlite_LIBS}
synchronizer_SOURCES = DOMAIN_ADMIN/synchronizer/file_operation.c DOMAIN_ADMIN/synchronizer/main.c DOMAIN_ADMIN/synchronizer/processing_engine.c DOMAIN_ADMIN/synchronizer/url_downloader.c
synchronizer_LDADD = -lresolv -lpthread ${HX_LIBS} libgromox_common.la

# SYSTEM_ADMIN
adaptor_SOURCES = LIBRARY/system_log.c SYSTEM_ADMIN/adaptor/data_source.c SYSTEM_ADMIN/adaptor/engine.c SYSTEM_ADMIN/adaptor/file_operation.c SYSTEM_ADMIN/adaptor/gateway_control.c SYSTEM_ADMIN/adaptor/main.c
adaptor_LDADD = -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la
admin_archive_SOURCES = DOMAIN_ADMIN/domain_archive/message_lookup.c DOMAIN_ADMIN/domain_archive/midb_client.c LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/admin_archive/admin_ui.c SYSTEM_ADMIN/admin_archive/data_source.c SYSTEM_ADMIN/admin_archive/main.c
admin_archive_LDADD = ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_email.la libgromox_webkit.la
admin_insulation_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/admin_insulation/admin_ui.c SYSTEM_ADMIN/admin_insulation/gateway_control.c SYSTEM_ADMIN/admin_insulation/main.c SYSTEM_ADMIN/admin_insulation/message_lookup.c
admin_insulation_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
admin_log_SOURCES = DOMAIN_ADMIN/daemon/log_flusher.c LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/admin_log/admin_ui.c SYSTEM_ADMIN/admin_log/main.c SYSTEM_ADMIN/admin_log/match_engine.c
admin_log_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
admin_main_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/admin_main/main.c SYSTEM_ADMIN/admin_main/ui_main.c
admin_main_LDADD = libgromox_common.la libgromox_webkit.la
archiver_list_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/archiver_list/list_ui.c SYSTEM_ADMIN/archiver_list/main.c SYSTEM_ADMIN/archiver_list/reload_control.c
archiver_list_LDADD = libgromox_common.la libgromox_webkit.la
area_list_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/area_list/list_ui.c SYSTEM_ADMIN/area_list/main.c
area_list_LDADD = libgromox_common.la libgromox_webkit.la
areadb_SOURCES = SYSTEM_ADMIN/areadb.c
areadb_LDADD = -lpthread libgromox_common.la libgromox_email.la
athena_SOURCES = SYSTEM_ADMIN/athena.c
athena_LDADD = ${HX_LIBS}
bl_delete_SOURCES = SYSTEM_ADMIN/bl_delete/midb_client.c SYSTEM_ADMIN/bl_delete/main.c
bl_delete_LDADD = -lpthread ${HX_LIBS} libgromox_common.la libgromox_webkit.la
boundary_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/boundary_blacklist/blacklist_ui.c SYSTEM_ADMIN/boundary_blacklist/main.c SYSTEM_ADMIN/boundary_blacklist/reload_control.c
boundary_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
cdnd_SOURCES = SYSTEM_ADMIN/cdnd.c
cdnd_LDADD = -lpthread ${HX_LIBS} ${crypto_LIBS} ${ssl_LIBS} ${mysql_LIBS} ${zlib_LIBS} libgromox_common.la
sa_daemon_SOURCES = DOMAIN_ADMIN/daemon/log_flusher.c DOMAIN_ADMIN/daemon/smtp_sender.c LIBRARY/locker_client.c LIBRARY/system_log.c SYSTEM_ADMIN/daemon/auto_backup.c SYSTEM_ADMIN/daemon/data_source.c SYSTEM_ADMIN/daemon/domain_cleaner.c SYSTEM_ADMIN/daemon/file_operation.c SYSTEM_ADMIN/daemon/keyword_cleaning.c SYSTEM_ADMIN/daemon/log_analyzer.c SYSTEM_ADMIN/daemon/main.c SYSTEM_ADMIN/daemon/media_migrator.c SYSTEM_ADMIN/daemon/message.c SYSTEM_ADMIN/daemon/midb_client.c SYSTEM_ADMIN/daemon/password_cleaner.c
sa_daemon_LDADD = -lresolv ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_email.la libgromox_resolv.la libgromox_webkit.la
daily_statistic_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/daily_statistic/data_extractor.c SYSTEM_ADMIN/daily_statistic/main.c SYSTEM_ADMIN/daily_statistic/statistic_ui.c SYSTEM_ADMIN/daily_statistic/translator.c
daily_statistic_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
daily_status_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/daily_status/data_extractor.c SYSTEM_ADMIN/daily_status/main.c SYSTEM_ADMIN/daily_status/status_ui.c
daily_status_LDADD = libgromox_common.la libgromox_webkit.la
dispasswd_SOURCES = SYSTEM_ADMIN/dispasswd.c
dispasswd_LDADD = libgromox_common.la ${mysql_LIBS}
dns_table_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/dns_table/main.c SYSTEM_ADMIN/dns_table/reload_control.c SYSTEM_ADMIN/dns_table/table_ui.c
dns_table_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
domain_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/domain_blacklist/blacklist_ui.c SYSTEM_ADMIN/domain_blacklist/main.c SYSTEM_ADMIN/domain_blacklist/reload_control.c
domain_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
domain_list_SOURCES = LIBRARY/acl_control.c LIBRARY/locker_client.c LIBRARY/system_log.c SYSTEM_ADMIN/domain_list/data_source.c SYSTEM_ADMIN/domain_list/exmdb_tool.c SYSTEM_ADMIN/domain_list/list_ui.c SYSTEM_ADMIN/domain_list/main.c
domain_list_LDADD = ${HX_LIBS} ${mysql_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la libgromox_webkit.la
domain_mailbox_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/domain_mailbox/list_ui.c SYSTEM_ADMIN/domain_mailbox/main.c SYSTEM_ADMIN/domain_mailbox/reload_control.c
domain_mailbox_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
domain_whitelist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/domain_whitelist/main.c SYSTEM_ADMIN/domain_whitelist/reload_control.c SYSTEM_ADMIN/domain_whitelist/whitelist_ui.c
domain_whitelist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
dynamic_dnslist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/dynamic_dnslist/dnslist_ui.c SYSTEM_ADMIN/dynamic_dnslist/main.c SYSTEM_ADMIN/dynamic_dnslist/reload_control.c
dynamic_dnslist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
enpasswd_SOURCES = SYSTEM_ADMIN/enpasswd.c
enpasswd_LDADD = libgromox_common.la ${mysql_LIBS}
event_SOURCES = SYSTEM_ADMIN/event.c
event_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la
forward_table_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/forward_table/main.c SYSTEM_ADMIN/forward_table/reload_control.c SYSTEM_ADMIN/forward_table/table_ui.c
forward_table_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
from_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/from_blacklist/blacklist_ui.c SYSTEM_ADMIN/from_blacklist/main.c SYSTEM_ADMIN/from_blacklist/reload_control.c
from_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
from_replace_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/from_replace/list_ui.c SYSTEM_ADMIN/from_replace/main.c SYSTEM_ADMIN/from_replace/reload_control.c
from_replace_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
ip_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/ip_blacklist/blacklist_ui.c SYSTEM_ADMIN/ip_blacklist/main.c SYSTEM_ADMIN/ip_blacklist/reload_control.c
ip_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
ip_whitelist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/ip_whitelist/main.c SYSTEM_ADMIN/ip_whitelist/reload_control.c SYSTEM_ADMIN/ip_whitelist/whitelist_ui.c
ip_whitelist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
ipdomain_table_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/ipdomain_table/main.c SYSTEM_ADMIN/ipdomain_table/reload_control.c SYSTEM_ADMIN/ipdomain_table/table_ui.c
ipdomain_table_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
keyword_group_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/keyword_group/data_extractor.c SYSTEM_ADMIN/keyword_group/group_ui.c SYSTEM_ADMIN/keyword_group/main.c SYSTEM_ADMIN/keyword_group/reload_control.c
keyword_group_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
keyword_statistic_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/keyword_statistic/main.c SYSTEM_ADMIN/keyword_statistic/statistic_ui.c
keyword_statistic_LDADD = libgromox_common.la libgromox_webkit.la
keyword_upload_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/keyword_upload/main.c SYSTEM_ADMIN/keyword_upload/reload_control.c SYSTEM_ADMIN/keyword_upload/upload_ui.c
keyword_upload_LDADD = libgromox_common.la libgromox_webkit.la
locker_SOURCES = SYSTEM_ADMIN/locker.c
locker_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
mensual_statistic_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/mensual_statistic/main.c SYSTEM_ADMIN/mensual_statistic/statistic_ui.c
mensual_statistic_LDADD = libgromox_common.la libgromox_webkit.la
message_sign_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/message_sign/list_ui.c SYSTEM_ADMIN/message_sign/main.c SYSTEM_ADMIN/message_sign/reload_control.c
message_sign_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
mkmidb_SOURCES = SYSTEM_ADMIN/mkmidb.c
mkmidb_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la
mkprivate_SOURCES = SYSTEM_ADMIN/mkprivate.c
mkprivate_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
mkpublic_SOURCES = SYSTEM_ADMIN/mkpublic.c
mkpublic_LDADD = ${HX_LIBS} ${mysql_LIBS} ${ssl_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
monitor_SOURCES = SYSTEM_ADMIN/monitor.c
monitor_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
org_list_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/org_list/data_source.c SYSTEM_ADMIN/org_list/list_ui.c SYSTEM_ADMIN/org_list/main.c
org_list_LDADD = libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
pad_SOURCES = LIBRARY/system_log.c SYSTEM_ADMIN/pad/communicator.c SYSTEM_ADMIN/pad/data_source.c SYSTEM_ADMIN/pad/exec_sched.c SYSTEM_ADMIN/pad/main.c SYSTEM_ADMIN/pad/midb_client.c SYSTEM_ADMIN/pad/pop3.c SYSTEM_ADMIN/pad/sensor_client.c SYSTEM_ADMIN/pad/uid_db.c SYSTEM_ADMIN/pad/vuser.c
pad_LDADD = -lresolv -lpthread ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_email.la
pop_porting_SOURCES = SYSTEM_ADMIN/pop_porting/main.c SYSTEM_ADMIN/pop_porting/pop3.c SYSTEM_ADMIN/pop_porting/smtp.c
pop_porting_LDADD = libgromox_common.la
rcpt_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/rcpt_blacklist/blacklist_ui.c SYSTEM_ADMIN/rcpt_blacklist/main.c SYSTEM_ADMIN/rcpt_blacklist/reload_control.c
rcpt_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
rebuild_SOURCES = SYSTEM_ADMIN/rebuild.c
rebuild_LDADD = ${HX_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
relay_allow_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/relay_allow/list_ui.c SYSTEM_ADMIN/relay_allow/main.c SYSTEM_ADMIN/relay_allow/reload_control.c
relay_allow_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
relay_domains_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/relay_domains/list_ui.c SYSTEM_ADMIN/relay_domains/main.c SYSTEM_ADMIN/relay_domains/reload_control.c
relay_domains_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
relay_table_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/relay_table/list_ui.c SYSTEM_ADMIN/relay_table/main.c SYSTEM_ADMIN/relay_table/reload_control.c
relay_table_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
rsyncd_SOURCES = SYSTEM_ADMIN/rsyncd.c
rsyncd_LDADD = -lpthread ${HX_LIBS} ${crypto_LIBS} ${ssl_LIBS} ${zlib_LIBS} libgromox_common.la
rsyncer_SOURCES = SYSTEM_ADMIN/rsyncer.c
rsyncer_LDADD = -lpthread ${HX_LIBS} ${crypto_LIBS} ${ssl_LIBS} ${zlib_LIBS} libgromox_common.la
scanner_SOURCES = LIBRARY/locker_client.c LIBRARY/system_log.c SYSTEM_ADMIN/scanner/data_source.c SYSTEM_ADMIN/scanner/engine.c SYSTEM_ADMIN/scanner/main.c SYSTEM_ADMIN/scanner/message.c SYSTEM_ADMIN/scanner/midb_client.c SYSTEM_ADMIN/scanner/smtp.c
scanner_LDADD = -lresolv -lpthread ${HX_LIBS} ${mysql_LIBS} ${sqlite_LIBS} libgromox_common.la libgromox_email.la libgromox_resolv.la
sendmail_SOURCES = SYSTEM_ADMIN/sendmail/main.c SYSTEM_ADMIN/sendmail/midb_client.c
sendmail_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
sensor_SOURCES = SYSTEM_ADMIN/sensor/main.c SYSTEM_ADMIN/sensor/exmdb_client.c SYSTEM_ADMIN/sensor/exmdb_ext.c
sensor_LDADD = -lpthread -lrt ${HX_LIBS} libgromox_common.la libgromox_email.la libgromox_mapi.la
session_SOURCES = SYSTEM_ADMIN/session.c
session_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
single_rcpt_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/single_rcpt/list_ui.c SYSTEM_ADMIN/single_rcpt/main.c SYSTEM_ADMIN/single_rcpt/reload_control.c
single_rcpt_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
status_rpc_SOURCES = SYSTEM_ADMIN/status_rpc.c
status_rpc_LDADD = libgromox_common.la
supervising_list_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/supervising_list/list_ui.c SYSTEM_ADMIN/supervising_list/main.c
supervising_list_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
supervising_statistic_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/supervising_statistic/main.c SYSTEM_ADMIN/supervising_statistic/statistic_ui.c
supervising_statistic_LDADD = libgromox_common.la libgromox_webkit.la
supervisor_SOURCES = SYSTEM_ADMIN/supervisor/main.c SYSTEM_ADMIN/supervisor/message.c SYSTEM_ADMIN/supervisor/pop3.c SYSTEM_ADMIN/supervisor/scheduler.c SYSTEM_ADMIN/supervisor/smtp.c
supervisor_LDADD = -lresolv -lpthread ${HX_LIBS} libgromox_common.la libgromox_resolv.la
synchronization_rpc_SOURCES = SYSTEM_ADMIN/synchronization_rpc.c
synchronization_rpc_LDADD = -lpthread libgromox_common.la
system_backup_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c LIBRARY/gateway_control.c SYSTEM_ADMIN/system_backup/backup_ui.c SYSTEM_ADMIN/system_backup/file_operation.c SYSTEM_ADMIN/system_backup/main.c
system_backup_LDADD = libgromox_common.la libgromox_webkit.la
system_info_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/system_info/data_source.c SYSTEM_ADMIN/system_info/info_ui.c SYSTEM_ADMIN/system_info/main.c
system_info_LDADD = libgromox_common.la libgromox_webkit.la ${mysql_LIBS}
system_password_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/system_password/main.c SYSTEM_ADMIN/system_password/password_ui.c
system_password_LDADD = libgromox_common.la libgromox_webkit.la
system_setup_SOURCES = LIBRARY/acl_control.c LIBRARY/gateway_control.c LIBRARY/system_log.c SYSTEM_ADMIN/system_setup/main.c SYSTEM_ADMIN/system_setup/setup_ui.c
system_setup_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
system_users_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/system_users/list_ui.c SYSTEM_ADMIN/system_users/main.c
system_users_LDADD = libgromox_common.la libgromox_webkit.la
tagging_whitelist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/tagging_whitelist/main.c SYSTEM_ADMIN/tagging_whitelist/reload_control.c SYSTEM_ADMIN/tagging_whitelist/whitelist_ui.c
tagging_whitelist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la
timer_SOURCES = SYSTEM_ADMIN/timer.c
timer_LDADD = -lpthread ${HX_LIBS} libgromox_common.la
userinfo_SOURCES = SYSTEM_ADMIN/userinfo.c
userinfo_LDADD = libgromox_common.la ${mysql_LIBS}
xmailer_blacklist_SOURCES = LIBRARY/acl_control.c LIBRARY/system_log.c SYSTEM_ADMIN/xmailer_blacklist/blacklist_ui.c SYSTEM_ADMIN/xmailer_blacklist/main.c SYSTEM_ADMIN/xmailer_blacklist/reload_control.c
xmailer_blacklist_LDADD = ${HX_LIBS} libgromox_common.la libgromox_webkit.la

# ARCHIVE_SYSTEM
archive_SOURCES = ARCHIVE_SYSTEM/archive.c
archive_LDADD = ${HX_LIBS} libgromox_common.la libgromox_email.la
cidb_SOURCES = ARCHIVE_SYSTEM/cidb/classify_engine.c ARCHIVE_SYSTEM/cidb/sphinxclient.c ARCHIVE_SYSTEM/cidb/cmd_parser.c ARCHIVE_SYSTEM/cidb/listener.c ARCHIVE_SYSTEM/cidb/main.c ARCHIVE_SYSTEM/cidb/mysql_pool.c LIBRARY/system_log.c
cidb_LDADD = -lpthread -lresolv ${HX_LIBS} ${mysql_LIBS} libgromox_common.la libgromox_email.la
migrator_SOURCES = ARCHIVE_SYSTEM/migrator.c
migrator_LDADD = ${HX_LIBS}
titan_SOURCES = ARCHIVE_SYSTEM/titan.c
titan_LDADD = ${HX_LIBS}

# php_mapi
mapi_la_CPPFLAGS = ${AM_CPPFLAGS} ${PHP_INCLUDES}
mapi_la_SOURCES = AGENT_SERVICE/php_mapi/ext_pack.c AGENT_SERVICE/php_mapi/mapi.cpp AGENT_SERVICE/php_mapi/rpc_ext.c AGENT_SERVICE/php_mapi/type_conversion.cpp AGENT_SERVICE/php_mapi/zarafa_client.cpp
mapi_la_LDFLAGS = ${plugin_LDFLAGS} ${PHP_LDFLAGS}

# tests
noinst_PROGRAMS = tests/getmxbyname
tests_getmxbyname_LDADD = ${HX_LIBS} libgromox_resolv.la

.la.ldd:
	${AM_V_GEN}${top_srcdir}/lddcheck ${top_builddir}/libtool $< $@
.tps.service: ${top_builddir}/config.status
	${AM_V_GEN}${SED} -e 's|@''libexecdir''@|${libexecdir}|g' <$< >$@

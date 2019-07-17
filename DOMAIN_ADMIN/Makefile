#add project parts name here
PARTS_LIST=posidon \
daemon \
domain_archive \
domain_binput \
domain_classes \
domain_folders \
domain_groups\
domain_info\
domain_limit \
domain_log \
domain_main \
domain_mlists\
domain_monitor \
domain_sign \
domain_keyword \
domain_setup \
domain_statistic \
domain_users \
domain_approve \
fcgi_cgi \
group_archive \
group_binput \
group_classes \
group_clists \
group_info \
group_log \
group_main \
group_monitor \
group_users \
synchronizer 

SCRIPTS_PATH=./scripts
#object files under "lib" directory, used for linking
REMOTE_LINKS=../common/common.so ../rpc_lib/rpc_lib.so ../email_lib/email_lib.so ../mapi_lib/mapi_lib.so ../webkit_lib/webkit_lib.so

.PHONY : normal
.PHONY : debug
.PHONY : clean
.PHONY : release

normal :
	@$(SCRIPTS_PATH)/environment lib $(REMOTE_LINKS)
	@echo $(PARTS_LIST) > /tmp/list_tmp
	@$(SCRIPTS_PATH)/compile normal /tmp/list_tmp
debug :
	@$(SCRIPTS_PATH)/environment lib $(REMOTE_LINKS)
	@echo $(PARTS_LIST) > /tmp/list_tmp
	@$(SCRIPTS_PATH)/compile debug /tmp/list_tmp
clean :
	@echo $(PARTS_LIST) > /tmp/list_tmp
	@$(SCRIPTS_PATH)/compile clean /tmp/list_tmp
release :
	-@$(SCRIPTS_PATH)/release

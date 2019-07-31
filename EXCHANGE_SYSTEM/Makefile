#add project parts name here
PARTS_LIST=http\
		   midb\
		   zcore\
		   service_plugins\
		   proc_plugins\
		   hpm_plugins\
		   medusa

SCRIPTS_PATH=./scripts
#object files under "lib" directory, used for linking
REMOTE_LINKS=../common/common.so \
			 ../epoll_scheduler/epoll_scheduler.so \
			 ../email_lib/email_lib.so \
			 ../webkit_lib/webkit_lib.so \
			 ../rpc_lib/rpc_lib.so \
			 ../mapi_lib/mapi_lib.so

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

#add project parts name here
PARTS_LIST=common\
		   epoll_scheduler\
		   email_lib\
		   webkit_lib\
		   rpc_lib\
		   mapi_lib

SCRIPTS_PATH=./scripts
#object files under "lib" directory, used for linking
REMOTE_LINKS=../common/common.so \
			 ../email_lib/email_lib.so

.PHONY : normal
.PHONY : debug
.PHONY : clean

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

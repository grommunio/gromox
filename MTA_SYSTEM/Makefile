#add project parts name here
PARTS_LIST=smtp\
		   service_plugins\
		   flusher_plugins\
		   as_plugins\
		   delivery_app\
		   mpc_plugins\
		   herculiz

SCRIPTS_PATH=./scripts
#object files under "lib" directory, used for linking
REMOTE_LINKS=../common/common.so\
			 ../epoll_scheduler/epoll_scheduler.so\
			 ../email_lib/email_lib.so\
			 ../mapi_lib/mapi_lib.so

.PHONY : normal
.PHONY : debug
.PHONY : clean
.PHONY : release
.PHONY : gateway

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
gateway :
	-@$(SCRIPTS_PATH)/release_gateway

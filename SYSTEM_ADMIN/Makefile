#add project parts name here
PARTS_LIST=adaptor\
admin_archive \
admin_insulation \
admin_log \
admin_main \
areadb \
area_list \
archiver_list \
athena \
bl_delete \
boundary_blacklist \
cdnd \
daemon \
daily_statistic \
daily_status \
dispasswd \
dns_table \
domain_blacklist \
domain_list \
domain_mailbox \
domain_whitelist \
dynamic_dnslist \
enpasswd \
event \
forward_table \
from_blacklist \
from_replace\
ip_blacklist \
ip_whitelist \
ipdomain_table \
keyword_group \
keyword_statistic \
keyword_upload \
locker \
mensual_statistic \
message_sign \
mkmidb \
mkprivate \
mkpublic \
monitor \
notifysend \
org_list \
pad \
pop_porting \
rcpt_blacklist \
rebuild \
relay_allow \
relay_domains \
relay_table \
rsyncd \
rsyncer \
scanner \
sendmail \
sensor \
session \
single_rcpt \
status_rpc \
supervising_list \
supervising_statistic \
supervisor \
synchronization_rpc \
system_backup \
system_info \
system_password \
system_setup \
system_users \
tagging_whitelist \
timer \
userinfo \
xmailer_blacklist\

SCRIPTS_PATH=./scripts
#object files under "lib" directory, used for linking
REMOTE_LINKS=../common/common.so ../email_lib/email_lib.so ../webkit_lib/webkit_lib.so ../mapi_lib/mapi_lib.so

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

#ifndef _H_MESSAGE_
#define _H_MESSAGE_

#define MESSAGE_BUFF_SIZE       64*1024

enum{
	MESSAGE_TURN_OUTOFDATE,
	MESSAGE_WILL_OUTOFDATE,
	MESSAGE_PASSWORD_AGING,
	MESSAGE_TOTAL_NUM
};


void message_init(const char *background_path, const char *logo_path,
	const char *logo_link, const char *resource_path);

int message_run();

int message_stop();

void message_free();

void message_make(char *buff, int type, const char *language,
	const char *str_domain_user, const char *admin_mailbox);

#endif

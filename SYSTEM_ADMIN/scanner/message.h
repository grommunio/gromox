#ifndef _H_MESSAGE_
#define _H_MESSAGE_

#define MESSAGE_BUFF_SIZE		64*1024


void message_init(const char *background_path, const char *logo_path,
	const char *logo_link);

int message_run();
extern void message_stop(void);
void message_free();

void message_alarm_message(char *buff, const char *area, const char *to);

#endif

#pragma once
#define MESSAGE_BUFF_SIZE		64*1024


void message_init(const char *background_path, const char *logo_path,
	const char *logo_link);
extern int message_run(void);
extern void message_stop(void);
extern void message_free(void);
void message_alarm_message(char *buff, const char *area, const char *to);

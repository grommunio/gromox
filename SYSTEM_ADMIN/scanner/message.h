#pragma once
#define MESSAGE_BUFF_SIZE		64*1024


void message_init(const char *background_path, const char *logo_path,
	const char *logo_link);
void message_alarm_message(char *buff, const char *area, const char *to);

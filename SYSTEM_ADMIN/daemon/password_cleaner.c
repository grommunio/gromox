#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "util.h"
#include "message.h"
#include "config_file.h"
#include "data_source.h"
#include "midb_client.h"

static int password_cleaner_daysofmonth(int year, int month);

static time_t password_cleaner_monthitvl(time_t from_time, int itvl_month);

static time_t password_cleaner_type_until(time_t cur_time, int type);

static void password_cleaner_verify_user(int default_type, time_t cur_time,
	const char *username, const char *maildir, const char *password);

static void password_cleaner_get_userlang(const char *maildir, char *lang);

static void password_cleaner_send_mail(char *msg_buff, int length,
	const char *maildir);


static time_t g_now_time;

void password_cleaner_init(time_t now_time)
{
	g_now_time = now_time;
}

int password_cleaner_run()
{
	int type;
	char *str_value;
	USER_INFO *puser;
	char temp_path[256];
	CONFIG_FILE *pconfig;
	DATA_COLLECT *pcollect;
	DATA_COLLECT *pcollect1;
	EXTPASSWD_DOMAIN *pdomain;


	pcollect = data_source_collect_init();
	if (NULL == pcollect) {
		return 0;
	}
	
	if (FALSE == data_source_get_extpasswd_domain(pcollect)) {
		data_source_collect_free(pcollect);
		return 0;
	}

	for (data_source_collect_begin(pcollect);
		!data_source_collect_done(pcollect);
		data_source_collect_forward(pcollect)) {
		pdomain = (EXTPASSWD_DOMAIN*)data_source_collect_get_value(pcollect);
		snprintf(temp_path, 256, "%s/domain.cfg", pdomain->homedir);
		pconfig = config_file_init(temp_path);
		if (NULL == pconfig) {
			continue;
		}
		str_value = config_file_get_value(pconfig, "EXTPASSWD_TYPE");
		if (NULL == str_value) {
			type = 2;
		} else {
			type = atoi(str_value);
			if (type < 2 || type > 5) {
				type = 2;
			}
		}
		config_file_free(pconfig);

		pcollect1 = data_source_collect_init();
		if (NULL == pcollect1) {
			continue;
		}

		if (FALSE == data_source_get_user_list(pdomain->domainname, pcollect1)) {
			data_source_collect_free(pcollect1);
			continue;
		}

		for (data_source_collect_begin(pcollect1);
			!data_source_collect_done(pcollect1);
			data_source_collect_forward(pcollect1)) {
			puser = (USER_INFO*)data_source_collect_get_value(pcollect1);
			password_cleaner_verify_user(type, g_now_time, puser->username,
				puser->maildir, puser->password);
		}
		data_source_collect_free(pcollect1);

	}

	data_source_collect_free(pcollect);
	return 0;

}

void password_cleaner_stop(void)
{
	/* do nothing */

}


void password_cleaner_free()
{
	/* do nothing */
}

static void password_cleaner_verify_user(int default_type, time_t cur_time,
	const char *username, const char *maildir, const char *password)
{
	int fd;
	int type;
	int length;
	int obsolete;
	time_t zero_time;
	time_t until_time;
	char language[32];
	char num_buff[32];
	char temp_path[256];
	char temp_buff[1024];
	char passwd_buff[256];
	struct stat node_stat;
	char message_buff[MESSAGE_BUFF_SIZE];

	
	if ('\0' == password[0]) {
		return;
	}
	snprintf(temp_path, 256, "%s/config/extpasswd.cfg", maildir);
	if (0 != stat(temp_path, &node_stat)) {
		length = snprintf(temp_buff, 1024, "{\"lastpasswd\":\"%s\","
					"\"zero\":%ld,\"obsolete\":0}", password, cur_time);
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			write(fd, temp_buff, length);
			close(fd);
		}
		return;
	}
	
	if (node_stat.st_size > sizeof(temp_buff) - 1) {
		return;
	}
	
	fd = open(temp_path, O_RDWR);
	if (-1 == fd) {
		return;
	}
	
	if (node_stat.st_size != read(fd, temp_buff, node_stat.st_size)) {
		close(fd);
		return;
	}
	temp_buff[node_stat.st_size] = '\0';
	close(fd);
	
	if (FALSE == get_digest(temp_buff, "obsolete", num_buff, 32)) {
		return;
	}
	obsolete = atoi(num_buff);
	if (0 != obsolete) {
		if (FALSE == get_digest(temp_buff, "lastpasswd",
			passwd_buff, 256) || '\0' == passwd_buff[0] ||
			0 == strcmp(passwd_buff, password)) {
			return;
		}
		
		/* password is changed */
		snprintf(num_buff, 32, "%ld", cur_time);
		add_digest(temp_buff, sizeof(temp_buff), "zero", num_buff);
		sprintf(passwd_buff, "\"%s\"", password);
		add_digest(temp_buff, sizeof(temp_buff), "lastpasswd", passwd_buff);
		set_digest(temp_buff, sizeof(temp_buff), "obsolete", "0");
		fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
		if (-1 != fd) {
			write(fd, temp_buff, strlen(temp_buff));
			close(fd);
		}
		return;
	} else {
		if (FALSE == get_digest(temp_buff, "type", num_buff, 16)) {
			type = default_type;
		} else {
			type = atoi(num_buff);
		}
		
		if (1 == type || FALSE == get_digest(temp_buff, "zero",
			num_buff, 32)) {
			snprintf(num_buff, 32, "%ld", cur_time);
			add_digest(temp_buff, sizeof(temp_buff), "zero", num_buff);
			sprintf(passwd_buff, "\"%s\"", password);
			add_digest(temp_buff, sizeof(temp_buff), "lastpasswd", passwd_buff);
			fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (-1 != fd) {
				write(fd, temp_buff, strlen(temp_buff));
				close(fd);
			}
			return;
		}
		
		zero_time = atol(num_buff);
		until_time = password_cleaner_type_until(zero_time, type);
		if (cur_time >= until_time - 7*24*60*60 &&
			cur_time < until_time - 6*24*60*60) {
			password_cleaner_get_userlang(maildir, language);
			message_make(message_buff, MESSAGE_PASSWORD_AGING,
				language, username, "notifier@system.mail");
			password_cleaner_send_mail(message_buff,
				strlen(message_buff), maildir);
		} else if (until_time <= cur_time) {
			randstring(num_buff, 16);
			strcpy(passwd_buff, md5_crypt_wrapper(num_buff));
			if (TRUE == data_source_update_userpasswd(username, passwd_buff)) {
				length = strlen(passwd_buff);
				memmove(passwd_buff + 1, passwd_buff, length);
				passwd_buff[0] = '"';
				length += 1;
				passwd_buff[length] = '"';
				length ++;
				passwd_buff[length] = '\0';
				add_digest(temp_buff, sizeof(temp_buff), "lastpasswd", passwd_buff);
				set_digest(temp_buff, sizeof(temp_buff), "obsolete", "1");
				fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd) {
					write(fd, temp_buff, strlen(temp_buff));
					close(fd);
				}
			}
		} else {
			if (FALSE == get_digest(temp_buff, "lastpasswd",
				passwd_buff, 256)) {
				sprintf(passwd_buff, "\"%s\"", password);
				add_digest(temp_buff, sizeof(temp_buff), "lastpasswd", passwd_buff);
				fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd) {
					write(fd, temp_buff, strlen(temp_buff));
					close(fd);
				}
				return;
			}
			if (0 != strcmp(passwd_buff, password)) {
				snprintf(num_buff, 32, "%ld", cur_time);
				add_digest(temp_buff, sizeof(temp_buff), "zero", num_buff);
				sprintf(passwd_buff, "\"%s\"", password);
				add_digest(temp_buff, sizeof(temp_buff), "lastpasswd", passwd_buff);
				fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
				if (-1 != fd) {
					write(fd, temp_buff, strlen(temp_buff));
					close(fd);
				}
			}
		}
	}
	
}

static time_t password_cleaner_type_until(time_t cur_time, int type)
{
	switch (type) {
	case 2:
		return password_cleaner_monthitvl(cur_time, 12);
	case 3:
		return password_cleaner_monthitvl(cur_time, 6);
	case 4:
		return password_cleaner_monthitvl(cur_time, 3);
	case 5:
		return password_cleaner_monthitvl(cur_time, 1);
	}
	return 0;
}

static time_t password_cleaner_monthitvl(time_t from_time, int itvl_month)
{
	int days;
	struct tm tmp_tm;
	
	if (0 == itvl_month) {
		return from_time;
	}
	
	memset(&tmp_tm, 0, sizeof(tmp_tm));
	localtime_r(&from_time, &tmp_tm);
	
	tmp_tm.tm_mon += itvl_month;
	if (tmp_tm.tm_mon >= 12) {
		tmp_tm.tm_year += tmp_tm.tm_mon / 12;
		tmp_tm.tm_mon = tmp_tm.tm_mon % 12;
	}
	
	days = password_cleaner_daysofmonth(tmp_tm.tm_year, tmp_tm.tm_mon + 1);
	if (tmp_tm.tm_mday > days) {
		tmp_tm.tm_mday = days;
	}
	
	return mktime(&tmp_tm);
}


static int password_cleaner_daysofmonth(int year, int month)
{
	if (year <= 0) {
		return 0;
	}
	switch(month) {
	case 1:  
	case 3:
	case 5:
	case 7:
	case 8:
	case 10:
	case 12:
		return 31;
	case 4:
	case 6:
	case 9:
	case 11:
		return 30;
	case 2:
		if((year % 4 != 0)||((year % 100 == 0)&&(year % 400 != 0))) {
			return 28;
		} else {
			return 29;
		}
	default:
		return 0;
	}
}

static void password_cleaner_get_userlang(const char *maildir, char *lang)
{
	int fd;
	size_t tmp_len;
	char *pbuff;
	char temp_lang[32];
	char temp_lang1[32];
	char temp_lang2[32];
	char temp_path[256];
	struct stat node_stat;
	
	snprintf(temp_path, 255, "%s/config/setting.cfg", maildir);
	if (0 != stat(temp_path, &node_stat) || 0 == S_ISREG(node_stat.st_mode)) {
		strcpy(lang, "en");
		return;
	}
	
	pbuff = malloc(node_stat.st_size + 1);
	if (NULL == pbuff) {
		strcpy(lang, "en");
		return;
	}
	
	fd = open(temp_path, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		strcpy(lang, "en");
		return;
	}
	
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		strcpy(lang, "en");
		return;
	}
	
	close(fd);
	pbuff[node_stat.st_size] = '\0';
	if (FALSE == get_digest(pbuff, "lang", temp_lang, sizeof(temp_lang))) {
		free(pbuff);
		strcpy(lang, "en");
		return;
	}
	
	free(pbuff);
	
	tmp_len = 32;
	if (0 == decode64(temp_lang, strlen(temp_lang),
		temp_lang1, &tmp_len) && 0 == encode64(temp_lang1,
		strlen(temp_lang1), temp_lang2, 32, &tmp_len) &&
		0 == strcmp(temp_lang, temp_lang2)) {
		strcpy(lang, temp_lang1);
	} else {
		strcpy(lang, temp_lang);
	}

	if (0 == strcasecmp(lang, "zh")) {
		strcpy(lang, "zh-cn");
	} else if (0 == strcasecmp(lang, "cn")) {
		strcpy(lang, "zh-tw");
	} else if (0 == strcasecmp(lang, "jp")) {
		strcpy(lang, "ja");
	} else {
		strcpy(lang, "en");
	}
}

static void password_cleaner_send_mail(char *msg_buff, int length,
	const char *maildir)
{
	int fd;
	int tmp_len;
	size_t offset;
	char temp_path[256];
	char mid_string[128];
	
	sprintf(mid_string, "%ld.0.passwd", time(NULL)); 
	snprintf(temp_path, 256, "%s/eml/%s", maildir, mid_string);
	fd = open(temp_path, O_CREAT|O_TRUNC|O_WRONLY, 0666);
	if (-1 == fd) {
		return;
	}
	write(fd, msg_buff, length);
	close(fd);
	if (FALSE == midb_client_insert(maildir, "inbox", mid_string)) {
		remove(temp_path);
	}

}


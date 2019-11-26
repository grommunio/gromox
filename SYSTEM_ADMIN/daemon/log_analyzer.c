#include "log_analyzer.h"
#include "util.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>


static char g_statistic_path[256];
static char g_original_path[256];
static time_t g_now_time;

void log_analyzer_init(time_t now_time, const char *statistic_path,
	const char *orignal_path)
{
	strcpy(g_statistic_path, statistic_path);
	strcpy(g_original_path, orignal_path);
	g_now_time = now_time;
}

int log_analyzer_run()
{
	DIR *dirp;
	FILE *fp;
	BOOL b_outgoing;
	int in_spam_num;
	int in_normal_num;
	int out_spam_num;
	int out_normal_num;
	struct dirent *direntp;
	struct stat node_stat;
	struct tm *ptime, tm_time;
	char *ptr, time_str[32];
	char temp_path[256];
	char temp_buff[64*1024];
	

	in_spam_num = 0;
	in_normal_num = 0;
	out_spam_num = 0;
	out_normal_num = 0;
	
	dirp = opendir(g_original_path);
	if (NULL == dirp){
		printf("[log_analyzer]: fail to open directory %s\n",
			g_original_path);
		return -1;
	}
	/* 
	 * enumerate the sub-directory of source director each 
	 * sub-directory represents one MTA
	 */
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", g_original_path, direntp->d_name);
		if (0 != stat(temp_path, &node_stat)) {
			continue;
		}
		if (0 == S_ISDIR(node_stat.st_mode)) {
			continue;
		}
		ptime = localtime(&g_now_time);
		strftime(time_str, 32, "%m%d", ptime);
		/* open the SMTP log of today */
		sprintf(temp_path, "%s/%s/logs/smtp/smtp_log%s.txt", g_original_path,
			direntp->d_name, time_str);
		fp = fopen(temp_path, "r");
		if (NULL == fp) {
			continue;
		}
		/* parse each line in log file */
		while (NULL != fgets(temp_buff, 64*1024, fp)) {
			memset(&tm_time, 0, sizeof(tm_time));
			/* convert string to time epoch */
			ptr = strptime(temp_buff, "%Y/%m/%d %H:%M:%S\t", &tm_time);
			if (NULL == ptr) {
				continue;
			}
			/* ignore the items of yesterday */
			
			if (tm_time.tm_mday != ptime->tm_mday) {
				continue;
			} 

			/* retrieve the source IP */
			if (NULL != strstr(ptr, "IP: 127.0.0.1,")) {
				continue;
			}

			if (NULL != strstr(ptr, "user: ")) {
				b_outgoing = TRUE;
			} else if (NULL != strstr(ptr, "FROM: ")) {
				b_outgoing = FALSE;
			} else {
				continue;
			}
			
			/* get the process result of SMTP session */
			if (NULL != strstr(ptr, "illegal mail is cut!") ||
				NULL != strstr(ptr, "flushing queue permanent fail") ||
				NULL != strstr(ptr, "dubious mail is cut!")) {
				if (TRUE == b_outgoing) {
					out_spam_num ++;
				} else {
					in_spam_num ++;
				}
			} else if (NULL != strstr(ptr, "return OK, queue-id:")) {
				if (TRUE == b_outgoing) {
					out_normal_num ++;
				} else {
					in_normal_num ++;
				}
			}
		}
		fclose(fp);
		
	}				
	
	closedir(dirp);

	strftime(time_str, 32, "%Y-%m-%d", localtime(&g_now_time));
	sprintf(temp_buff, "%s\t%d\t%d\n", time_str, in_spam_num + out_spam_num,
		in_normal_num + out_normal_num);
	fp = fopen(g_statistic_path, "a");
	if (NULL != fp) {
		fwrite(temp_buff, 1, strlen(temp_buff), fp);
		fclose(fp);
	}
	return 0;
}

int log_analyzer_stop()
{
	/* do nothing */
	return 0;
}

void log_analyzer_free()
{
	g_statistic_path[0] = '\0';
	g_original_path[0] = '\0';
}


#include <errno.h>
#include <string.h>
#include <libHX/string.h>
#include "domain_classifier.h"
#include "util.h"
#include "str_hash.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>


static char g_original_path[256];
static char g_dest_path[256];
static time_t g_now_time;
static int g_hash_num;
static int g_table_size;
static STR_HASH_TABLE *g_hash_table;

static unsigned int domain_classifier_hash_domain(const char *domain_name);

static void domain_classifier_remove_inode(const char *path);

void domain_classifier_init(time_t now_time, const char *orignal_path,
	int hash_num, int table_size)
{
	strcpy(g_original_path, orignal_path);
	strcpy(g_dest_path, "/tmp/posidon_cache");
	g_now_time = now_time;
	g_hash_num = hash_num;
	g_table_size = table_size;
}

int domain_classifier_run()
{
	DIR *dirp;
	FILE *fp, *fp1, **fp_hash;
	LOG_ITEM item;
	ITEM_DATA tmp_item;
	BOOL b_limit;
	BOOL b_fopen;
	BOOL b_outgoing;
	STR_HASH_ITER *iter;
	int length, i;
	int hash_num;
	struct dirent *direntp;
	struct stat node_stat;
	struct tm *ptime, tm_time;
	struct rlimit rl;
	char *pdomain, *first_domain;
	char *ptr, *ptr1, *ptr_prev;
	char temp_ip[16];
	char time_str[32];
	char temp_path[256];
	char temp_buff[64*1024];
	
	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[domain_classifier]: fail to get file limit\n");
		return -3;
	}
	b_limit = FALSE;
	if (rl.rlim_cur < g_table_size + 100) {
		rl.rlim_cur = g_table_size + 100;
		b_limit = TRUE;
	}
	if (rl.rlim_max < g_table_size + 100) {
		rl.rlim_max = g_table_size + 100;
		b_limit = TRUE;
	}
	if (TRUE == b_limit && 0 != setrlimit(RLIMIT_NOFILE, &rl)) {
		printf("[domain_classifier]: fail to modify file limit\n");
	}
	g_hash_table = str_hash_init(g_table_size, sizeof(FILE*), NULL);
	if (NULL == g_hash_table) {
		printf("[domain_classifier]: failed to create hash table: %s\n", strerror(errno));
		return -5;
	}

	
	dirp = opendir(g_original_path);
	if (NULL == dirp){
		printf("[domain_classifier]: failed to open directory %s: %s\n",
			g_original_path, strerror(errno));
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
		return -6;
	}
	mkdir("/tmp/posidon_cache", 0777);
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
			memset(&item, 0, sizeof(item));
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

			item.time = mktime(&tm_time);
			/* retrieve the source ipaddr */
			ptr = strstr(ptr, " IP: ");
			if (NULL == ptr) {
				continue;
			}
			ptr += 5;
			ptr1 = strchr(ptr, ',');
			if (NULL == ptr1) {
				continue;
			}
			length = ptr1 - ptr;
			if (length > 15) {
				continue;		
			}
			memcpy(temp_ip, ptr, length);
			temp_ip[length] = '\0';
			/* ignore monitor sessions */
			if (0 == strcmp(temp_ip, "127.0.0.1")) {
				continue;
			}
			item.ip = inet_addr(temp_ip);
			/* search MAIL FROM address of SMTP session */
			ptr = strstr(temp_buff, "user: ");
			b_outgoing = TRUE;
			if (NULL == ptr) {
				ptr = strstr(temp_buff, "FROM: ");
				if (NULL == ptr) {
					continue;
				}
				b_outgoing = FALSE;
			}
			ptr += 6;
			/* get RCPT TO addresses of SMTP session */
			ptr1 = strchr(ptr, ',');
			if (NULL == ptr) {
				continue;
			}
			length = ptr1 - ptr;
			if (length >= 64 || length <= 0) {
				continue;
			}
			memcpy(item.from, ptr, length);
			HX_strlower(item.from);
			if (TRUE == b_outgoing) {
				first_domain = strchr(item.from, '@');
				if (NULL == first_domain) {
					continue;
				}
				first_domain ++;
			}
			ptr = strstr(ptr1, ", TO: ");
			if (NULL == ptr) {
				continue;
			}
			ptr += 6;
			ptr1 = strstr(ptr, "  ");
			if (NULL == ptr1) {
				continue;
			}
			length = ptr1 - ptr;
			if (length > 64 * 8 - 2) {
				continue;
			}
			/* 
			 * parse FROM addresses into rcpt array, and
			 * compare if addresses' domains are same
			 */
			if (FALSE == b_outgoing) {
				first_domain = NULL;
			}
			for (ptr_prev=ptr,i=0; i<8 && ptr<=ptr1; ptr++) {
				if (' ' != *ptr) {
					continue;
				}
				if (ptr - ptr_prev >= 64) {
					ptr_prev = ptr + 1;
					continue;
				}
				memcpy(item.to + 64*i, ptr_prev, ptr - ptr_prev);
				HX_strlower(item.to + 64 * i);
				if (FALSE == b_outgoing) {
					if (0 == i) {
						first_domain = strchr(item.to, '@');
						if (NULL == first_domain) {
							break;
						}
						first_domain ++;
					} else {
						pdomain = strchr(item.to + 64*i, '@');
						if (NULL == pdomain || 0 != strcasecmp((++pdomain),
							first_domain)){
							break;
						}
					}
				}
				ptr_prev = ptr + 1;
				i ++;
			}
			if (FALSE == b_outgoing && (ptr != ptr1 + 1 || NULL == first_domain)) {
				continue;
			}
			/* get the process result of SMTP session */
			if (0 == strncmp(ptr1 + 2, "rcpt address is invalid", 23)) {
				item.type = LOG_ITEM_NO_USER;	
			} else if (0 == strncmp(ptr1 + 2, "illegal mail is cut!", 20)) {
				item.type = LOG_ITEM_SPAM_MAIL;	
			} else if (0 == strncmp(ptr1 + 2, "return OK, queue-id:", 20)) {
				if (TRUE == b_outgoing) {
					item.type = LOG_ITEM_OUTGOING_OK;
				} else {
					item.type = LOG_ITEM_OK;
				}
				item.queue_id = atoi(ptr1 + 22);
			} else if (0 == strncmp(ptr1 + 2, "time out", 8)) {
				item.type = LOG_ITEM_TIMEOUT;
			} else if (0 == strncmp(ptr1 + 2, "flushing queue "
			    "permanent failure", 29)) {
				item.type = LOG_ITEM_SPAM_VIRUS;
			} else if (0 == strncmp(ptr1 + 2, "dubious mail is cut!", 20)) {
				item.type = LOG_ITEM_RETRYING;
			} else {
				continue;
			}
			/* get file pointer from cache table if exists, else create it */
			ptr = item.to;
			b_fopen = FALSE;
			fp_hash = (FILE**)str_hash_query(g_hash_table, first_domain);
			if (NULL == fp_hash) {
				/* get hash number of domain */
				hash_num = domain_classifier_hash_domain(first_domain)%
							g_hash_num;
				sprintf(temp_path, "%s/%d", g_dest_path, hash_num);
				if (0 != stat(temp_path, &node_stat)) {
					mkdir(temp_path, 0777);
				} else if (0 == S_ISDIR(node_stat.st_mode)) {
					continue;
				}
				sprintf(temp_path, "%s/%d/%s", g_dest_path, hash_num,
					first_domain); 
				if (0 != stat(temp_path, &node_stat)) {
					mkdir(temp_path, 0777);
				} else if (0 == S_ISDIR(node_stat.st_mode)) {
					continue;
				}
				sprintf(temp_path, "%s/%d/%s/temp.dat", g_dest_path, hash_num,
						first_domain);
				fp1 = fopen(temp_path, "a+");
				if (NULL == fp1) {
					continue;
				}
				if (1 != str_hash_add(g_hash_table, first_domain, &fp1)) {
					b_fopen = TRUE;
				}
			} else {
				fp1 = *fp_hash;
			}
			/* 
			 * write parsed rseult into file, each rcpt
			 * address takes one item 
			 */
			i = 0;
			while ('\0' != *ptr && i < 8) {
				tmp_item.time = item.time;
				tmp_item.ip = item.ip;
				memcpy(tmp_item.from, item.from, 64);
				memcpy(tmp_item.to, ptr, 64);
				tmp_item.type = item.type;
				tmp_item.queue_id = item.queue_id;

				fwrite(&tmp_item, 1, sizeof(tmp_item), fp1);
				i ++;
				ptr += 64;
			}
			if (TRUE == b_fopen) {
				fclose(fp1);
			}
		}
		fclose(fp);
		
		/* open the DELIVERY log of today */
		sprintf(temp_path, "%s/%s/logs/delivery/delivery_log%s.txt",
			g_original_path, direntp->d_name, time_str);
		fp = fopen(temp_path, "r");
		if (NULL == fp) {
			continue;
		}
		/* parse each line in log file */
		while (NULL != fgets(temp_buff, 64*1024, fp)) {
			memset(&item, 0, sizeof(item));
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

			item.time = mktime(&tm_time);
			/* retrieve the source ipaddr */
			if (0 != strncmp(ptr, "SMTP message queue-ID: ", 23)) {
				continue;
			}
			ptr += 23;
			ptr1 = strchr(ptr, ',');
			if (NULL == ptr1) {
				continue;
			}
			*ptr1 = '\0';
			item.queue_id = atoi(ptr);
			ptr = ptr1 + 1;
			if (NULL != strstr(ptr, "message has been insulated ") ||
				NULL != (ptr1 = strstr(ptr, "there's no user in "
				"mail system"))) {
				/* get "from" name for comparing */
				ptr1 = strstr(ptr, "FROM: ");
				if (NULL == ptr1) {
					continue;
				}
				ptr = ptr1 + 6;
				/* write first "to address" into data struct */
				ptr1 = strstr(ptr, ", TO: ");
				length = ptr1 - ptr;
				if (length >= 64 || length <= 0) {
					continue;
				}
				memcpy(item.from, ptr, length);
				HX_strlower(item.from);
				ptr = ptr1 + 6;
				ptr1 = strstr(ptr, " ");
				if (NULL == ptr1) {
					continue;
				}
				length = ptr1 - ptr;
				if (length >= 64 || length <= 0) {
					continue;
				}
				memcpy(item.to, ptr, length);
				HX_strlower(item.to);
				/* get "to domain" name */
				first_domain = strchr(item.to, '@');
				if (NULL == first_domain) {
					continue;
				}
				first_domain ++;
				if (NULL != strstr(temp_buff, "message has been insulated ")) {
					item.type = LOG_ITEM_SPAM_INSULATION;
				} else {
					item.type = LOG_ITEM_NO_USER;
				}
			} else {
				continue;
			}
			b_fopen = FALSE;
			fp_hash = (FILE**)str_hash_query(g_hash_table, first_domain);
			if (NULL == fp_hash) {
				/* get hash number of domain */
				hash_num = domain_classifier_hash_domain(first_domain)%
							g_hash_num;
				sprintf(temp_path, "%s/%d", g_dest_path, hash_num);
				if (0 != stat(temp_path, &node_stat)) {
					mkdir(temp_path, 0777);
				} else if (0 == S_ISDIR(node_stat.st_mode)) {
					continue;
				}
				sprintf(temp_path, "%s/%d/%s", g_dest_path, hash_num,
					first_domain); 
				if (0 != stat(temp_path, &node_stat)) {
					mkdir(temp_path, 0777);
				} else if (0 == S_ISDIR(node_stat.st_mode)) {
					continue;
				}
				sprintf(temp_path, "%s/%d/%s/temp.dat", g_dest_path, hash_num,
					first_domain);
				fp1 = fopen(temp_path, "a+");
				if (NULL == fp1) {
					continue;
				}
				if (1 != str_hash_add(g_hash_table, first_domain, &fp1)) {
					b_fopen = TRUE;
				}
			} else {
				fp1 = *fp_hash;
			}
				
			tmp_item.time = item.time;
			tmp_item.ip = item.ip;
			memcpy(tmp_item.from, item.from, 64);
			memcpy(tmp_item.to, item.to, 64);
			tmp_item.type = item.type;
			tmp_item.queue_id = item.queue_id;

			fwrite(&tmp_item, 1, sizeof(tmp_item), fp1);
			if (TRUE == b_fopen) {
				fclose(fp1);
			}
		}	
		fclose(fp);
	}				
	
	closedir(dirp);

	iter = str_hash_iter_init(g_hash_table);
	for (str_hash_iter_begin(iter); !str_hash_iter_done(iter);
		str_hash_iter_forward(iter)) {
		fp = *(FILE**)str_hash_iter_get_value(iter, NULL);
		fclose(fp);
		str_hash_iter_remove(iter);
	}
	str_hash_iter_free(iter);
	
	return 0;
}

static unsigned int domain_classifier_hash_domain(const char *domain_name)
{
	unsigned int sum;
	int len;

	len = strlen(domain_name);
	sum = 0;
	if (len >= sizeof(unsigned int)) {
		memcpy(&sum, domain_name, sizeof(unsigned int));
	} else {
		memcpy(&sum, domain_name, len);
	}
	return sum;
}

int domain_classifier_stop()
{
	if (NULL != g_hash_table) {
		str_hash_free(g_hash_table);
		g_hash_table = NULL;
	}
	domain_classifier_remove_inode("/tmp/posidon_cache");
	return 0;
}

void domain_classifier_free()
{
	g_original_path[0] = '\0';
	g_dest_path[0] = '\0';
}

static void domain_classifier_remove_inode(const char *path)
{
	DIR *dirp;
	char temp_path[256];
	struct dirent *direntp;
	struct stat node_stat;

	if (0 != stat(path, &node_stat)) {
		return;
	}
	if (0 == S_ISDIR(node_stat.st_mode)) {
		remove(path);
		return;
	}
	dirp = opendir(path);
	if (NULL == dirp) {
		return;
	}
	while ((direntp = readdir(dirp)) != NULL) {
		if (0 == strcmp(direntp->d_name, ".") ||
			0 == strcmp(direntp->d_name, "..")) {
			continue;
		}
		sprintf(temp_path, "%s/%s", path, direntp->d_name);
		domain_classifier_remove_inode(temp_path);
	}
	closedir(dirp);
	remove(path);
}



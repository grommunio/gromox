#include <unistd.h>
#include "auto_backup.h"
#include "file_operation.h"
#include "smtp_sender.h"
#include "util.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

static char g_config_path[256];
static char g_data_path[256];
static char g_backup_path[256];
static char g_admin_mailbox[256];
static char g_default_domain[256];

void auto_backup_init(const char *config_path, const char *data_path,
	const char *backup_path, const char *admin_mailbox, const char *default_domain)
{
	strcpy(g_config_path, config_path);
	strcpy(g_data_path, data_path);
	strcpy(g_backup_path, backup_path);
	strcpy(g_admin_mailbox, admin_mailbox);
	strcpy(g_default_domain, default_domain);
}

int auto_backup_run()
{
	int fd, len;
	size_t encode_len;
	time_t now_time;
	char temp_buff[256];
	char dst_dir[256];
	char src_file[256];
	char dst_file[256];
	char *pbuff, *pdomain;
	struct stat node_stat;

	sprintf(dst_dir, "%s/data_files", g_backup_path);
	mkdir(dst_dir, 0777);

	sprintf(src_file, "%s/area_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/area_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/cidb_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/cidb_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/boundary_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/boundary_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/dns_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/dns_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/domain_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/domain_mailbox.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_mailbox.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/domain_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/domain_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/dynamic_dnslist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/dynamic_dnslist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/forward_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/forward_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/from_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/from_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/from_replace.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/from_replace.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ip_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ip_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ip_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ip_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/ipdomain_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/ipdomain_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/keyword_group.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_group.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/keyword_charset.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_charset.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_subject.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_subject.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_from.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_from.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_to.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_to.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_cc.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_cc.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_content.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_content.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	sprintf(src_file, "%s/keyword_attachment.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/keyword_attachment.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/system_sign", g_data_path);
	sprintf(dst_file, "%s/data_files/system_sign", g_backup_path);
	file_operation_copy_dir(src_file, dst_file);

	sprintf(src_file, "%s/rcpt_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/rcpt_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/relay_allow.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_allow.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/relay_domains.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_domains.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/relay_table.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/relay_table.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/single_rcpt.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/single_rcpt.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/supervising_list.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/supervising_list.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/system_users.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/system_users.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(src_file, "%s/tagging_whitelist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/tagging_whitelist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);
	
	sprintf(src_file, "%s/xmailer_blacklist.txt", g_data_path);
	sprintf(dst_file, "%s/data_files/xmailer_blacklist.txt", g_backup_path);
	file_operation_copy_file(src_file, dst_file);

	sprintf(dst_file, "%s/data_files/sa.cfg", g_backup_path);
	file_operation_copy_file(g_config_path, dst_file);
	
	
	sprintf(dst_file, "%s/auto_backup.tgz", g_backup_path);
	file_operation_compress(dst_dir, dst_file);
	file_operation_remove_dir(dst_dir);

	
	pdomain = strchr(g_admin_mailbox, '@');
	if (NULL == pdomain) {
		remove(dst_file);
		return 0;
	}
	pdomain ++;
	
	if (0 != stat(dst_file, &node_stat)) {
		remove(dst_file);
		return 0;
	}
	pbuff = (char*)malloc(3*node_stat.st_size + 4096);
	if (NULL == pbuff) {
		remove(dst_file);
		return 0;
	}
	fd = open(dst_file, O_RDONLY);
	if (-1 == fd) {
		free(pbuff);
		remove(dst_file);
		return 0;
	}
	if (node_stat.st_size != read(fd, pbuff, node_stat.st_size)) {
		close(fd);
		free(pbuff);
		remove(dst_file);
		return 0;
	}
	close(fd);
	
	time(&now_time);	
	strftime(temp_buff, 128, "%a, %d %b %Y %H:%M:%S %z", localtime(&now_time));
	len = sprintf(pbuff + node_stat.st_size, 
			"Received: from unknown (helo localhost) (unkown@127.0.0.1)"
			"\r\n\tby herculiz with SMTP\r\n");
	len += sprintf(pbuff + node_stat.st_size + len,
			"From: <auto-backup@system.mail>\r\n"
			"To: <%s>\r\n"
			"Subject: Mail system automatic backup of %s\r\n"
			"Date: %s\r\n"
			"Content-Transfer-Encoding: base64\r\n"
			"Content-Type: application/gzip;\r\n"
			"\tname=\"system_config.tgz\"\r\n"
			"Content-Disposition: attachment;\r\n"
			"\tfilename=\"system_config.tgz\r\n\r\n",
			g_admin_mailbox, g_default_domain, temp_buff);
	if (0 != encode64_ex(pbuff, node_stat.st_size, pbuff + node_stat.st_size + 
		len, 2*node_stat.st_size + 4096 - len, &encode_len)) {
		free(pbuff);
		remove(dst_file);
		return 0;
	}
	len += encode_len;
	
	if (0 == strcasecmp(pdomain, g_default_domain)) {
		smtp_sender_send("auto-backup@system.mail", g_admin_mailbox,
			pbuff + node_stat.st_size, len);
	} else {
		sprintf(temp_buff, "auto-backup@%s", g_default_domain);
		smtp_sender_send(temp_buff, g_admin_mailbox,
			pbuff + node_stat.st_size, len);
	}
	
	free(pbuff);
	remove(dst_file);
	return 0;
}

int auto_backup_stop()
{
	return 0;
}

void auto_backup_free()
{
	/* do nothing */
}



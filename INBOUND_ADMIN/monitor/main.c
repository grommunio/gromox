#include "single_list.h"
#include "util.h"
#include "list_file.h"
#include "config_file.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MONITOR_VERSION		"1.0"
#define SHARE_MEMORY_SIZE	64*1024
#define STATISTIC_COMMAND	"spam_statistic.svc status\r\n"
#define SYSTEM_COMMAND		"system status\r\n"
#define STATUS_COMMAND		"status_forms.hook status\r\n"
#define CALCULATE_INTERVAL(a, b)	\
		((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec


typedef struct _CONSOLE_PORT {
	SINGLE_LIST_NODE node;
	pthread_t tid;
	BOOL notify_stop;
	int index;
	char smtp_ip[16];
	int smtp_port;
	char delivery_ip[16];
	int delivery_port;
} CONSOLE_PORT;

static int *g_shm_begin;
static BOOL g_notify_stop;

static void term_handler(int signo);

static void* thread_work_func(void *arg);

static int parse_statistic(char *buff_in, int *items);

static void parse_connection(char *buff_in, int *connection);

static void parse_status(char *buff_in, int *cpu, int *network);

static void flush_data(int index, int cpu, int network, int connection,
	int ham, int spam);

int main(int argc, char **argv)
{
	int i;
	int shm_id;
	int list_len;
	key_t k_shm;
	char *pitem;
	char *str_value;
	char temp_path[256];
	char data_path[256];
	char token_path[256];
	SINGLE_LIST_NODE *pnode;
	SINGLE_LIST console_list;
	LIST_FILE *plist_file;
	CONFIG_FILE *pconfig_file;
	CONSOLE_PORT *pconsole;
	
	if (2 != argc) {
		printf("%s <cfg file>\n", argv[0]);
		return -1;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("%s <cfg file>\n", argv[0]);
		return 0;
	}
	if (2 == argc && 0 == strcmp(argv[1], "--version")) {
		printf("version: %s\n", MONITOR_VERSION);
		return 0;
	}
	signal(SIGPIPE, SIG_IGN);
	pconfig_file = config_file_init(argv[1]);
	if (NULL == pconfig_file) {
		printf("[system]: fail to open config file %s\n", argv[1]);
		return -2;
	}
	str_value = config_file_get_value(pconfig_file, "DATA_FILE_PATH");
	if (NULL == str_value) {
		strcpy(data_path, "../data");
		config_file_set_value(pconfig_file, "DATA_FILE_PATH", "../data");
	} else {
		strcpy(data_path, str_value);
	}
	printf("[system]: data path is %s\n", data_path);
	str_value = config_file_get_value(pconfig_file, "TOKEN_FILE_PATH");
	if (NULL == str_value) {
		strcpy(token_path, "../token");
		config_file_set_value(pconfig_file, "TOKEN_FILE_PATH", "../token");
	} else {
		strcpy(token_path, str_value);
	}
	printf("[system]: token path is %s\n", token_path);
	config_file_save(pconfig_file);
	config_file_free(pconfig_file);

	sprintf(temp_path, "%s/monitor.shm", token_path);
	k_shm = ftok(temp_path, 1);
	if (-1 == k_shm) {
		printf("[system]: cannot get key for share memory from %s\n",
			temp_path);
		return -3;
	}
	shm_id = shmget(k_shm, SHARE_MEMORY_SIZE, 0666);
	if (-1 == shm_id) {
		shm_id = shmget(k_shm, SHARE_MEMORY_SIZE, 0666|IPC_CREAT);
	}
	if (-1 == shm_id) {
		printf("[system]: fail to get or create share memory\n");
		return -4;
	}
	g_shm_begin = shmat(shm_id, NULL, 0);
	if (NULL == g_shm_begin) {
		printf("[system]: fail to attach share memory\n");
		return -5;
	}
	memset(g_shm_begin, 0, SHARE_MEMORY_SIZE);
	sprintf(temp_path, "%s/console_table.txt", data_path);
	plist_file = list_file_init(temp_path, "%s:16%d%s:16%d");
	if (NULL == plist_file) {
		printf("[system]: fail to open console list file %s\n", temp_path);
		return -6;
	}
	single_list_init(&console_list);
	pitem = (char*)list_file_get_list(plist_file);
	list_len = list_file_get_item_num(plist_file);
	if (list_len > (SHARE_MEMORY_SIZE - sizeof(int))/(5*sizeof(int))) {
		list_file_free(plist_file);
		printf("[system]: too many console unit!\n");
		return -7;
	}
	for (i=0; i<list_len; i++) {
		pconsole = (CONSOLE_PORT*)malloc(sizeof(CONSOLE_PORT));
		if (NULL== pconsole) {
			continue;
		}
		pconsole->node.pdata = pconsole;
		pconsole->notify_stop = FALSE;
		pconsole->index = i;
		strcpy(pconsole->smtp_ip, pitem);
		pconsole->smtp_port = *(int*)(pitem + 16);
		strcpy(pconsole->delivery_ip, pitem + 16 + sizeof(int));
		pconsole->delivery_port = *(int*)(pitem + 32 + sizeof(int));
		pitem += 32 + 2*sizeof(int);
		pthread_create(&pconsole->tid, NULL, thread_work_func, pconsole);
		single_list_append_as_tail(&console_list, &pconsole->node);
	}
	*g_shm_begin = list_len;
	list_file_free(plist_file);

	g_notify_stop = FALSE;
	signal(SIGTERM, term_handler);
	printf("[system]: MONITOR is now rinning\n");
	while (FALSE == g_notify_stop) {
		sleep(1);
	}
	while (pnode=single_list_get_from_head(&console_list)) {
		pconsole = (CONSOLE_PORT*)pnode->pdata;
		pconsole->notify_stop = TRUE;
		pthread_join(pconsole->tid, NULL);
		free(pconsole);
	}
	shmdt(g_shm_begin);
	return 0;
	
}
static void term_handler(int signo)
{
	g_notify_stop = TRUE;
}

static void* thread_work_func(void *arg)
{
	int i;
	int ham_num;
	int spam_num;
	int smtp_num;
	int delivery_num;
	int cpu_val;
	int network_val;
	int connection_val;
	int sockd_smtp = -1;
	int sockd_delivery = -1;
	int read_len, offset;
	int smtp_items[1024];
	int delivery_items[1024];
	unsigned long time_interval;
	char temp_buff[65536];
	char read_buff[1024];
	struct timeval last_tm;
	struct timeval current_tm;
	CONSOLE_PORT *pconsole;
	
	pconsole = (CONSOLE_PORT*)arg;
	while (FALSE == pconsole->notify_stop) {
		if (-1 == sockd_smtp) {
			flush_data(pconsole->index, -1, -1, -1, -1, -1);
			sleep(1);
			sockd_smtp = connect_console(pconsole->smtp_ip,
							pconsole->smtp_port);
			if (-1 == sockd_smtp) {
				continue;
			}
		}
		if (-1 == sockd_delivery) {
			flush_data(pconsole->index, -1, -1, -1, -1, -1);
			sleep(1);
			sockd_delivery = connect_console(pconsole->delivery_ip,
								pconsole->delivery_port);
			if (-1 == sockd_delivery) {
				continue;
			}
		}
		gettimeofday(&last_tm, NULL);
		
		if (sizeof(STATISTIC_COMMAND) != write(sockd_smtp, STATISTIC_COMMAND,
			sizeof(STATISTIC_COMMAND))) {
			close(sockd_smtp);
			sockd_smtp = -1;
			continue;
		}
		read_len = read(sockd_smtp, temp_buff, 65536);
		if (0 == read_len || -1 == read_len) {
			close(sockd_smtp);
			sockd_smtp = -1;
			continue;
		}
		temp_buff[read_len] = '\0';
		if (NULL == strstr(temp_buff, "console>")) {
			read(sockd_smtp, read_buff, 1024);
		}
		smtp_num = parse_statistic(temp_buff, smtp_items);
		if (sizeof(SYSTEM_COMMAND) != write(sockd_smtp, SYSTEM_COMMAND,
			sizeof(SYSTEM_COMMAND))) {
			close(sockd_smtp);
			sockd_smtp = -1;
			continue;
		}
		read_len = read(sockd_smtp, temp_buff, 65536);
		if (0 == read_len || -1 == read_len) {
			close(sockd_smtp);
			sockd_smtp = -1;
			continue;
		}
		temp_buff[read_len] = '\0';
		if (NULL == strstr(temp_buff, "console>")) {
			read(sockd_smtp, read_buff, 1024);
		}
		parse_connection(temp_buff, &connection_val);
		if (sizeof(STATISTIC_COMMAND) != write(sockd_delivery,
			STATISTIC_COMMAND, sizeof(STATISTIC_COMMAND))) {
			close(sockd_delivery);
			sockd_delivery = -1;
			continue;
		}
		read_len = read(sockd_delivery, temp_buff, 65536);
		if (0 == read_len || -1 == read_len) {
			close(sockd_delivery);
			sockd_delivery = -1;
			continue;
		}
		temp_buff[read_len] = '\0';
		if (NULL == strstr(temp_buff, "console>")) {
			read(sockd_delivery, read_buff, 1024);
		}
		delivery_num = parse_statistic(temp_buff, delivery_items);
		if (sizeof(STATUS_COMMAND) != write(sockd_delivery, STATUS_COMMAND,
			sizeof(STATUS_COMMAND))) {
			close(sockd_delivery);
			sockd_delivery = -1;
			continue;
		}
		read_len = read(sockd_delivery, temp_buff, 65536);
		if (0 == read_len || -1 == read_len) {
			close(sockd_delivery);
			sockd_delivery = -1;
			continue;
		}
		temp_buff[read_len] = '\0';
		if (NULL == strstr(temp_buff, "console>")) {
			read(sockd_delivery, read_buff, 1024);
		}
		parse_status(temp_buff, &cpu_val, &network_val);
		spam_num = 0;
		ham_num = delivery_items[0];
		for (i=1; i<smtp_num; i++) {
			spam_num += smtp_items[i];
		}
		for (i=1; i<delivery_num; i++) {
			spam_num += delivery_items[i];
		}
		flush_data(pconsole->index, cpu_val, network_val, connection_val, 
			ham_num, spam_num);
		gettimeofday(&current_tm, NULL);
		time_interval = CALCULATE_INTERVAL(current_tm, last_tm);
		if (time_interval < 1000000) {
			usleep(1000000 - time_interval);
		}
	}
	if (-1 != sockd_smtp) {
		write(sockd_smtp, "quit\r\n", 6);
		close(sockd_smtp);
		sockd_smtp = -1;
	}
	if (-1 != sockd_delivery) {
		write(sockd_smtp, "quit\r\n", 6);
		close(sockd_delivery);
		sockd_delivery = -1;
	}
}

int connect_console(const char *ip, int port)
{
	int sockd;
	int offset, read_len;
	char temp_buff[1024];
	struct sockaddr_in servaddr;
	
	sockd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	if (0 != connect(sockd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
		close(sockd);
		return -1;
	}
	
	offset = 0;
	memset(temp_buff, 0, 1024);
	/* read welcome information */
	do {
		read_len = read(sockd, temp_buff + offset, 1024 - offset);
		if (-1 == read_len || 0 == read_len) {
			close(sockd);
			return -1;
		}
		offset += read_len;
		if (NULL != search_string(temp_buff, "console> ", offset)) {
			break;
		}
	} while (offset < 1024);
	if (offset >= 1024) {
		close(sockd);
		return -1;
	}
	return sockd;
}

static int parse_statistic(char *buff_in, int *items)
{
	char *temp_ptr;
	char temp_buff[64];
	int buff_len, last_crlf;
	int  start_pos, end_pos;
	int i, j, item_num, temp_len; 
	
	buff_len = strlen(buff_in);
	for (i=0; i<buff_len; i++) {
		if ('\n' == buff_in[i]) {
			break;
		}
	}
	if (i == buff_len) {
		return 0;
	}
	start_pos = i + 1;
	temp_ptr = strstr(buff_in, "* last statistic time:");
	if (NULL == temp_ptr) {
		return 0;
	}
	end_pos = temp_ptr - buff_in;
	
	for (i=start_pos,last_crlf=start_pos-1,item_num=0; i<end_pos; i++) {
		if ('\r' == buff_in[i]) {
			for (j=i; j>last_crlf; j--) {
				if (' ' == buff_in[j]) {
					break;
				}
			}
			if (j > last_crlf) {
				if (i - j - 1 >= 64) {
					return 0;
				}
				memcpy(temp_buff, buff_in + j + 1, i - j - 1);
				temp_buff[i - j - 1] = '\0';
				items[item_num] = atoi(temp_buff);
				item_num ++;
			}
			last_crlf = i + 1;
		}
	}
	return item_num;
}

static void parse_connection(char *buff_in, int *connection)
{
	char *ptr, *ptr1;
	int parsing_num;
	int flushing_num;
	
	*connection = 0;
	ptr = strstr(buff_in, "current parsing contexts     ");
	if (NULL == ptr) {
		return;
	}
	ptr += 29;
	ptr1 = strchr(ptr, '\n');
	if (NULL == ptr1) {
		return;
	}
	*ptr1 = '\0';
	parsing_num = atoi(ptr);
	ptr = ptr1 + 1;
	ptr = strstr(ptr, "current flushing contexts    ");
	if (NULL == ptr) {
		return;
	}
	ptr += 29;
	ptr1 = strchr(ptr, '\n');
	if (NULL == ptr1) {
		return;
	}
	*ptr1 = '\0';
	flushing_num = atoi(ptr);
	*connection = parsing_num + flushing_num;
}

static void parse_status(char *buff_in, int *cpu, int *network)
{
	char *ppercent;
	char *temp_ptr;
	char *last_ptr;
	char temp_buff[128];
	int temp_len;
	int buff_len;
	int start_pos;
	int end_pos;
	
	*cpu = 0;
	*network = 0;
	last_ptr = 0;
	buff_len = strlen(buff_in);
	temp_ptr = strstr(buff_in, "250 ");
	if (NULL == temp_ptr) {
		return;
	}
	temp_ptr = strstr(temp_ptr, "\r\n");
	if (NULL == temp_ptr) {
		return;
	}
	last_ptr = temp_ptr + 2;
	start_pos = last_ptr - buff_in;
	temp_ptr = strstr(last_ptr, "\r\n");
	if (NULL == temp_ptr) {
		return;
	}
	end_pos = temp_ptr - buff_in;
	
	temp_len = end_pos - start_pos;
	if (temp_len > 127) {
		temp_len = 127;
	}
	memcpy(temp_buff, last_ptr, temp_len);
	temp_buff[temp_len] = '\0';
	ppercent = strchr(temp_buff, '%');
	if (NULL == ppercent) {
		return;
	}
	*ppercent = '\0';
	*cpu = atoi(temp_buff);
	for (temp_ptr=ppercent+1; temp_ptr<temp_buff+temp_len; temp_ptr++) {
		if (*temp_ptr != ' ') {
			break;
		}
	}
	if (temp_ptr == temp_buff + temp_len) {
		return;
	}
	*network = atoi(temp_ptr);
}

static void flush_data(int index, int cpu, int network, int connection,
	int ham, int spam)
{
	int *punit;
	
	punit = g_shm_begin + 1 + index * 5;
	*punit = cpu;
	punit ++;
	*punit = network;
	punit ++;
	*punit = connection;
	punit ++;
	*punit = ham;
	punit ++;
	*punit = spam;
}


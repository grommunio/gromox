/*
 *                 +++++++++++++    when SIGTERM is sent to deamon, it will be
 *                 +  ancestor +    broadcasted to supervisors and by theses
 *                 +++++++++++++    supervisors, the signal will be relayed
 *                       |          to SMTP and DELIVERY
 *                       |
 *                 +++++++++++++    when the program is started, ancestor forks
 *                 +   daemon  +    daemon, and daemon forks two supervisors,
 *                 +++++++++++++    one supervises SMTP and another supervises
 *                   |       |      DELIVERY.
 *                   |       |                  
 *         +++++++++++++   +++++++++++++        
 *         + supervisor+   + supervisor+        
 *         +++++++++++++   +++++++++++++
 *               |               |
 *               |               |
 *         +++++++++++++   +++++++++++++
 *         +   SMTP    +   + DELIVERY  +
 *         +++++++++++++   +++++++++++++
 */
#include <time.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define TOKEN_MONITOR_QUEUE     100

typedef struct _MSG_BUFF {
	long msg_type;
	int msg_tick;
} MSG_BUFF;

static char QUEUE_MESS_PATH[256];
static char QUEUE_SAVE_PATH[256];
static char MONITOR_TOKEN_FILE[256];
static char PID_LOCK_FILE[256];
static char SMTP_LOG_FILE[256];
static char DELIVERY_LOG_FILE[256];
static char HERCULIZ_MAIN_DIR[256];

static int g_token_fd;
static int g_notify_stop;
static pid_t g_smtp_supervisor;
static pid_t g_delivery_supervisor;
static pid_t g_supervised_process;
static char *opt_path;

static struct HXoption g_options_table[] = {
	{.sh = 'p', .type = HXTYPE_STRING, .ptr = &opt_path, .help = "Path to Gromox binaries", .htyp = "DIR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

/*
 *	set the stop flag and relay signal to supervised process
 *	@param
 *		sig			signal type
 */
void supervisor_sigstop(int sig)
{
	g_notify_stop = 1;
	if (g_supervised_process > 0) {
		kill(g_supervised_process, SIGTERM);
	}
}

/*
 *	make the supervised process stop, and the supervised process will be
 *	started again by supervisor process
 *	@param
 *		sig			signal type
 */
void supervisor_sigrestart(int sig)
{
	if (g_supervised_process > 0) {
		kill(g_supervised_process, SIGKILL);
	}
}

/*
 *	stop the daemon process, the signal will also be relayed to supervisors
 *	@param
 *		sig			signal type
 */
void daemon_sigstop(int sig)
{
	g_notify_stop = 1;
	if (g_smtp_supervisor > 0) {
		kill(g_smtp_supervisor, SIGTERM);
	}
	if (g_delivery_supervisor > 0) {
    	kill(g_delivery_supervisor, SIGTERM);
	}
}


/*
 *	start smtp service
 */
void start_smtp()
{
	int fd, status;
	struct stat node_stat;
	const char *args[] = {"smtp", NULL};

	if (0 != stat(SMTP_LOG_FILE, &node_stat) 
		|| node_stat.st_size > 128*1024*1024) {
		fd = open(SMTP_LOG_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0666);
		close(fd);
	}
	g_smtp_supervisor = fork();
	if (g_smtp_supervisor < 0) {
		exit(EXIT_FAILURE);
	} else if (0 == g_smtp_supervisor) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				fd = open(SMTP_LOG_FILE, O_WRONLY|O_APPEND);
				close(STDOUT_FILENO);
				dup2(fd, STDOUT_FILENO);
				close(fd);
				chdir(HERCULIZ_MAIN_DIR);
				execve("./smtp", const_cast(char **, args), NULL);
				_exit(-1);
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *	start delivery service
 */
void start_delivery()
{
	DIR *dirp;
	char temp_path[256];
	char save_name[256];
	struct dirent *direntp;
	struct stat node_stat;
	time_t start_points[3];
	int fd, status, start_times;
	const char *args[] = {"delivery", NULL};

	if (0 != stat(DELIVERY_LOG_FILE, &node_stat)
		|| node_stat.st_size > 128*1024*1024) {
		fd = open(DELIVERY_LOG_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0666);
		close(fd);
	}
	g_delivery_supervisor = fork();
	if (g_delivery_supervisor < 0) {
		exit(EXIT_FAILURE);
	} else if (0 == g_delivery_supervisor) {
		g_notify_stop = 0;
		start_times = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				fd = open(DELIVERY_LOG_FILE, O_WRONLY|O_APPEND);
				close(STDOUT_FILENO);
				dup2(fd, STDOUT_FILENO);
				close(fd);
				chdir(HERCULIZ_MAIN_DIR);
				execve("./delivery", const_cast(char **, args), NULL);
				_exit(-1);
			} else if (g_supervised_process > 0) {
				time(&start_points[start_times]);
				waitpid(g_supervised_process, &status, 0);
				start_times ++;
				if (3 == start_times) {
					if (start_points[2] - start_points[0] <= 600) {
						dirp = opendir(QUEUE_MESS_PATH);
						while ((direntp = readdir(dirp)) != NULL) {
							if (strcmp(direntp->d_name, ".") == 0 ||
							    strcmp(direntp->d_name, "..") == 0)
								continue;
							sprintf(temp_path, "%s/%s", QUEUE_MESS_PATH,
								direntp->d_name);
							sprintf(save_name, "%s/%s", QUEUE_SAVE_PATH,
								direntp->d_name);
							link(temp_path, save_name);
							remove(temp_path);
						}
						closedir(dirp);
						start_times = 0;
					} else {
						start_points[0] = start_points[1];
						start_points[1] = start_points[2];
						start_times = 2;
					}
				}
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *	start smtp and delivery services
 */
void start_service()
{
	time_t expect_tick, current_tick;
	pid_t pid, sid; /* process ID and session ID */
	int fd, monitor_id;
	char str[16];
	key_t k_msg;
	MSG_BUFF msg;


	pid = fork();
	if (pid < 0) {
		printf("fail to fork the child process\n");
        exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	/* child (daemon) continues */
	/* obtain a new process group */
	sid = setsid();
	if (sid < 0) {
        printf("fail to create new session ID\n");
        exit(EXIT_FAILURE);
    }
	for (fd=getdtablesize(); fd>=0; fd--) {
		if (STDOUT_FILENO != fd) {
			close(fd); /* close all descriptors */
		}
	}
	/* check if the process is running uniquely */
	g_token_fd = open(PID_LOCK_FILE, O_RDWR|O_CREAT, 0640);
	/* can not open */
	if (g_token_fd < 0) {
		printf("cannot open the %s\n", PID_LOCK_FILE);
		exit(EXIT_FAILURE);
	}
	/* can not lock */
	if (lockf(g_token_fd, F_TLOCK, 0) < 0 ) {
		printf("there's another instance is running in system\n");
		close(g_token_fd);
		exit(EXIT_FAILURE);
	}
	/* first instance continues */
	sprintf(str,"%d\n",getpid());
	write(g_token_fd, str, strlen(str));
	fsync(g_token_fd);
	/* record pid to lockfile */
	/* handle standart I/O */

	/* close the STDOUT_FILENO */
	close(STDOUT_FILENO);
	fd = open("/dev/null",O_RDWR);
	dup(fd);
	dup(fd);
	/* change the file mode mask */
	umask(0);
	/* change running directory */
	chdir("/tmp");
	signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU, SIG_IGN); /* ignore tty signals */
	signal(SIGTTIN, SIG_IGN); /* ignore tty signals */
	signal(SIGTERM, daemon_sigstop);    /* catch term signal */


	start_delivery();
	start_smtp();

	k_msg = ftok(MONITOR_TOKEN_FILE, TOKEN_MONITOR_QUEUE);
	if (-1 == k_msg) {
		goto WAIT_WITHOUT_MONITOR;
	}
	monitor_id = msgget(k_msg, 0666|IPC_CREAT);
	if (-1 == monitor_id) {
		goto WAIT_WITHOUT_MONITOR;
	}
	time(&expect_tick);
	expect_tick = expect_tick/180 + 1;
	while (0 == g_notify_stop) {
		if (-1 != msgrcv(monitor_id, &msg, sizeof(int), 0, IPC_NOWAIT)) {
			time(&expect_tick);
			expect_tick = expect_tick/180 + 1;
		} else {
			time(&current_tick);
			current_tick /= 180;
			if (current_tick > expect_tick) {
				kill(g_smtp_supervisor, SIGALRM);
				kill(g_delivery_supervisor, SIGALRM);
				time(&expect_tick);
				expect_tick = expect_tick/180 + 1;
			}
		}
		sleep(1);
	}
WAIT_WITHOUT_MONITOR:
	while (0 == g_notify_stop) {
		sleep(1);
	}
	lockf(g_token_fd, F_ULOCK, 0);
	close(g_token_fd);
	remove(PID_LOCK_FILE);
	exit(EXIT_SUCCESS);
}

/*
 *	stop the daemon
 */
void stop_service()
{
	int fd;
    pid_t pid;
    char str[32];

	fd = open(PID_LOCK_FILE, O_RDONLY);
	if (fd < 0) {
		printf("herculiz is not running\n");
		exit(EXIT_SUCCESS);
	}
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("fail to get herculiz's pid\n");
		exit(EXIT_FAILURE);
	}
	kill(pid, SIGTERM);
	exit(EXIT_SUCCESS);
}

/*
 *	print the daemon status
 */
void status_service()
{
	int fd;
    pid_t pid;
    char str[32];
    struct stat node_stat;

	if (0 != stat(PID_LOCK_FILE, &node_stat)) {
		printf("herculiz is not running\n");
		exit(EXIT_SUCCESS);
	}
	fd = open(PID_LOCK_FILE, O_RDONLY);
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("herculiz is not running\n");
		exit(EXIT_SUCCESS);
	}
	sprintf(str, "ps -p %d > /dev/null", pid);
	if (0 == WEXITSTATUS(system(str))) {
		printf("herculiz (pid: %d) is running\n", pid);
	} else {
		printf("herculiz is not running\n");
	}
	exit(EXIT_SUCCESS);
}

/*
 *	restart the daemon
 */
void restart_service()
{
	int i, fd;
    pid_t pid;
    char str[32];

	fd = open(PID_LOCK_FILE, O_RDONLY);
	if (fd < 0) {
		printf("herculiz is not running\n");
		exit(EXIT_FAILURE);
	}
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("herculiz is not running\n");
		exit(EXIT_FAILURE);
	}
	kill(pid, SIGTERM);
	sprintf(str, "ps -p %d > /dev/null", pid);
	for (i=0; i<20; i++) {
	    if (0 != WEXITSTATUS(system(str))) {
			break;
		}
		sleep(3);
	}
	if (20 == i) {
		printf("cannot stop herculiz\n");
		exit(EXIT_FAILURE);
	}
	sleep(3);
	start_service();
}

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) != HXOPT_ERR_SUCCESS)
		return EXIT_FAILURE;
	if (opt_path == NULL) {
		printf("You need to specify the -p option.\n");
		return 1;
	}
	if (argc != 2) {
		printf("usage: %s -p path {start|stop|restart|status}\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	sprintf(QUEUE_MESS_PATH, "%s/queue/mess", opt_path);
	sprintf(QUEUE_SAVE_PATH, "%s/queue/save", opt_path);
	sprintf(MONITOR_TOKEN_FILE, "%s/queue/token.ipc", opt_path);
	sprintf(PID_LOCK_FILE, "%s/queue/token.pid", opt_path);
	sprintf(SMTP_LOG_FILE, "%s/logs/smtp_running.log", opt_path);
	sprintf(DELIVERY_LOG_FILE, "%s/logs/delivery_running.log", opt_path);
	sprintf(HERCULIZ_MAIN_DIR, "%s/bin", opt_path);
	if (strcmp(argv[1], "start") == 0) {
		start_service();
	} else if (strcmp(argv[1], "stop") == 0) {
		stop_service();
	} else if (strcmp(argv[1], "restart") == 0) {
		restart_service();
	} else if (strcmp(argv[1], "status") == 0) {
		status_service();
	} else {
		printf("unknown command %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
}


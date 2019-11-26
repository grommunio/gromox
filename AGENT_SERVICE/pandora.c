#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define TOKEN_CONTROL				100
#define CTRL_RESTART_AMYSQL			1
#define CTRL_RESTART_ASESSION		2
#define CTRL_RESTART_ALOCK			3
#define CTRL_RESTART_ASENSOR		4
#define CTRL_RESTART_AMIDB			5

static char PID_LOCK_FILE[256];
static char PANDORA_MAIN_DIR[256];
static char CONTROL_TOKEN_FILE[256];

static int g_token_fd;
static int g_notify_stop;
static pid_t g_amysql_pid;
static pid_t g_asession_pid;
static pid_t g_alock_pid;
static pid_t g_asensor_pid;
static pid_t g_amidb_pid;
static pid_t g_supervised_process;


/*
 *  set the stop flag and relay signal to supervised process
 *  @param
 *      sig         signal type
 */
void supervisor_sigstop(int sig)
{
	g_notify_stop = 1;
	if (g_supervised_process > 0) {
		kill(g_supervised_process, SIGTERM);
	}
}

/*
 *  make the supervised process stop, and the supervised process will be
 *  started again by supervisor process
 *  @param
 *      sig         signal type
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
	if (g_amysql_pid > 0) {
		kill(g_amysql_pid, SIGTERM);
	}
	if (g_asession_pid > 0) {
		kill(g_asession_pid, SIGTERM);
	}
	if (g_alock_pid > 0) {
		kill(g_alock_pid, SIGTERM);
	}
	if (g_asensor_pid > 0) {
		kill(g_asensor_pid, SIGTERM);
	}
	if (g_amidb_pid > 0) {
		kill(g_amidb_pid, SIGTERM);
	}
}

/*
 *  start amysql service
 */
void start_amysql()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	char *args[] = {"./amysql", "../config/pandora.cfg", NULL};

	sprintf(temp_path, "%s/amysql", PANDORA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_amysql_pid = -1;
		return;
	}
	g_amysql_pid = fork();
	if (g_amysql_pid < 0) {
		return;
	} else if (0 == g_amysql_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(PANDORA_MAIN_DIR);
				if (execve("./amysql", args, NULL) == -1) {
					exit(EXIT_FAILURE);
				}
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}


/*
 *  start asession service
 */
void start_asession()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	char *args[] = {"./asession", "../config/pandora.cfg", NULL};

	sprintf(temp_path, "%s/asession", PANDORA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_asession_pid = -1;
		return;
	}
	g_asession_pid = fork();
	if (g_asession_pid < 0) {
		return;
	} else if (0 == g_asession_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(PANDORA_MAIN_DIR);
				if (execve("./asession", args, NULL) == -1) {
					exit(EXIT_FAILURE);
				}
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *  start alock service
 */
void start_alock()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	char *args[] = {"./alock", "../config/pandora.cfg", NULL};

	sprintf(temp_path, "%s/alock", PANDORA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_alock_pid = -1;
		return;
	}
	g_alock_pid = fork();
	if (g_alock_pid < 0) {
		return;
	} else if (0 == g_alock_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(PANDORA_MAIN_DIR);
				if (execve("./alock", args, NULL) == -1) {
					exit(EXIT_FAILURE);
				}
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *  start asensor service
 */
void start_asensor()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	char *args[] = {"./asensor", "../config/pandora.cfg", NULL};

	sprintf(temp_path, "%s/asensor", PANDORA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_asensor_pid = -1;
		return;
	}
	g_asensor_pid = fork();
	if (g_asensor_pid < 0) {
		return;
	} else if (0 == g_asensor_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(PANDORA_MAIN_DIR);
				if (execve("./asensor", args, NULL) == -1) {
					exit(EXIT_FAILURE);
				}
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *  start amidb service
 */
void start_amidb()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	char *args[] = {"./amidb", "../config/pandora.cfg", NULL};

	sprintf(temp_path, "%s/amidb", PANDORA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_amidb_pid = -1;
		return;
	}
	g_amidb_pid = fork();
	if (g_amidb_pid < 0) {
		return;
	} else if (0 == g_amidb_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(PANDORA_MAIN_DIR);
				if (execve("./amidb", args, NULL) == -1) {
					exit(EXIT_FAILURE);
				}
			} else if (g_supervised_process > 0) {
				waitpid(g_supervised_process, &status, 0);
			}
			sleep(1);
		}
		exit(EXIT_SUCCESS);
	}
}

/*
 *	start services
 */
void start_service()
{
	pid_t pid, sid; /* process ID and session ID */
	int ctrl_id, fd;
	char str[16];
	key_t k_ctrl;
	long ctrl_type;


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
	
	start_amysql();
	start_asession();
	start_alock();
	start_asensor();
	start_amidb();
	

	k_ctrl = ftok(CONTROL_TOKEN_FILE, TOKEN_CONTROL);
	if (-1 == k_ctrl) {
		ctrl_id = -1;
	} else {
		ctrl_id = msgget(k_ctrl, 0666|IPC_CREAT);
	}
	
	while (0 == g_notify_stop) {
		if (-1 != ctrl_id && -1 != msgrcv(ctrl_id, &ctrl_type, 0, 0,
			IPC_NOWAIT)) {
			switch (ctrl_type) {
			case CTRL_RESTART_AMYSQL:
				if (g_amysql_pid > 0) {
					kill(g_amysql_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_ASESSION:
				if (g_asession_pid > 0) {
					kill(g_asession_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_ALOCK:
				if (g_alock_pid > 0) {
					kill(g_alock_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_ASENSOR:
				if (g_asensor_pid > 0) {
					kill(g_asensor_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_AMIDB:
				if (g_amidb_pid > 0) {
					kill(g_amidb_pid, SIGALRM);
				}
				break;
			}
		}
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

	memset(str, 0, 32);
	fd = open(PID_LOCK_FILE, O_RDONLY);
	if (fd < 0) {
		printf("pandora is not running\n");
		exit(EXIT_SUCCESS);
	}
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("fail to get pandora's pid\n");
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
		printf("pandora is not running\n");
		exit(EXIT_SUCCESS);
	}
	fd = open(PID_LOCK_FILE, O_RDONLY);
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("pandora is not running\n");
		exit(EXIT_SUCCESS);
	}
	sprintf(str, "ps -p %d > /dev/null", pid);
	if (0 == WEXITSTATUS(system(str))) {
		printf("pandora (pid: %d) is running\n", pid);
	} else {
		printf("pandora is not running\n");
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
		printf("pandora is not running\n");
		exit(EXIT_FAILURE);
	}
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("pandora is not running\n");
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
		printf("cannot stop pandora\n");
		exit(EXIT_FAILURE);
	}
	sleep(3);
	start_service();
}

int main(int argc, char **argv)
{
	if (2 == argc && 0 == strcmp(argv[1], "--help")) {
		printf("usage: %s start|stop|restart|status\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (3 != argc) {
		printf("usage: %s path start|stop|restart|status\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	sprintf(PID_LOCK_FILE, "%s/token/token.pid", argv[1]);
	sprintf(CONTROL_TOKEN_FILE, "%s/token/control.msg", argv[1]);
	sprintf(PANDORA_MAIN_DIR, "%s/bin", argv[1]);
	if (0 == strcmp(argv[2], "start")) {
		start_service();
	} else if (0 == strcmp(argv[2], "stop")) {
		stop_service();
	} else if (0 == strcmp(argv[2], "restart")) {
		restart_service();
	} else if (0 == strcmp(argv[2], "status")) {
		status_service();
	} else {
		printf("unknown option %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
}

#include <time.h>
#include <libHX/defs.h>
#include <libHX/option.h>
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
#include <sys/shm.h>

#define INTERVAL_BEFORE_MIDNIGHT	5
#define TOKEN_SESSION				1
#define TOKEN_CONTROL				100
#define CTRL_RESTART_MONTOR			1
#define CTRL_RESTART_SUPERVISOR		2
#define CTRL_RESTART_ADAPTOR		3
#define CTRL_RESTART_SCANNER		4
#define CTRL_RESTART_LOCKER			5
#define CTRL_RESTART_SESSION		6
#define CTRL_RESTART_EVENT			7
#define CTRL_RESTART_TIMER			8
#define CTRL_RESTART_PAD			9
#define CTRL_RESTART_SENSOR			10
#define CTRL_RESTART_RSYNC			11
#define CTRL_RESTART_CDND			12
#define SHARE_MEMORY_SIZE			1024*(32+sizeof(time_t)+16+256)

static char PID_LOCK_FILE[256];
static char ATHENA_MAIN_DIR[256];
static char CONTROL_TOKEN_FILE[256];
static char SESSION_TOKEN_FILE[256];

static int g_token_fd;
static int g_notify_stop;
static pid_t g_monitor_pid;
static pid_t g_supervisor_pid;
static pid_t g_scanner_pid;
static pid_t g_adaptor_pid;
static pid_t g_locker_pid;
static pid_t g_event_pid;
static pid_t g_timer_pid;
static pid_t g_session_pid;
static pid_t g_pad_pid;
static pid_t g_sensor_pid;
static pid_t g_rsync_pid;
static pid_t g_cdnd_pid;
static pid_t g_supervised_process;
static char *opt_path;

static struct HXoption g_options_table[] = {
	{.sh = 'p', .type = HXTYPE_STRING, .ptr = &opt_path, .help = "Path to Gromox binaries", .htyp = "DIR"},
	HXOPT_AUTOHELP,
	HXOPT_TABLEEND,
};

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
	if (g_monitor_pid > 0) {
		kill(g_monitor_pid, SIGTERM);
	}
	if (g_supervisor_pid > 0) {
		kill(g_supervisor_pid, SIGTERM);
	}
	if (g_adaptor_pid > 0) {
		kill(g_adaptor_pid, SIGTERM);
	}
	if (g_scanner_pid > 0) {
		kill(g_scanner_pid, SIGTERM);
	}
	if (g_locker_pid > 0) {
		kill(g_locker_pid, SIGTERM);
	}
	if (g_event_pid > 0) {
		kill(g_event_pid, SIGTERM);
	}
	if (g_timer_pid > 0) {
		kill(g_timer_pid, SIGTERM);
	}
	if (g_session_pid > 0) {
		kill(g_session_pid, SIGTERM);
	}
	if (g_pad_pid > 0) {
		kill(g_pad_pid, SIGTERM);
	}
	if (g_sensor_pid > 0) {
		kill(g_sensor_pid, SIGTERM);
	}
	if (g_rsync_pid > 0) {
		kill(g_rsync_pid, SIGTERM);
	}
	if (g_cdnd_pid > 0) {
		kill(g_cdnd_pid, SIGTERM);
	}
}

void start_analyzer()
{
	pid_t pid;
	int len, status;
	char temp_str[32];
	char temp_path[256];
	const char *args[] = {"sa_daemon", "-c", "../config/athena.cfg", NULL};
	struct stat node_stat;
	
	sprintf(temp_path, "%s/sa_daemon", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		return;
	}
	pid = fork();
	if (0 == pid) {
		chdir(ATHENA_MAIN_DIR);
		if (execve("./sa_daemon", const_cast(char **, args), NULL) == -1) {
			exit(EXIT_FAILURE);
		}
	} else if (pid > 0) {
		lseek(g_token_fd, SEEK_SET, 0);	
		write(g_token_fd, "-1\n", 3);
		fsync(g_token_fd);
		waitpid(pid, &status, 0);
		lseek(g_token_fd, SEEK_SET, 0);	
		len = sprintf(temp_str, "%d\n", getpid());
		write(g_token_fd, temp_str, len);
		fsync(g_token_fd);
	}
}

/*
 *  start monitor service
 */
void start_monitor()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"monitor", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/monitor", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_monitor_pid = -1;
		return;
	}
	g_monitor_pid = fork();
	if (g_monitor_pid < 0) {
		return;
	} else if (0 == g_monitor_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./monitor", const_cast(char **, args), NULL) == -1) {
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
 *  start supervisor service
 */
void start_supervisor()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"supervisor", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/supervisor", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_supervisor_pid = -1;
		return;
	}
	g_supervisor_pid = fork();
	if (g_supervisor_pid < 0) {
		return;
	} else if (0 == g_supervisor_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./supervisor", const_cast(char **, args), NULL) == -1) {
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
 *  start web adaptor service
 */
void start_adaptor()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"adaptor", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/adaptor", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_adaptor_pid = -1;
		return;
	}
	g_adaptor_pid = fork();
	if (g_adaptor_pid < 0) {
		return;
	} else if (0 == g_adaptor_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./adaptor", const_cast(char **, args), NULL) == -1) {
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
 *  start scanner service
 */
void start_scanner()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"scanner", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/scanner", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_scanner_pid = -1;
		return;
	}
	g_scanner_pid = fork();
	if (g_scanner_pid < 0) {
		return;
	} else if (0 == g_scanner_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./scanner", const_cast(char **, args), NULL) == -1) {
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
 *  start locker service
 */
void start_locker()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"locker", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/locker", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_locker_pid = -1;
		return;
	}
	g_locker_pid = fork();
	if (g_locker_pid < 0) {
		return;
	} else if (0 == g_locker_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./locker", const_cast(char **, args), NULL) == -1) {
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
 *  start event service
 */
void start_event()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"event", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/event", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_event_pid = -1;
		return;
	}
	g_event_pid = fork();
	if (g_event_pid < 0) {
		return;
	} else if (0 == g_event_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./event", const_cast(char **, args), NULL) == -1) {
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
 *  start sensor service
 */
void start_sensor()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"sensor", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/sensor", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_sensor_pid = -1;
		return;
	}
	g_sensor_pid = fork();
	if (g_sensor_pid < 0) {
		return;
	} else if (0 == g_sensor_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./sensor", const_cast(char **, args), NULL) == -1) {
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
 *  start rsync service
 */
void start_rsync()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"rsync", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/rsync", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_rsync_pid = -1;
		return;
	}
	g_rsync_pid = fork();
	if (g_rsync_pid < 0) {
		return;
	} else if (0 == g_rsync_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./rsync", const_cast(char **, args), NULL) == -1) {
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
 *  start cdnd service
 */
void start_cdnd()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"cdnd", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/cdnd", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_cdnd_pid = -1;
		return;
	}
	g_cdnd_pid = fork();
	if (g_cdnd_pid < 0) {
		return;
	} else if (0 == g_cdnd_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./cdnd", const_cast(char **, args), NULL) == -1) {
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
 *  start timer service
 */
void start_timer()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"timer", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/timer", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_timer_pid = -1;
		return;
	}
	g_timer_pid = fork();
	if (g_timer_pid < 0) {
		return;
	} else if (0 == g_timer_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./timer", const_cast(char **, args), NULL) == -1) {
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
 *  start pad service
 */
void start_pad()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"pad", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/pad", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_pad_pid = -1;
		return;
	}
	g_pad_pid = fork();
	if (g_pad_pid < 0) {
		return;
	} else if (0 == g_pad_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./pad", const_cast(char **, args), NULL) == -1) {
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
 *  start session service
 */
void start_session()
{
	int status;
	struct stat node_stat;
	char temp_path[256];
	const char *args[] = {"session", "-c", "../config/athena.cfg", NULL};

	sprintf(temp_path, "%s/session", ATHENA_MAIN_DIR);
	if (0 != stat(temp_path, &node_stat)) {
		g_session_pid = -1;
		return;
	}
	g_session_pid = fork();
	if (g_session_pid < 0) {
		return;
	} else if (0 == g_session_pid) {
		g_notify_stop = 0;
		signal(SIGTERM, supervisor_sigstop);
		signal(SIGALRM, supervisor_sigrestart);
		while (0 == g_notify_stop) {
			g_supervised_process = fork();
			if (0 == g_supervised_process) {
				chdir(ATHENA_MAIN_DIR);
				if (execve("./session", const_cast(char **, args), NULL) == -1) {
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
	time_t now_time;
	struct tm *ptm;
	pid_t pid, sid; /* process ID and session ID */
	int ctrl_id;
	int fd, shm_id;
	char *shm_begin;
	char str[16];
	key_t k_shm;
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

	start_monitor();
	start_supervisor();
	start_adaptor();
	start_scanner();
	start_locker();
	start_event();
	start_timer();
	start_session();
	start_pad();
	start_sensor();
	start_rsync();
	start_cdnd();
	
	k_shm = ftok(SESSION_TOKEN_FILE, TOKEN_SESSION);
	if (-1 != k_shm) {
		shm_id = shmget(k_shm, SHARE_MEMORY_SIZE, 0666);
		if (-1 == shm_id) {
			shm_id = shmget(k_shm, SHARE_MEMORY_SIZE, 0666|IPC_CREAT);
		}
		if (-1 != shm_id) {
			shm_begin = shmat(shm_id, NULL, 0);
			if (NULL != shm_begin) {
				memset(shm_begin, 0, SHARE_MEMORY_SIZE);
				shmdt(shm_begin);
			}
		}
	}


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
			case CTRL_RESTART_MONTOR:
				if (g_monitor_pid > 0) {
					kill(g_monitor_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_SUPERVISOR:
				if (g_supervisor_pid > 0) {
					kill(g_supervisor_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_ADAPTOR:
				if (g_adaptor_pid > 0) {
					kill(g_adaptor_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_SCANNER:
				if (g_scanner_pid > 0) {
					kill(g_scanner_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_LOCKER:
				if (g_locker_pid > 0) {
					kill(g_locker_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_EVENT:
				if (g_event_pid > 0) {
					kill(g_event_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_SESSION:
				if (g_session_pid > 0) {
					kill(g_session_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_TIMER:
				if (g_timer_pid > 0) {
					kill(g_timer_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_PAD:
				if (g_pad_pid > 0) {
					kill(g_pad_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_SENSOR:
				if (g_sensor_pid > 0) {
					kill(g_sensor_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_RSYNC:
				if (g_rsync_pid > 0) {
					kill(g_rsync_pid, SIGALRM);
				}
				break;
			case CTRL_RESTART_CDND:
				if (g_cdnd_pid > 0) {
					kill(g_cdnd_pid, SIGALRM);
				}
				break;
			}
		}
		time(&now_time);
		ptm = localtime(&now_time);
		if (24*60*60 - ptm->tm_sec - 60*ptm->tm_min - 
			60*60*ptm->tm_hour < INTERVAL_BEFORE_MIDNIGHT) {
			start_analyzer();
			sleep(INTERVAL_BEFORE_MIDNIGHT);
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
		printf("athena is not running\n");
		exit(EXIT_SUCCESS);
	}
	read(fd, str, 16);
	close(fd);
	if (0 == strcmp(str, "-1\n")) {
		printf("daemon analyzer is now running, please stop athena later\n");
		exit(EXIT_FAILURE);	
	}
	pid = atoi(str);
	if (0 == pid) {
		printf("fail to get athena's pid\n");
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
		printf("athena is not running\n");
		exit(EXIT_SUCCESS);
	}
	fd = open(PID_LOCK_FILE, O_RDONLY);
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("athena is not running\n");
		exit(EXIT_SUCCESS);
	}
	sprintf(str, "ps -p %d > /dev/null", pid);
	if (0 == WEXITSTATUS(system(str))) {
		printf("athena (pid: %d) is running\n", pid);
	} else {
		printf("athena is not running\n");
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
		printf("athena is not running\n");
		exit(EXIT_FAILURE);
	}
	read(fd, str, 16);
	close(fd);
	pid = atoi(str);
	if (0 == pid) {
		printf("athena is not running\n");
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
		printf("cannot stop athena\n");
		exit(EXIT_FAILURE);
	}
	sleep(3);
	start_service();
}

int main(int argc, const char **argv)
{
	if (HX_getopt(g_options_table, &argc, &argv, HXOPT_USAGEONERR) < 0)
		return EXIT_FAILURE;
	if (opt_path == NULL) {
		printf("You need to specify the -p option.\n");
		return EXIT_FAILURE;
	}
	if (argc != 2) {
		printf("usage: %s -p path {start|stop|restart|status}\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	sprintf(PID_LOCK_FILE, "%s/token/token.pid", opt_path);
	sprintf(CONTROL_TOKEN_FILE, "%s/token/control.msg", opt_path);
	sprintf(SESSION_TOKEN_FILE, "%s/token/session.shm", opt_path);
	sprintf(ATHENA_MAIN_DIR, "%s/bin", opt_path);
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


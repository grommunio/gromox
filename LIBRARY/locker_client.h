#ifndef _H_LOCKER_CLIENT_
#define _H_LOCKER_CLIENT_

#define		LOCKD	int

void locker_client_init(const char *ip, int port, int max_interval);
extern int locker_client_run(void);
extern int locker_client_stop(void);
LOCKD locker_client_lock(const char *resource);

void locker_client_unlock(LOCKD lockd);
extern void locker_client_free(void);

#endif

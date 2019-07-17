#ifndef _H_LOCKER_CLIENT_
#define _H_LOCKER_CLIENT_

#define		LOCKD	int

void locker_client_init(const char *ip, int port, int max_interval);

int locker_client_run();

int locker_client_stop();

LOCKD locker_client_lock(const char *resource);

void locker_client_unlock(LOCKD lockd);

void locker_client_free();


#endif

#!/bin/sh
#
# athena:   athena daemon
# chkconfig: 345 98 02
#
# description:  This is a daemon for bring up mail system web administration
#
# processname: athena
#

# Sanity checks.
[ -x /usr/bin/athena ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
ATHENA_PATH=/var/athena

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting athena... "
    	daemon athena $ATHENA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping athena... "
    	daemon athena $ATHENA_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        athena $ATHENA_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting athena... "
		daemon athena $ATHENA_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon athena $ATHENA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting athena... "
		daemon athena $ATHENA_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

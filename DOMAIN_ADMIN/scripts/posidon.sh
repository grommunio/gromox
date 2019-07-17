#!/bin/sh
#
# posidon:   posidon daemon
# chkconfig: 345 98 02
#
# description:  This is a daemon for bring up user web agent
#
# processname: posidon
#

# Sanity checks.
[ -x /usr/bin/posidon ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
POSIDON_PATH=/var/posidon

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting posidon... "
    	daemon posidon $POSIDON_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping posidon... "
    	daemon posidon $POSIDON_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        posidon $POSIDON_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting posidon... "
		daemon posidon $POSIDON_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon posidon $POSIDON_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting posidon... "
		daemon posidon $POSIDON_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

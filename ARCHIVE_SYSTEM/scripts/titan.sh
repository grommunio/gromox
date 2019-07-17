#!/bin/sh
#
# titan:   titan daemon
# chkconfig: 345 98 02
#
# description:  This is a daemon for bring up mail archive service
#
# processname: titan
#

# Sanity checks.
[ -x /usr/bin/titan ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
TITAN_PATH=/var/titan

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting titan... "
    	daemon titan $TITAN_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping titan... "
    	daemon titan $TITAN_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        titan $TITAN_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting titan... "
		daemon titan $TITAN_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon titan $TITAN_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting titan... "
		daemon titan $TITAN_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

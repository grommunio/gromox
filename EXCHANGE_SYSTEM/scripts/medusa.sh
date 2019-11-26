#!/bin/sh
#
# medusa:   medusa daemon
#
# chkconfig: 345 98 02
# description:  This is a daemon for bring up rpc over http with MAPI SERVER
#
# processname: medusa
#

# Sanity checks.
[ -x /usr/bin/medusa ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
MEDUSA_PATH=/var/medusa

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting medusa... "
    	daemon medusa $MEDUSA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping medusa... "
    	daemon medusa $MEDUSA_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        medusa $MEDUSA_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting medusa... "
		daemon medusa $MEDUSA_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon medusa $MEDUSA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting medusa... "
		daemon medusa $MEDUSA_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

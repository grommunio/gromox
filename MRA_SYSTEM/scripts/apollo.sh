#!/bin/sh
#
# apollo:   apollo daemon
#
# chkconfig: 345 98 02
# description:  This is a daemon for bring up POP and IMAP
#
# processname: apollo
#

# Sanity checks.
[ -x /usr/bin/apollo ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
APOLLO_PATH=/var/apollo

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting apollo... "
    	daemon apollo $APOLLO_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping apollo... "
    	daemon apollo $APOLLO_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        apollo $APOLLO_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting apollo... "
		daemon apollo $APOLLO_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon apollo $APOLLO_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting apollo... "
		daemon apollo $APOLLO_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

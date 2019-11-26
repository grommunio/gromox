#!/bin/sh
#
# herculiz:   herculiz daemon
#
# chkconfig: 345 98 02
# description:  This is a daemon for bring up SMTP and DELIVERY
#
# processname: herculiz
#

# Sanity checks.
[ -x /usr/bin/herculiz ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
HERCULIZ_PATH=/var/herculiz

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting herculiz... "
    	daemon herculiz $HERCULIZ_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping herculiz... "
    	daemon herculiz $HERCULIZ_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        herculiz $HERCULIZ_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting herculiz... "
		daemon herculiz $HERCULIZ_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon herculiz $HERCULIZ_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting herculiz... "
		daemon herculiz $HERCULIZ_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

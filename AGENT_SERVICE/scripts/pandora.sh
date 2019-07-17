#!/bin/sh
#
# pandora:   pandora daemon
# chkconfig: 345 98 02
#
# description:  This is a daemon for bring up domain socket services
#
# processname: pandora
#

# Sanity checks.
[ -x /usr/bin/pandora ] || exit 0

# Source function library.
. /etc/rc.d/init.d/functions

# so we can rearrange this easily
PANDORA_PATH=/var/pandora

RETVAL=0

# See how we were called.
case "$1" in
    start)
    	echo -n $"Starting pandora... "
    	daemon pandora $PANDORA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    stop)
    	echo -n $"Stopping pandora... "
    	daemon pandora $PANDORA_PATH stop
    	RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    status)
        pandora $PANDORA_PATH status
        RETVAL=$?
        ;;
    restart)
		echo -n $"Restarting pandora... "
		daemon pandora $PANDORA_PATH stop
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
		daemon pandora $PANDORA_PATH start
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    condrestart)
		echo -n $"Restarting pandora... "
		daemon pandora $PANDORA_PATH restart
		RETVAL=$?
		echo
		[ $RETVAL -eq 0 ]
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart}"
        ;;
esac
exit $RETVAL

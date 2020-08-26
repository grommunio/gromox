#!/bin/sh
if [ $# -lt 1 ];then
	echo "usage $0 queue_dir"
	exit 1
fi

rm -rf $1
mkdir $1
mkdir $1/mess
mkdir $1/save
touch $1/token.ipc
mkdir $1/timer
mkdir $1/cache
mkdir $1/clone
mkdir $1/insulation
echo "message queue $1 is created successfully"
exit 0

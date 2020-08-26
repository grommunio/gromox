#!/bin/sh

if [ $# -lt 1 ];then
	echo "usage $0 area_dir"
	exit 1
fi

chmod a+wrx $1


if [ -d $1 ];then

declare -i idx

idx=1
while [ $idx -lt 201 ]
do

mkdir $1/v$idx
chown titan. $1/v$idx
chmod a+wrx $1/v$idx

declare -i idx1

idx1=1
while [ $idx1 -lt 251 ]
do

mkdir $1/v$idx/$idx1
chown titan. $1/v$idx/$idx1
chmod a+wrx $1/v$idx/$idx1
idx1=$idx1+1
done

idx=$idx+1
done

fi


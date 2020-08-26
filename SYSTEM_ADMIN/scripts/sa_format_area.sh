#!/bin/sh

if [ $# -lt 1 ];then
	echo "usage $0 area_dir"
	exit 1
fi

chmod a+wrx $1

echo "0M,0C,0H" > $1/pinfo
chmod a+wr $1/pinfo

declare -i idx

idx=1
while [ $idx -lt 201 ]
do

mkdir $1/v$idx
chown herculiz. $1/v$idx
chmod a+wrx $1/v$idx
echo "0H" > $1/v$idx/vinfo
chown herculiz. $1/v$idx/vinfo
chmod a+wr $1/v$idx/vinfo

idx=$idx+1
done


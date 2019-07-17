#!/bin/sh

phpize
export CFLAGS='-O0'
./configure --enable-mapi
make

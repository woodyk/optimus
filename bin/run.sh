#!/bin/sh
path="$HOME/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -i $1 -c 5000 --server 192.168.4.12:9200 --l7 --bytes 128;  done

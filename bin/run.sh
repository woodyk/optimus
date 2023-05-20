#!/bin/bash
INTERFACE=$1
cd -P $(dirname "${BASH_SOURCE}")

while [ 1 ]
	do
		./optimus.pl -i $INTERFACE -c 5000 --server 192.168.4.12:9200 --l7 --bytes 128
	done

#!/bin/sh
path="$HOME/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -i $1 -e -c 5000; sleep 1; done

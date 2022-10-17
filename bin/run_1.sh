#!/bin/sh
int="eth1"
path="/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -i $int -e -c 5000; ./bumblebee.pl; sleep 1; done

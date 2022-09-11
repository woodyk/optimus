#!/bin/sh
int="eth1"
path="/path/to/prime/bin";
cd $path 
while [ 1 ]; do time perl ./optimus.pl $int; time perl ./bumblebee.pl; sleep 1; done

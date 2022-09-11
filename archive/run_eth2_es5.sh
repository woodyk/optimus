#!/bin/sh
int="eth2"
cd /home/flint/src/prime
while [ 1 ]; do time perl bulkhead.pl $int; time perl bumblebee_bulkhead.pl; sleep 1; done

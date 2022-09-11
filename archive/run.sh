#!/bin/sh
int="eth0"
while [ 1 ]; do time perl optimus.pl ; time perl bumblebee.pl; sleep 1; done

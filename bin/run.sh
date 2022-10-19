#!/bin/sh
path="/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -i $1 -j; sleep 1; done

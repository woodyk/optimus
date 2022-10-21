#!/bin/sh
path="/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -e -i $OPTIMUS_INT; sleep 1; done

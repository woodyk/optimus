#!/bin/sh
path="/optimus/bin/";
cd $path 
while [ 1 ]; do ./optimus.pl -i $OPTIMUS_INT; sleep 1; done

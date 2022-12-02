#!/bin/sh
path="/optimus/bin/";
cd $path 
/etc/init.d/apache2 start
while [ 1 ]; do ./optimus.pl $OPTIMUS_ARGS; done

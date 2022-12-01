#!/bin/sh
path="/optimus/bin/";
cd $path 
php -S 0.0.0.0:8000 -t ../web &
while [ 1 ]; do ./optimus.pl $OPTIMUS_ARGS; done

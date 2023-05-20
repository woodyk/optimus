#!/bin/bash
/etc/init.d/apache2 start
cd -P $(dirname "${BASH_SOURCE}")
while [ 1 ]
    do
        ./optimus.pl $OPTIMUS_ARGS
    done

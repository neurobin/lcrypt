#!/bin/bash
pn=travis_check.sh
ids=$(pidof "$pn" -x)
t1=$(date +%s)
threshold=$(expr 60 \* 1)

while true;do
    t2=$(date +%s)
    time=$(expr $t2 - $t1)
    if [ $time -ge $threshold ]; then
        t1=$(date +%s)
        ids=$(pidof "$pn" -x)
        if [ "x$ids" != 'x' ]; then
            kill -s SIGINT $ids
            ./test/$pn
        fi
        break
    fi
done

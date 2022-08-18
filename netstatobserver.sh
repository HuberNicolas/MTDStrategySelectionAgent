#!/bin/bash
observations=300
for (( i=1; i<=observations; i++ ))
do  
  snapshot=`netstat -ent | sed '1d;2d;'`
  echo $(date +"%Y-%m-%d_%H-%M-%S") >> log.txt
  echo "$snapshot" >> log.txt
  sleep 1
done
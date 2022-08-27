#!/bin/bash
observations=360
now=`date +%F-%H-%M-%S`
suffix="-netstatlog.txt"
filename="$path$now$suffix"
for (( i=1; i<=observations; i++ ))
do  
  snapshot=`netstat -ent | sed '1d;2d;'`
  echo $(date +"%Y-%m-%d_%H-%M-%S") >> "$filename"
  echo "$snapshot" >> "$filename"
  sleep 1
done

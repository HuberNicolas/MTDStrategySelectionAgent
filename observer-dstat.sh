#!/bin/bash

: '
Observer script for
CPU metrics
RAM metrics
Disk metrics
Network metrics
System-calls metrics

generates #ITERTIONS .csv files, each has #OBSERVATIONS entries
generates a total of ITERATIONS * OBSERVATIONS observation entries

based on dstat:
https://manpages.ubuntu.com/manpages/kinetic/en/man1/dstat.1.html
https://linux.die.net/man/1/dstat
http://dag.wiee.rs/home-made/dstat/
sudo apt-get install dstat
'
cd /root/MTDPolicy/data/csv/

iterations=1
delay=1
observations=360
for ((i = 0 ; i < $iterations ; i++)); do
    now=`date +%F-%H-%M-%S`
    suffix="-log.csv"
    filename="$path$now$suffix"
    # time, cpu, memory, filesystem, disk, network, tcp, system, procs
    # -t        : enable time/date output
    # -cpu      : enable cpu stats (system, user, idle, wait, hardware interrupt, software interrupt)
    # -mem      : enable memory stats (used, buffers, cache, free)
    # -fs       : enable filesystem stats (open files, inodes)
    # -d        : enable disk stats (read, write)
    # -disk-tps : number of read and write transactions per device. Displays the number of read and write I/O transactions per device.
    # -n        : enable network stats (receive, send)
    # -tcp      : enable tcp stats (listen, established, syn, time_wait, close)
    # -socket   : enable socket stats (total, tcp, udp, raw, ip-fragments)
    # -y        : enable system stats (interrupts, context switches)
    # -p        : enable process stats (runnable, uninterruptible, new)
    # -N eth0   : specifiys network on eth0
    # -ouput    : write CSV output to file
    dstat -t --cpu --mem --fs -d --disk-tps -n --tcp --socket -y -p -N eth0 --output $filename $delay $observations
done

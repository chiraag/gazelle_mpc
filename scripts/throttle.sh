#!/bin/bash

# Based on this gist: https://gist.github.com/trongthanh/1196596
# Replace lo with eth0/wlan0 to limit speed from wide lan

if [ $# -ne 1 ]; then
  echo "Usage: $0 [start|stop|report]"
elif [ "$1" == "start" ]; then
  #Setup the rate control and delay
  sudo tc qdisc add dev lo root handle 1: htb default 12
  sudo tc class add dev lo parent 1:1 classid 1:12 htb rate 2.5Gbit # ceil 20Mbit
  sudo tc qdisc add dev lo parent 1:12 netem delay 0.1ms
elif [ $1 == "stop" ]; then
  #Remove the rate control/delay
  sudo tc qdisc del dev lo root
elif [ $1 == "report" ]; then
  #To see what is configured on an interface, do this
  sudo tc -s qdisc ls dev lo
else
  echo "Usage: $0 [start|stop|report]"
fi


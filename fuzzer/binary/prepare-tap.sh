#! /bin/bash

HOST_IP=192.168.99.37

sudo tunctl -u ivan
sudo ip link set tap0 up
sudo ip addr add $HOST_IP/24 dev tap0

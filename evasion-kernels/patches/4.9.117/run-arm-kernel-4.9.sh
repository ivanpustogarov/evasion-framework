#! /bin/bash

QEMU=../../qemu-3.1.1/arm-softmmu/qemu-system-arm
MEM=128 # set it to 32


QEMU=../../qemu-3.1.1/arm-softmmu/qemu-system-arm
MEM=128

DTB=./arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb
KERNEL=./arch/arm/boot/zImage
# This was build with buildroot
FILESYSTEM=./arm-linux-3.4-buildroot.ext2.qcow2
HOST_IP=192.168.99.37

# Enable host-guest network via tun interface
sudo tunctl -u $USER
sudo ip link set tap0 up
sudo ip addr add $HOST_IP/24 dev tap0


$QEMU -M vexpress-a15 -dtb $DTB -nographic -smp 1 -m $MEM -kernel $KERNEL -append "console=ttyAMA0 root=/dev/mmcblk0 init=/sbin/init" -s -sd $FILESYSTEM -net nic,model=lan9118,netdev=net0 -netdev tap,id=net0,script=no,downscript=no,ifname=tap0 -pidfile ./qemu.pid

# Remove tap interface
sudo tunctl -d tap0

#! /bin/bash

export PATH="$PATH:../compilers/arm-linux-androideabi-4.9/bin"
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- menuconfig

#! /bin/bash

export PATH="$PATH:$(realpath ../../compilers/arm-linux-androideabi-4.9/bin)"
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- -j8

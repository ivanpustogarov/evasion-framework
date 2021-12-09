#! /bin/bash

export PATH="$PATH:$(realpath ../../compilers/arm-linux-androideabi-4.9/bin)"
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- vexpress_defconfig
sed -i 's/# CONFIG_DEVTMPFS_MOUNT is not set/CONFIG_DEVTMPFS_MOUNT=y/g'  .config
sed -i 's/# CONFIG_ARM_PTDUMP is not set/CONFIG_ARM_PTDUMP=y/g'  .config

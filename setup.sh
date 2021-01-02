#! /bin/bash

## >>  1. Get cross compilers <<
mkdir compilers
cd compilers
git clone https://source.codeaurora.org/quic/la/platform/prebuilts/gcc/linux-x86/arm/arm-eabi-4.6
cd arm-eabi-4.6
git checkout M8930AAAAANLYA255092112
cd ../
git clone https://source.codeaurora.org/quic/la/platform/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8
cd arm-eabi-4.8 
git checkout aosp-new/lollipop-release
cd ../
git clone https://source.codeaurora.org/quic/la/platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9
cd arm-linux-androideabi-4.9
git checkout aosp-new/master
git checkout b91992b549430ac1a8a684f4bfe8c95941901165  # gcc was removed in the current verssion
cd ../
git clone https://source.codeaurora.org/quic/la/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.8
cd aarch64-linux-android-4.8
git checkout aosp-new/lollipop-release
cd ../
git clone https://source.codeaurora.org/quic/la/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
cd aarch64-linux-android-4.9
git checkout aosp-new/pie-release
cd ../

## >> 2. Get and build Qemu <<
wget https://download.qemu.org/qemu-3.1.1.tar.xz
tar -xf qemu-3.1.1.tar.xz
cd qemu-3.1.1/
./configure --target-list=arm-softmmu
make -j3

## >> 3. Install Unicorn <<
sudo dnf install python2-setuptools.noarch
git clone https://github.com/ivanpustogarov/afl-unicorn.git
bash -c "cd afl-unicorn && make && cd unicorn_mode && sudo ./build_unicorn_support.sh"

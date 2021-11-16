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
cd ../
wget https://download.qemu.org/qemu-3.1.1.tar.xz
tar -xf qemu-3.1.1.tar.xz
rm qemu-3.1.1.tar.xz
cd qemu-3.1.1/
./configure --target-list=arm-softmmu
make -j3

## >> 3. Get and build gdb with arm and xml support <<
cd ../
wget https://ftp.gnu.org/gnu/gdb/gdb-10.1.tar.xz
tar xf gdb-10.1.tar.xz
rm gdb-10.1.tar.xz
cd gdb-10.1
mkdir build
./configure \
  --enable-targets=arm-none-eabi \
  --prefix=$(realpath ./build) \
  --enable-languages=all \
  --enable-multilib \
  --enable-interwork \
  --with-system-readline \
  --disable-nls \
  --with-python=/usr/bin/python \
  --with-guile=guile-2.0 \
  --with-system-gdbinit=/etc/gdb/gdbinit \
  --with-expat
make -j8
make install

## >> 3. Install Unicorn <<
cd ../
#sudo dnf install python2-setuptools.noarch
git clone https://github.com/ivanpustogarov/afl-unicorn.git
bash -c "cd afl-unicorn && make && cd unicorn_mode && sudo ./build_unicorn_support.sh"

## >> 4. Install some perl modules, prepare-emulation-arm.pl will need them <<
sudo cpan Binutils::Objdump
sudo cpan Parse::ExuberantCTags
sudo cpan Net::OpenSSH
sudo cpan Devel::GDB
sudo cpan IO::Pty
sudo cpan File::Slurp


## >> 5. Custom version of symbolic execution library <<
git clone https://github.com/ivanpustogarov/manticore
cd manticore
python2 setup.py build 
sudo python2 setup.py install
# Fedora
dnf install z3-4.8.9-4.fc33.x86_64
# Ubuntu
sudo apt install z3



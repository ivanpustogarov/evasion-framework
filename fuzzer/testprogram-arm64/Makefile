kernel_src := /home/ivan/prj/LKM-fuzz/linux-kernels/linux-4.9.117-alien-arm64
export PATH := $(PATH):/home/ivan/prj/LKM-fuzz/linux-kernels/compilers/aarch64-linux-android-4.9/bin/
PREFIX := aarch64-linux-gnu-
CC := $(PREFIX)gcc

all:
	$(CC) -static -I$(kernel_src)/include/ sample-ioctl.c -o sample-ioctl

clean:
	rm -f *.o sample-ioctl

export PATH := $(PATH):/home/ivan/prj/LKM-fuzz/linux-kernels/compilers/arm-eabi-4.6/bin/

all:
	arm-eabi-gcc -c -marm -fno-stack-protector syscall.c
	arm-eabi-gcc -c -marm -fno-stack-protector util.c
	arm-eabi-gcc -c -marm -fno-stack-protector sample-ioctl.c
	arm-eabi-ld -static -e main syscall.o util.o sample-ioctl.o -o sample-ioctl
	# The reason for ccu_drv-testprogram is that we need to issue two ioclt's (the first one is to power on)
	arm-eabi-gcc -c -marm -fno-stack-protector ccu_drv-testprogram.c
	arm-eabi-ld -static -e main syscall.o util.o ccu_drv-testprogram.o -o ccu_drv-testprogram

clean:
	rm -f *.o sample-ioctl

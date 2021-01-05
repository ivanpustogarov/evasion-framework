export PATH := $(PATH):/home/ivan/prj/LKM-fuzz/linux-kernels/compilers/arm-eabi-4.6/bin/

all:
	@arm-eabi-gcc -c -marm -fno-stack-protector syscall.c
	@arm-eabi-gcc -c -marm -fno-stack-protector util.c
	@arm-eabi-gcc -c -marm -fno-stack-protector testprogram.c 
	@arm-eabi-ld -static -e main syscall.o util.o testprogram.o -o testprogram
	arm-eabi-gcc -c -marm -fno-stack-protector sample-ioctl.c
	arm-eabi-ld -static -e main syscall.o util.o sample-ioctl.o -o sample-ioctl

clean:
	@rm -f *.o testprogram

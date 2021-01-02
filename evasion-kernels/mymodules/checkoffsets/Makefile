# ll errors are to be suppressed
KBUILD_CFLAGS += -w

# specific error is to be suppressed.
#KBUILD_CFLAGS += -Wno-error=unused-but-set-variable
#KBUILD_CFLAGS += -Wno-error=unused-variable

# -----> export PATH="$PATH:$(realpath ../../../../compilers/arm-linux-androideabi-4.9/bin)"

obj-m+=testoffsets.o

all:
	make -C ../../ M=$(PWD) ARCH=arm CROSS_COMPILE=arm-linux-androideabi- modules
	arm-linux-androideabi-objcopy --dump-section .text=text.bin testoffsets.ko

clean:
	rm -f *.ko *.o

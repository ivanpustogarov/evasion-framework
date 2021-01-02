# if all errors are to be suppressed
# source link: https://stackoverflow.com/questions/7950757/cross-compiling-kernel-using-makefile-how-to-suppress-wunused-but-set-variabl
#KBUILD_CFLAGS += -w

# if that specific error is to be suppressed.
#KBUILD_CFLAGS += -Wno-error=unused-but-set-variable
#KBUILD_CFLAGS += -Wno-error=unused-variable


obj-m+=devicecreator.o


all:
	make -C ../../ M=$(PWD) ARCH=arm CROSS_COMPILE=arm-eabi- modules


clean:
	rm -f *.ko *.o
	rm -f ./.e*
	rm -rf .tmp_versions/
	rm -f modules.order Module.symvers
	rm -f *.mod.c

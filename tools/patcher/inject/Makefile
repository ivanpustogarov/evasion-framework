# ->> export PATH="$PATH:$(realpath ../../../compilers/arm-eabi-4.8/bin)"
#  # Don't use arm-adnroideabi-gcc, it creats GOT relocation entries which are not recognized
#    byt the kernel

elf32:
	arm-eabi-gcc -fno-short-enums -c inject.c
	@echo Now do: "arm-eabi-ld -r inject.o ../yourmodule.ko -o yourmodule-injected.ko"

elf64:
	aarch64-linux-gnu-gcc -fno-short-enums -c inject.c
	@echo Now do: "aarch64-linux-gnu-ld -r inject.o ../vidc.ko -o vidc-injected.ko"

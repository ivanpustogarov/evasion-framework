#ifndef UTIL_H
#define UTIL_H

//#include <features.h>
//#include <errno.h>
////#include <sys/types.h>
//#include <sys/syscall.h>
//#include <stdint.h>
//#include <linux/types.h>

// Sys call numbers for arm: https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
//                           https://w3challs.com/syscalls/?arch=arm_strong
#define __NR_close 6
#define __NR_open 5
#define __NR_write 4
#define __NR_exit 1
#define __NR_read 3
#define __NR_ioctl 54
#define O_RDONLY         00
#define O_WRONLY         01
#define O_RDWR           02

extern long syscall(long number, ...);
int print_int(uint32_t n);
int print_hex(uint32_t n);
int print_s(char *s);
int print_self_memmap();
void *memcpy_alt(void *dest, const void *src, unsigned int n);
int print_double_word(uint32_t *p);
int print_double_words(uint32_t *start, int n);

#endif

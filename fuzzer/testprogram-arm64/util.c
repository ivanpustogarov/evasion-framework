#include <stdint-gcc.h>
#include "util.h"


//#define __NR_open 5
//#define __NR_write 4
//#define __NR_exit 1
//#define __NR_read 3
//#define __NR_ioctl 54
//#define O_RDONLY         00
//#define O_WRONLY         01
//#define O_RDWR           02

char hex_tab[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
                  '9', 'a', 'b', 'c', 'd', 'e', 'f'};

int print_int(uint32_t n)
{
  char c;
  char buf[100];
  int len = 0;
  int i = 0;


  if(n==0)
  {
    syscall(__NR_write, 1, buf+i, 1);
    return 0;
  }

  while(n!=0)
  {
    c = n % 10; 
    c = c + '0';
    n = n/10;
    buf[len] = c;
    //syscall(__NR_write, 1, buf+len, 1);
    len++;
    //syscall(__NR_write, 1, &c, 1);
  }
  for(i=len-1; i>=0; i--)
    syscall(__NR_write, 1, buf+i, 1);

  //syscall(__NR_write, 1, "\n", 1);
  return 0;
}

int print_hex(uint32_t n)
{
  char c;
  char buf[100];
  int i = 0;
  int len = 0;
  for(i=0; i<100; i++)
    buf[i] = 0;
  if(n == 0)
  {
    syscall(__NR_write, 1, "0", 1);
    return 0;
  }
  while(n!=0)
  {
    c = n & 0x0000000f; 
    n = n >> 4;
    //print_int(c);
    //print_s("\n");
    buf[len] = hex_tab[c];
    //syscall(__NR_write, 1, buf+len, 1);
    len++;
    //syscall(__NR_write, 1, &c, 1);
  }
  for(i=len-1; i>=0; i--)
    syscall(__NR_write, 1, buf+i, 1);

  //syscall(__NR_write, 1, "\n", 1);
  return 0;
}

int print_s(char *s)
{
  while(*s != 0)
  {
    syscall(__NR_write, 1, s, 1);
    s++;
  }
  return 0;
  //syscall(__NR_write, 1, "\n", 1);
}

int print_line(char *s)
{
  print_s(s);
  print_s("\n");
  return 0;
  //syscall(__NR_write, 1, "\n", 1);
}


/* This is just to show this process's memory map. We might need it for
 * prepare-emulation-arm.pl */
int print_self_memmap()
{
  char maps_contents[1024];
  char maps_filename[] = "/proc/self/maps";
  long fd_map = syscall(__NR_open, maps_filename, O_RDWR);
  syscall(__NR_read, fd_map, maps_contents, 1024);
  print_s(maps_contents);
  //syscall(__NR_write, 1, maps_contents, 1024);
  return 0;
}

void *memcpy_alt(void *dest, const void *src, unsigned int n)
{
  int i = 0;
  char *d = (char *)dest;
  char *s = (char *)src;
  for(i=0;i<n;i++)
  {
    *d = *s;
    d++;
    s++;
  }
  return dest;
}

int print_double_word(uint32_t *p)
{
  //uint32_t n = *p;
  print_hex(*p);
  return 0;
}

int print_double_words(uint32_t *start, int n)
{
  //uint32_t n = *p;
  uint32_t *p = start;
  int i = 0;
  for(i=0;i<n;i++)
  {
    print_hex((int32_t)(p+i));
    print_s(" : ");
    print_double_word((uint32_t *)(p+i));
    print_s("\n");
  }
  return 0;
}

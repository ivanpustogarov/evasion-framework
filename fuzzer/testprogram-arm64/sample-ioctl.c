#include <sys/ioctl.h> /* this comes from kernel source, see Makefile for -I option */
#include <stdio.h>

#define O_RDONLY         00
#define O_WRONLY         01
#define O_RDWR           02

typedef char uint8_t;

char dev_name[] = "dec";
int main(int argc, char **argv)
{

  dev_name[0] = 'd'; // So that .data page is mapped when we go into the system call

  char maps_contents[1024];
  char maps_filename[] = "/proc/self/maps";
  long fd_map = open(maps_filename, O_RDWR);
  read(fd_map, maps_contents, 1024);
  printf("%s\n",maps_contents);

  if(argc != 2)
  {
    printf("usage: sample-ioctl /dev/xxx\n");
    return 0;
  }

  int fd = open(argv[1], O_RDWR);
  if(fd==-1)
  {
    printf("Can't open %s\n", argv[1]);
    return 0;
  }

  printf("[+] Was able to open %s\n", argv[1]);

  ioctl(fd, 0x12345678, 0x12345678);
  return 0;
}














//#include <stdint-gcc.h>
//#include "util.h" /* Contains syscall numbers and print functions */
//
//
//char dev_name[] = "dec";
//char maps_filename[] = "/proc/self/maps";
//char maps_contents[1024];
//char err_open_msg[] = "error: could not open file ";
//char err_open_msg1[] = "error: could not open ";
//char err_write_msg[] = "error: could not write to /dev/ebbchar\n";
//char success_open_msg[] = "open was successfull\n";
//int main()
//{
//  int ss = 0x42; /* Stack start */
//  long ret;
//  uint32_t **my_argv;
//  int my_argc;
//  char *arg1;
//  dev_name[0] = 'd'; // So that .data page is mapped when we go into the system call
//  print_self_memmap();
//
//  //print_double_words((uint32_t *)(&ss),9);
//  my_argc = *(&ss+6);
//  my_argv = (uint32_t **)(&ss+7);
//
//  print_s("argc = ");
//  print_int(my_argc);
//  print_s("\n");
//
//  if(my_argc != 2)
//  {
//    print_line("error: not enough arguments");
//    print_line("usage: sample-ioctl FILE");
//    syscall(__NR_exit, 0);
//  }
//
//  long fd;
//  print_s("opennning ");
//  print_line(my_argv[1]);
//
//  fd = syscall(__NR_open, my_argv[1], O_RDWR);
//
//  if(fd == -1)
//  {
//    print_s("error opening ");
//    print_line(my_argv[1]);
//    syscall(__NR_exit, 127);
//  }
//
//  print_s("[+] Was able to open ");
//  print_line(my_argv[1]);
//
//  //char param[1024];
//  int param[3];
//  param[0] = 2;
//  param[1] = 2;
//  param[2] = 2;
//  my_argc = syscall(__NR_ioctl, fd, 0x12345678, 0x12345678);
//
//  print_int(my_argc);
//  print_s("\n");
//  syscall(__NR_exit, 0);
//
//}

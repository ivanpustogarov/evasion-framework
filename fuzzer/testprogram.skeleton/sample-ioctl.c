//#include <stdio.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>
//#include <linux/ioctl.h>
//#include <asm-generic/int-l64.h>
//#include <x86_64-linux-gnu/asm/unistd_64.h>
//#include <stdint.h>
#include <stdint-gcc.h>
#include "util.h" /* Contains syscall numbers and print functions */
//#include "msm_cam_sensor.h"
//#include "camera_isp.h"

// Sys call numbers for arm: https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
//                           https://w3challs.com/syscalls/?arch=arm_strong

//char dev_name[] = "/dev/ebbchar";
char dev_name[] = "dec";
char maps_filename[] = "/proc/self/maps";
char maps_contents[1024];
//char err_open_msg[] = "error: could not open /dev/ebbchar\n";
char err_open_msg[] = "error: could not open file ";
char err_open_msg1[] = "error: could not open ";
char err_write_msg[] = "error: could not write to /dev/ebbchar\n";
char success_open_msg[] = "open was successfull\n";
//int main(int argc, char **argv)
int main()
{
  int ss = 0x42; /* Stack start */
  long ret;
  uint32_t **my_argv;
  int my_argc;
  char *arg1;
  dev_name[0] = 'd'; // So that .data page is mapped when we go into the system call
  print_self_memmap();

  //print_double_words((uint32_t *)(&ss),9);
  my_argc = *(&ss+6);
  my_argv = (uint32_t **)(&ss+7);

  print_s("argc = ");
  print_int(my_argc);
  print_s("\n");

  if(my_argc != 2)
  {
    print_line("error: not enough arguments");
    print_line("usage: sample-ioctl FILE");
    syscall(__NR_exit, 0);
  }

  long fd;
  print_s("opennning ");
  print_line(my_argv[1]);

  fd = syscall(__NR_open, my_argv[1], O_RDWR);

  if(fd == -1)
  {
    print_s("error opening ");
    print_line(my_argv[1]);
    syscall(__NR_exit, 127);
  }

  print_s("[+] Was able to open ");
  print_line(my_argv[1]);

  //char param[1024];
  int param[3];
  param[0] = 2;
  param[1] = 2;
  param[2] = 2;
  my_argc = syscall(__NR_ioctl, fd, 0x12345678, 0x12345678);

  print_int(my_argc);
  print_s("\n");
  syscall(__NR_exit, 0);

}

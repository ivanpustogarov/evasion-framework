#include <stdint-gcc.h>
#include "util.h" /* Contains syscall numbers and print functions */

#define DEVNAME "PLACEHOLDER"
char dummy[] = "some value to mapp the data section";
char err_open_msg[] = "[-] error: could not open " DEVNAME "\n";
char err_write_msg[] = "[-] error: could not write to " DEVNAME "\n";
char open_msg[] = "[+] openning " DEVNAME "\n";
char ioctl_msg[] = "[+] doing ioctl on " DEVNAME "\n";
char success_open_msg[] = "open was successfull\n";
int main(int argc, char *argv[])
{
  long ret;
  int i = 0;
  dummy[0] = 'd'; // So that .data page is mapped when we go into the system call

  print_self_memmap();

  /* ** OPEN ** */

  long fd;
  print_s("[+] openning " DEVNAME "\n");
  fd = syscall(__NR_open, DEVNAME, O_RDWR);

  /* Check if succeeded, exit outherwise */
  if(fd == -1)
  {
    print_s("[-] error: could not open " DEVNAME "\n");
    syscall(__NR_exit, 0);
  }

  print_s("[+] Was able to open " DEVNAME "\n");


  /* ** IOCTL ** */

  syscall(__NR_ioctl, fd, 0x12345678, 0x12345678);
  syscall(__NR_exit, 0);
}

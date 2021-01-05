#include <unicorn/unicorn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <alloca.h>
#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <string.h> 
#include <dirent.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include "emulate.h"

#define PAGE_SIZE 0x1000
#define PAGE_MASK 0xfffffffffffff000
#define PAGE_ALIGNED(sz)  ( sz ? (((sz-1) & PAGE_MASK) + PAGE_SIZE) : 0 )
#define PAGE_START(addr)  (addr & PAGE_MASK)
#define read_whole_file read_whole_dump

#define DEBUG 0
#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define MEMDUMPS_PATH  "./memdumps/"
#define REGISTERS_PATH "./registers/qmp-registers.txt"

/* http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ */
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_IOCTL 16
#define SYS_GETSOCKOPT 55
#define SYS_IOSUBMIT 209
#define SYS_AIOWRITE 5000

/* CPU model specific register (MSR) numbers */
/* x86-64 specific MSRs */
#define MSR_EFER                0xc0000080 /* extended feature register */
#define MSR_STAR                0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR               0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR               0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK        0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE             0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE             0xc0000101 /* 64bit GS ase */
#define MSR_KERNEL_GS_BASE      0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX             0xc0000103 /* Auxiliary TSC */

/* standard registers */
#define R_EAX 0 
#define R_EBX 1 
#define R_ECX 2 
#define R_EDX 3 
#define R_ESI 4 
#define R_EDI 5 
#define R_EBP 6 
#define R_ESP 7 

/* Segment registers */
#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

#define TARGET_LONG_BITS 64
#define TARGET_ADDRESS_SIZE_BYTES 8
#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)
#if TARGET_LONG_SIZE == 8
typedef int64_t target_long;
typedef uint64_t target_ulong;
#else
#error TARGET_LONG_SIZE undefined
#endif

/* Set this to true if we reached sysret */
bool sysret_reached = false;

#define CPU_NB_REGS64 16
typedef struct CPUX86State {
  /* standard registers */
  uint64_t regs[CPU_NB_REGS64];
  uint64_t rip;
  uint32_t eflags;
  /* segments */
  uc_x86_mmr segs[6]; /* selector values */
  uc_x86_mmr ldt;
  uc_x86_mmr tr;
  uc_x86_mmr gdt; /* only base and limit are used */
  uc_x86_mmr idt; /* only base and limit are used */

  target_ulong cr[5]; /* NOTE: cr1 is unused */
  target_ulong dr[8]; /* debug registers; note dr4 and dr5 are unused */

  /* Model specific registers */
  uc_x86_msr msr_fs_base; /* rid: 0xc0000100 */
  uc_x86_msr msr_gs_base; /* rid: 0xc0000101 */
} CPUX86State;

CPUX86State cpu_state;
char *afl_input_filepath = NULL;

int hexdump(void *p, int len)
{
  unsigned char *c = (unsigned char *)p;
  for (int i = 0; i < len; i++)
  {
    debug_print("%02hhx", *c); 
    c++;
  }
  debug_print("%s","\n");
  return 0;
}

#define QMPHOST "localhost"
#define QMPPORT 4444
#define BUFSIZE 1024
#define QMP_CMD_CAPABILITES "{\"execute\":\"qmp_capabilities\"}" 
#define QMP_CMD_MEMSAVE_FMT "{ \"execute\": \"memsave\", \"arguments\": {\"val\": %ld, \"size\": %lu, \"filename\": \"%s\"} }"
/* Write new memory to Unicron from Qemu  
 *
 * 1) Issue a memsave command to QMP which will save memory to a file 
 * 2) Read this file and write the contents to Unicorn memory
 *  As a bonus, this file will be saved, so the next time you 
 *  run the emulation, it will be read before the emulation starts */
int qmp_get_memory(uc_engine *uc, uint64_t address, uint64_t size)
{
  int sockfd,n;
  char sendline[BUFSIZE];
  char recvline[BUFSIZE];
  char dump_filepath[100];
  struct sockaddr_in servaddr;
  
  sockfd=socket(AF_INET,SOCK_STREAM,0);
  bzero(&servaddr,sizeof(struct sockaddr_in));
  
  servaddr.sin_family=AF_INET;
  servaddr.sin_port=htons(QMPPORT);
  inet_pton(AF_INET,QMPHOST,&(servaddr.sin_addr));
 
  int ret = connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
  if(ret < 0)
  {
    printf("error: could not connect to QMP server, is Qemu running?\n");
    return -2;
    //exit(0);
  }
  
  /* There is a bug in QMP memsave command, which reads the address as a _signed_ long int.
   * This make Qemu erroneously refuse memsave commands with addresses outside of 
   *  [-9223372036854775807 -- 9223372036854775807] 
   *  (or [-0x7FFFFFFFFFFFFFFF -- 0x7FFFFFFFFFFFFFFF] in hex).
   * Once the check is done, Qemu converts this number back to usigned to long.
   * Example: we need to save memory at address 
   * 0xFFFFFFFFA0000000, we need to convert
   * this unsigned number to a signed negative number 
   * (i.e. to -(0xFFFFFFFFFFFFFFFF-0xFFFFFFFFA0000000+1)=-1610612736 */
  bzero( sendline, BUFSIZE);
  bzero( recvline, BUFSIZE);
  read(sockfd,recvline,BUFSIZE); /* get back capabilities string, we don't really care about it */
  debug_print("  00:Received the following back: %s",recvline);

  write(sockfd,QMP_CMD_CAPABILITES,sizeof(QMP_CMD_CAPABILITES)-1);
  bzero(recvline, BUFSIZE);
  read(sockfd,recvline,BUFSIZE); /* get back capabilities string, we don't really care about it */
  debug_print("  01:Received the following back: %s",recvline);

  /* prepare the actual memsave command */
  char cur_dir[1024];
  getcwd(cur_dir, 1024);
  //sprintf(dump_filepath, "%s/%s%016lx-%016lx.dump",cur_dir,MEMDUMPS_PATH, PAGE_START(address), PAGE_ALIGNED(address+size));
  sprintf(dump_filepath, "%s/%s%016lx-%016lx.dump",cur_dir,MEMDUMPS_PATH, PAGE_START(address), PAGE_START(address)+PAGE_ALIGNED(size));
  /* see above why we covert address to 'long int' */
  sprintf(sendline, QMP_CMD_MEMSAVE_FMT, (long int)PAGE_START(address), PAGE_ALIGNED(size), dump_filepath);
  //debug_print("  Saving new memory dump to file: %s\n",dump_filepath);
  debug_print("  Issuing the following QMP command: %s\n",sendline);
  write(sockfd,sendline,strlen(sendline)+1);
  bzero( recvline, BUFSIZE);
  read(sockfd,recvline,BUFSIZE);
  debug_print("  Received the following back: %s",recvline);
  char *err = strstr(recvline, "error");
  if(err)
  {
    printf("[-] Could not access memory, probably a bug in the driver\n"); 
    dump_registers(uc);
    remove(dump_filepath);
    close(sockfd);
    return -1;
  }

  /* Now we should have a new memdump file in ./memdumps/, let's read it */
  unsigned long int dump_vaddr; /* Virtual address of the dump */
  unsigned long int dump_vaddr_end; /* End virtual address of the dump, for debugging only */
  void *dump = NULL;
  size_t dump_size = 0;
  /* Wait until dump is read */
  struct stat statbuf;
  while ( (stat(dump_filepath,&statbuf) == -1) || (statbuf.st_size != PAGE_ALIGNED(size))) {;};
  dump = read_whole_dump(dump_filepath, &dump_size);
  dump_vaddr = PAGE_START(address);
  dump_vaddr_end = PAGE_START(address) + PAGE_ALIGNED(size);
  //debug_print("Read memdump %s\n  vaddr: [0x%lx]-[0x%lx]-1 = 0x%lx; dump_size = 0x%lx\n", 
  //           dump_filepath, dump_vaddr, dump_vaddr_end, dump_vaddr_end - dump_vaddr-1, dump_size);
  debug_print("  vaddr: [0x%lx] s:[0x%lx] -> [0x%lx] s:[0x%lx] aligned\n", 
             dump_vaddr, dump_size, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size));
  assert(dump_size == (dump_vaddr_end-dump_vaddr));
  //assert(dump_size == (dump_vaddr_end-dump_vaddr-1));

  /* Tell Unicorn that these memory ranges should be available. Memory should
     be page-aligned, otherwise it will not be allocated. */
  if(uc_mem_map(uc, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size), UC_PROT_ALL)) {
    printf("error: uc_mem_map() for %s\n", dump_filepath);
    exit(0);
  }

  /* Write dumps to emulated memory */
  int ret_code = 0;
  if(ret_code = uc_mem_write(uc, dump_vaddr, dump, dump_size)) {
    printf("error: uc_mem_write() failed to write emulation code (%s) to memory (%s)\n", dump_filepath, uc_strerror(ret_code));
    exit(0);
  }

  free(dump);
  close(sockfd);
  return 0;
}


/* Patch some known functions that we do not want to track 
 * Note: System.map consists of line of the following format: 
 * ...
 * ffffffff81727960 T _cond_resched 
 * ...             ^
 *                 [we get this position]
*/
/* Path to System.map file */
char *systemmap_path = NULL;
/* Function names to patch */
const char *symbols[] = {" T printk\n", " T _cond_resched\n"};
//const char *symbols[] = {" T printk\n" };
#define n_symbols (sizeof (symbols) / sizeof (const char *))
int patch_kernel(char *mem_image, long unsigned int image_vaddr, size_t image_sz)
{
  if (systemmap_path == NULL)
    return 0;

  unsigned long int s_offset = 0; /* Function offset in the kernel image */
  char *s_loc = NULL; /* Symbol location in System.map */
  size_t sz = 0;
  char s_addr_s[17];
  unsigned long int s_addr; /* Symbol address */
  char *content = read_whole_file(systemmap_path, &sz);
  for (int i = 0; i < n_symbols; i++) {
    s_loc = strstr(content, symbols[i]);
    if(s_loc)
    {
      strncpy(s_addr_s, s_loc - 16, 16);
      s_addr_s[16] = 0;
      s_addr = strtoul(s_addr_s, NULL, 16);
      if( (s_addr < image_vaddr) || (s_addr > image_vaddr + image_sz) ) 
        continue;
      s_offset = s_addr-image_vaddr;
      debug_print("Patching %s @ [0x%lx, ofsset=0x%lx]\n", symbols[i], s_addr, s_offset);
      assert(s_offset < image_sz);
      /* Patch with ret */
      mem_image[s_offset] = 0xc3;
    } else {
      printf("Warning: %s: could not find symbol in System.map file\n", __func__);
    }
  }
  free(content);
  return 0;
}

/* Given a <pathname> for a file, read <size> bytes to <dest>.
*
*  Memory for <dest> should be pre-allocated by the caller.
*  The function gives a warning if not all file was read
*
*  @param pathname(in)  File to read
*  @param dest(out)     Stores file content (out)
*  @param size          Read this number of bytes
*  @return Number of bytes actually read
*/
#define read_file(x) read_dump(x)
int read_dump(char *pathname, void *dest, size_t size)
{
  struct stat statbuf; // To get file size
  int fd = open(pathname, O_RDONLY);
  if (fd < 0) {
    printf("open(): Could not open file '%s'\n", pathname);
    exit(-1);
  }

  if (fstat(fd, &statbuf) == -1) {
    printf("fstat(): Could not access file '%s'\n", pathname);
    exit(-1);
  }

  if(statbuf.st_size > size)
    printf("read_dump(): WARNING: memdump contains more data than requested; file '%s'\n", pathname);

  if(statbuf.st_size < size)
    printf("read_dump(): WARNING: memdump contains less data than requested; file '%s'\n", pathname);
    
  ssize_t sz = read(fd, dest, size);
  close(fd);
  return sz;
}


int write_regs_to_uc(uc_engine *uc)
{
  /* Regular */
  uc_reg_write(uc, UC_X86_REG_RAX, &cpu_state.regs[R_EAX]);
  uc_reg_write(uc, UC_X86_REG_RBX, &cpu_state.regs[R_EBX]);
  uc_reg_write(uc, UC_X86_REG_RCX, &cpu_state.regs[R_ECX]);
  uc_reg_write(uc, UC_X86_REG_RDX, &cpu_state.regs[R_EDX]);
  uc_reg_write(uc, UC_X86_REG_RSI, &cpu_state.regs[R_ESI]);
  uc_reg_write(uc, UC_X86_REG_RDI, &cpu_state.regs[R_EDI]);
  uc_reg_write(uc, UC_X86_REG_RBP, &cpu_state.regs[R_EBP]);
  uc_reg_write(uc, UC_X86_REG_RSP, &cpu_state.regs[R_ESP]);
  uc_reg_write(uc, UC_X86_REG_R8 , &cpu_state.regs[8]);
  uc_reg_write(uc, UC_X86_REG_R9 , &cpu_state.regs[9]);
  uc_reg_write(uc, UC_X86_REG_R10, &cpu_state.regs[10]);
  uc_reg_write(uc, UC_X86_REG_R11, &cpu_state.regs[11]);
  uc_reg_write(uc, UC_X86_REG_R12, &cpu_state.regs[12]);
  uc_reg_write(uc, UC_X86_REG_R13, &cpu_state.regs[13]);
  uc_reg_write(uc, UC_X86_REG_R14, &cpu_state.regs[14]);
  uc_reg_write(uc, UC_X86_REG_R15, &cpu_state.regs[15]);
  uc_reg_write(uc, UC_X86_REG_RIP, &cpu_state.rip);

  /* EFLAGS */
  uc_reg_write(uc, UC_X86_REG_EFLAGS, &cpu_state.eflags);

  /* LDT, TR, GDT, IDT */
  uc_reg_write(uc, UC_X86_REG_LDTR, &cpu_state.ldt);
  uc_reg_write(uc, UC_X86_REG_GDTR, &cpu_state.gdt);
  uc_reg_write(uc, UC_X86_REG_IDTR, &cpu_state.idt);
  uc_reg_write(uc, UC_X86_REG_TR, &cpu_state.tr);

  /* Segment registers */
  /* In 64-bit mode, we can only write the selector value in Unicorn,
     see file qemu/target-i386/unicorn.c, function x86_reg_write */
  uc_reg_write(uc, UC_X86_REG_CS,  &cpu_state.segs[R_CS].selector);
  uc_reg_write(uc, UC_X86_REG_SS,  &cpu_state.segs[R_SS].selector);
  uc_reg_write(uc, UC_X86_REG_DS,  &cpu_state.segs[R_DS].selector);
  uc_reg_write(uc, UC_X86_REG_ES,  &cpu_state.segs[R_ES].selector);
  uc_reg_write(uc, UC_X86_REG_FS,  &cpu_state.segs[R_FS].selector);
  uc_reg_write(uc, UC_X86_REG_GS,  &cpu_state.segs[R_GS].selector);

  /* Control, note that CR1 is unused */
  //cpu_state.cr[0] = cpu_state.cr[0] | 0xffffffff00000000;
  //cpu_state.cr[0] = 0x11;
  //uc_reg_write(uc, UC_X86_REG_CR0, &cpu_state.cr[0]);
  uc_reg_write(uc, UC_X86_REG_CR2, &cpu_state.cr[2]);
  uc_reg_write(uc, UC_X86_REG_CR3, &cpu_state.cr[3]);
  uc_reg_write(uc, UC_X86_REG_CR4, &cpu_state.cr[4]);

  /* Debug, note that Qemu does not print DR4 and DR5*/
  uc_reg_write(uc, UC_X86_REG_DR0, &cpu_state.dr[0]);
  uc_reg_write(uc, UC_X86_REG_DR1, &cpu_state.dr[1]);
  uc_reg_write(uc, UC_X86_REG_DR2, &cpu_state.dr[2]);
  uc_reg_write(uc, UC_X86_REG_DR3, &cpu_state.dr[3]);
  uc_reg_write(uc, UC_X86_REG_DR6, &cpu_state.dr[6]);
  uc_reg_write(uc, UC_X86_REG_DR7, &cpu_state.dr[7]);

  /* MSR's */
  /* See https://stackoverflow.com/questions/11497563/detail-about-msr-gs-base-in-linux-x86-64 */
  cpu_state.msr_fs_base.rid = MSR_FS_BASE;
  cpu_state.msr_fs_base.value = cpu_state.segs[R_FS].base;
  uc_reg_write(uc, UC_X86_REG_MSR,  &cpu_state.msr_fs_base);
  cpu_state.msr_gs_base.rid = MSR_GS_BASE;
  cpu_state.msr_gs_base.value = cpu_state.segs[R_GS].base;
  uc_reg_write(uc, UC_X86_REG_MSR,  &cpu_state.msr_gs_base);

  return 0;

}

int read_regs_from_uc(uc_engine *uc)
{
  /* Regular */
  uc_reg_read(uc, UC_X86_REG_RAX, &cpu_state.regs[R_EAX]);
  uc_reg_read(uc, UC_X86_REG_RBX, &cpu_state.regs[R_EBX]);
  uc_reg_read(uc, UC_X86_REG_RCX, &cpu_state.regs[R_ECX]);
  uc_reg_read(uc, UC_X86_REG_RDX, &cpu_state.regs[R_EDX]);
  uc_reg_read(uc, UC_X86_REG_RSI, &cpu_state.regs[R_ESI]);
  uc_reg_read(uc, UC_X86_REG_RDI, &cpu_state.regs[R_EDI]);
  uc_reg_read(uc, UC_X86_REG_RBP, &cpu_state.regs[R_EBP]);
  uc_reg_read(uc, UC_X86_REG_RSP, &cpu_state.regs[R_ESP]);
  uc_reg_read(uc, UC_X86_REG_R8 , &cpu_state.regs[8]);
  uc_reg_read(uc, UC_X86_REG_R9 , &cpu_state.regs[9]);
  uc_reg_read(uc, UC_X86_REG_R10, &cpu_state.regs[10]);
  uc_reg_read(uc, UC_X86_REG_R11, &cpu_state.regs[11]);
  uc_reg_read(uc, UC_X86_REG_R12, &cpu_state.regs[12]);
  uc_reg_read(uc, UC_X86_REG_R13, &cpu_state.regs[13]);
  uc_reg_read(uc, UC_X86_REG_R14, &cpu_state.regs[14]);
  uc_reg_read(uc, UC_X86_REG_R15, &cpu_state.regs[15]);
  uc_reg_read(uc, UC_X86_REG_RIP, &cpu_state.rip);

  /* EFLAGS */
  uc_reg_read(uc, UC_X86_REG_EFLAGS, &cpu_state.eflags);

  /* LDT, TR, GDT, IDT */
  uc_reg_read(uc, UC_X86_REG_LDTR, &cpu_state.ldt);
  uc_reg_read(uc, UC_X86_REG_GDTR, &cpu_state.gdt);
  uc_reg_read(uc, UC_X86_REG_IDTR, &cpu_state.idt);
  uc_reg_read(uc, UC_X86_REG_TR, &cpu_state.tr);

  /* Segment registers */
  /* In 64-bit mode, we can only write the selector value in Unicorn,
     see file qemu/target-i386/unicorn.c, function x86_reg_write */
  uc_reg_read(uc, UC_X86_REG_CS,  &cpu_state.segs[R_CS].selector);
  uc_reg_read(uc, UC_X86_REG_SS,  &cpu_state.segs[R_SS].selector);
  uc_reg_read(uc, UC_X86_REG_DS,  &cpu_state.segs[R_DS].selector);
  uc_reg_read(uc, UC_X86_REG_ES,  &cpu_state.segs[R_ES].selector);
  uc_reg_read(uc, UC_X86_REG_FS,  &cpu_state.segs[R_FS].selector);
  uc_reg_read(uc, UC_X86_REG_GS,  &cpu_state.segs[R_GS].selector);

  /* Control, note that CR1 is unused */
  //cpu_state.cr[0] = cpu_state.cr[0] | 0xffffffff00000000;
  //cpu_state.cr[0] = 0x11;
  //uc_reg_read(uc, UC_X86_REG_CR0, &cpu_state.cr[0]);
  uc_reg_read(uc, UC_X86_REG_CR2, &cpu_state.cr[2]);
  uc_reg_read(uc, UC_X86_REG_CR3, &cpu_state.cr[3]);
  uc_reg_read(uc, UC_X86_REG_CR4, &cpu_state.cr[4]);

  /* Debug, note that Qemu does not print DR4 and DR5*/
  uc_reg_read(uc, UC_X86_REG_DR0, &cpu_state.dr[0]);
  uc_reg_read(uc, UC_X86_REG_DR1, &cpu_state.dr[1]);
  uc_reg_read(uc, UC_X86_REG_DR2, &cpu_state.dr[2]);
  uc_reg_read(uc, UC_X86_REG_DR3, &cpu_state.dr[3]);
  uc_reg_read(uc, UC_X86_REG_DR6, &cpu_state.dr[6]);
  uc_reg_read(uc, UC_X86_REG_DR7, &cpu_state.dr[7]);

  /* MSR's */
  cpu_state.msr_fs_base.rid = MSR_FS_BASE;
  uc_reg_read(uc, UC_X86_REG_MSR,  &cpu_state.msr_fs_base);
  cpu_state.segs[R_FS].base = cpu_state.msr_fs_base.value;

  cpu_state.msr_gs_base.rid = MSR_GS_BASE;
  uc_reg_read(uc, UC_X86_REG_MSR, &cpu_state.msr_gs_base);
  cpu_state.segs[R_GS].base = cpu_state.msr_gs_base.value;

  return 0;

}

/* Parse output from Qemu 'info registers' over QMP */
int init_registers_from_qmp(uc_engine *uc)
{
  size_t sz;
  static const char *r_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
  char *s_loc = NULL; /* Symbol location in System.map */
  char *content = read_whole_file(REGISTERS_PATH, &sz);
  s_loc = strstr(content, "RAX=");
  /* The format is copied from Qemu QMP: target/i386/helper.c, function x86_cpu_dump_state */
  sscanf(s_loc,
                    "RAX=%016" PRIx64 " RBX=%016" PRIx64 " RCX=%016" PRIx64 " RDX=%016" PRIx64 "\\r\\n"
	            "RSI=%016" PRIx64 " RDI=%016" PRIx64 " RBP=%016" PRIx64 " RSP=%016" PRIx64 "\\r\\n"
	            "R8 =%016" PRIx64 " R9 =%016" PRIx64 " R10=%016" PRIx64 " R11=%016" PRIx64 "\\r\\n"
	            "R12=%016" PRIx64 " R13=%016" PRIx64 " R14=%016" PRIx64 " R15=%016" PRIx64 "\\r\\n"
	            "RIP=%016" PRIx64 " RFL=%08x",
              &cpu_state.regs[R_EAX], &cpu_state.regs[R_EBX], &cpu_state.regs[R_ECX], &cpu_state.regs[R_EDX], 
	      &cpu_state.regs[R_ESI], &cpu_state.regs[R_EDI], &cpu_state.regs[R_EBP], &cpu_state.regs[R_ESP], 
	      &cpu_state.regs[8]    , &cpu_state.regs[9]    , &cpu_state.regs[10]   , &cpu_state.regs[11],
	      &cpu_state.regs[12]   , &cpu_state.regs[13]   , &cpu_state.regs[14]   , &cpu_state.regs[15],
	      &cpu_state.rip        , &cpu_state.eflags);
  /* Load segment registers */
  static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
  for(int i = 0; i < 6; i++) {
      s_loc = strstr(content, seg_name[i]);
      /* ES =0000 0000000000000000 00000000 00000000 */
      sscanf(s_loc+4, "%04hx %016" PRIx64 " %08x %08x", 
       &cpu_state.segs[i].selector,  &cpu_state.segs[i].base, 
       &cpu_state.segs[i].limit,     &cpu_state.segs[i].flags);
  }
  s_loc = strstr(content, "LDT");
  sscanf(s_loc, "LDT=%04hx %016" PRIx64 " %08x %08x", 
   &cpu_state.ldt.selector,  &cpu_state.ldt.base, 
   &cpu_state.ldt.limit,     &cpu_state.ldt.flags);
  s_loc = strstr(content, "TR");
  sscanf(s_loc, "TR =%04hx %016" PRIx64 " %08x %08x", 
   &cpu_state.tr.selector,  &cpu_state.tr.base, 
   &cpu_state.tr.limit,     &cpu_state.tr.flags);

  /* Other registers */
  s_loc = strstr(content, "GDT");
  sscanf(s_loc, "GDT=     %016" PRIx64 " %08x",
               &cpu_state.gdt.base, &cpu_state.gdt.limit);
  s_loc = strstr(content, "IDT");
  sscanf(s_loc, "IDT=     %016" PRIx64 " %08x",
              &cpu_state.idt.base, &cpu_state.idt.limit);
  s_loc = strstr(content, "CR0");
  sscanf(s_loc, "CR0=%08lx CR2=%016" PRIx64 " CR3=%016" PRIx64 " CR4=%08x",
                  //(uint32_t *)&cpu_state.cr[0],
                  &cpu_state.cr[0],
                    &cpu_state.cr[2],
                     &cpu_state.cr[3],
                      (uint32_t *)&cpu_state.cr[4]);
  s_loc = strstr(content, "DR0");
  sscanf(s_loc, "DR0=%016" PRIx64 " DR1=%016" PRIx64 " DR2=%016" PRIx64 " DR3=%016" PRIx64,
        &cpu_state.dr[0],&cpu_state.dr[1],&cpu_state.dr[2],&cpu_state.dr[3]);
  s_loc = strstr(content, "DR6");
  sscanf(s_loc, "DR6=%016" PRIx64 " DR7=%016" PRIx64,
         &cpu_state.dr[6], &cpu_state.dr[7]);

  /* Finally write registers to Unicorn */
  write_regs_to_uc(uc);
  free(content);
  return 0;
}

void dump_registers(uc_engine *uc)
{
  read_regs_from_uc(uc);
  printf(
           "RAX=%016" PRIx64 " RBX=%016" PRIx64 " RCX=%016" PRIx64 " RDX=%016" PRIx64 "\n"
	   "RSI=%016" PRIx64 " RDI=%016" PRIx64 " RBP=%016" PRIx64 " RSP=%016" PRIx64 "\n"
	   "R8 =%016" PRIx64 " R9 =%016" PRIx64 " R10=%016" PRIx64 " R11=%016" PRIx64 "\n"
	   "R12=%016" PRIx64 " R13=%016" PRIx64 " R14=%016" PRIx64 " R15=%016" PRIx64 "\n"
	   "RIP=%016" PRIx64 " RFL=%08x\n",
              cpu_state.regs[R_EAX], cpu_state.regs[R_EBX], cpu_state.regs[R_ECX], cpu_state.regs[R_EDX], 
	      cpu_state.regs[R_ESI], cpu_state.regs[R_EDI], cpu_state.regs[R_EBP], cpu_state.regs[R_ESP], 
	      cpu_state.regs[8]    , cpu_state.regs[9]    , cpu_state.regs[10]   , cpu_state.regs[11],
	      cpu_state.regs[12]   , cpu_state.regs[13]   , cpu_state.regs[14]   , cpu_state.regs[15],
	      cpu_state.rip        , cpu_state.eflags);
  static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
  for(int i = 0; i < 6; i++) {
      printf("%s =%04x %016" PRIx64 " %08x %08x\n", seg_name[i],
       cpu_state.segs[i].selector,  cpu_state.segs[i].base, 
       cpu_state.segs[i].limit,     cpu_state.segs[i].flags);
  }
  printf("LDT=%04x %016" PRIx64 " %08x %08x\n", 
   cpu_state.ldt.selector,  cpu_state.ldt.base, 
   cpu_state.ldt.limit,     cpu_state.ldt.flags);
  printf("TR =%04x %016" PRIx64 " %08x %08x\n", 
   cpu_state.tr.selector,  cpu_state.tr.base, 
   cpu_state.tr.limit,     cpu_state.tr.flags);

  /* Other registers */
  printf("GDT=     %016" PRIx64 " %08x\n",
               cpu_state.gdt.base, cpu_state.gdt.limit);
  printf("IDT=     %016" PRIx64 " %08x\n",
              cpu_state.idt.base, cpu_state.idt.limit);
  printf("CR0=%lx CR2=%016" PRIx64 " CR3=%016" PRIx64 " CR4=%08x\n",
                  //(uint32_t)cpu_state.cr[0],
                  cpu_state.cr[0],
                    cpu_state.cr[2],
                     cpu_state.cr[3],
                      (uint32_t)cpu_state.cr[4]);
  printf("DR0=%016" PRIx64 " DR1=%016" PRIx64 " DR2=%016" PRIx64 " DR3=%016" PRIx64 "\n",
        cpu_state.dr[0], cpu_state.dr[1], cpu_state.dr[2], cpu_state.dr[3]);
  printf("DR6=%016" PRIx64 " DR7=%016" PRIx64 "\n",
        cpu_state.dr[6], cpu_state.dr[7]);

}

/* The same as read_dump, but dynamically allocates memory, reads the data, and
 * returns the pointer and the size. The caller is responsible of freeing the
 * memory.
 * 
 * @param pathname(in) Memdump file
 * @param dump_size(out) File of the memory dump, set by this function
 * @return Pointer to the memory dump
 */
void *read_whole_dump(char *pathname, size_t *dump_size)
{
  struct stat statbuf;
  if(stat(pathname,&statbuf) == -1) {
    printf("stat(): Could not access file '%s'\n", pathname);
    exit(-1);
  }
  void *buf = malloc(statbuf.st_size);
  *dump_size = read_dump(pathname, buf, statbuf.st_size);
  return buf;
}

/* Read read memdumps files and write them to Unicorn 
 * 
 * IMPORTANT NOTE
 * Filenames MUST have the following format:
 * ffff880000000000-ffff880000200000.dump 
 * ^                ^
 * [start address]  [end address]
 * BOTH SHOULD BE 16 DIGITS NUMBERS, i.e. if you address is 0x400000
 * the filename should contain '0x0000000000400000'
 */
int init_memory_from_dumps(uc_engine *uc)
{

  DIR *dfd;
  struct dirent *dump_file;
  char *dash_loc = NULL; /* dash in-between start and end address in the dump filename */
  char s_addr_s[17];
  char e_addr_s[17];
  unsigned long int dump_vaddr; /* Virtual address of the dump */
  void *dump = NULL;
  size_t dump_size = 0;
  dfd = opendir(MEMDUMPS_PATH);
  if(dfd == NULL) {
    printf("opendir(): Could not open dir '%s'\n", MEMDUMPS_PATH);
    exit(-1);
  }
  while ((dump_file = readdir(dfd))) {
    if (!strcmp (dump_file->d_name, "."))
        continue;
    if (!strcmp (dump_file->d_name, ".."))    
        continue;
  

    /* Read the dump */
    char *fullpath = malloc(sizeof(MEMDUMPS_PATH) + strlen(dump_file->d_name) + 1);
    strncpy(fullpath, MEMDUMPS_PATH, sizeof(MEMDUMPS_PATH));
    strncat(fullpath, dump_file->d_name, strlen(dump_file->d_name));
    //debug_print("Reading dump file: %s\n", fullpath);
    dump = read_whole_dump(fullpath, &dump_size);
    free(fullpath);

    /* Get start and end addresses from the filename */
    dump_vaddr = strtoul(dump_file->d_name, NULL, 16); /* will read until '-' in between */
    dash_loc = strchr(dump_file->d_name, '-');
    assert(dash_loc && "wrong memdump filename format!");
    unsigned long int dump_vaddr_end; /* End virtual address of the dump, for debugging only */
    dump_vaddr_end = strtoul(dash_loc+1, NULL, 16);
    //debug_print("Reading memdump %s\n  vaddr: [0x%lx]-[0x%lx]-1 = 0x%lx; dump_size = 0x%lx\n", 
    //         dump_file->d_name, dump_vaddr, dump_vaddr_end, dump_vaddr_end - dump_vaddr-1, dump_size);
    //debug_print("Reading memdump %s\n  vaddr: [0x%lx]-[0x%lx] = 0x%lx; dump_size = 0x%lx\n", 
    //         dump_file->d_name, dump_vaddr, dump_vaddr_end, dump_vaddr_end - dump_vaddr, dump_size);
    //debug_print("vaddr: [0x%lx]-[0x%lx] = 0x%lx; dump_size = 0x%lx\n", 
    //         dump_vaddr, dump_vaddr_end, dump_vaddr_end - dump_vaddr, dump_size);
    debug_print("vaddr: [0x%lx] s:[0x%lx] -> [0x%lx] s:[0x%lx] aligned\n", 
             dump_vaddr, dump_size, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size));
    //assert(dump_size == (dump_vaddr_end-dump_vaddr-1));
    assert(dump_size == (dump_vaddr_end-dump_vaddr));

    patch_kernel(dump, dump_vaddr, dump_size);

    /* Tell Unicorn that these memory ranges should be available. Memory should
       be page-aligned, otherwise it will not be allocated. */
    int ret_code = 0;
    if(ret_code = uc_mem_map(uc, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size), UC_PROT_ALL)) {
      printf("error: uc_mem_map() for %s (%s)\n", dump_file->d_name, uc_strerror(ret_code));
      exit(0);
    }

    /* Write dumps to emulated memory */
    if(ret_code = uc_mem_write(uc, dump_vaddr, dump, dump_size)) {
      printf("error: uc_mem_write() failed to write emulation code (%s) to memory (%s)\n", dump_file->d_name, uc_strerror(ret_code));
      exit(0);
    }
    free(dump);
  }
}

int disass(void *buf, uint32_t size, uint64_t address)
{
  // Capstone
  csh handle;
  cs_insn *insn;
  size_t count;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;
  count = cs_disasm(handle, buf, size, address, 0, &insn);
  if (count > 0) {
       size_t j;
       for (j = 0; j < count; j++) {
           printf("    0x%"PRIx64":\t\t%s\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
		                //for(int k =0; k<insn[j].size; k++)
		                //  printf("%02hhx",insn[j].bytes[k]);
		                //printf("\n");
       }
  
       cs_free(insn, count);
  } else
    return -1;
    //printf("ERROR: Failed to disassemble given code!\n");

  return 0;
}

bool x = true;
void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
  assert(size < 16);
  void *buf = alloca(16);
  uc_mem_read(uc, address, buf, size);
  disass(buf, size, address);
}

static void hook_sysret(uc_engine *uc, void *user_data)
{
    //uint64_t rax;
    //rax = 0x200;
    sysret_reached = true;
    printf("[+] We reached sysret, which successfully ends the emulation!\n");
    uc_emu_stop(uc);
}

/* The emulated code could not read <size> butes of memory at location <address> */
bool mem_unmapped_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
  //printf("Warning: Memory unmapped error when trying to access [0x%lx]; size = %d; value = %lx. Will try to fetch from Qemu\n", address, size, value);
  printf("Memory unmapped error when trying to access [0x%lx]; size = %d; value = %lx.\n", address, size, value);
  /* This is the error path: we were not able to get the memory from Qemu.
     However it's not a definite indication of a bug in the kernel: if it happends due
     to a page fault over a user space address it's not a bug.
     In such case (user space address failed) Linux kernel does not Oops.
     Instead EAX becomes -EFAULT (== -14), the value "read" from
     the user space is 0; execution continues at address of the
             instruction immediately after the faulting user access
     Source:  https://www.kernel.org/doc/Documentation/x86/exception-tables.txt
  */
  /* If it's a user space address  */
  if( (address > 0x0000700000000000) && (address < 0x00007fffffffffff) )
  {
   /* The kernel does some complicated stuff in this case (e.g. comes back from mmu fault,
    * jumps to page_fault(), etc.), but we just simulate the final result of it here */
    debug_print("Seem it's a user space address assuming it's not a bug, and stopping the emulation%s\n","");
    uc_emu_stop(uc);
    return false;
  }
  else /* Kernel space => we found a bug (yay!) */
    return false;
}

/* The emulated code could not read <size> butes of memory at location <address> */
bool mem_unmapped_hook_old(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
  printf("Warning: Memory unmapped error when trying to access [0x%lx]; size = %d; value = %lx. Will try to fetch from Qemu\n", address, size, value);
  int err = qmp_get_memory(uc, address, size);
  if(err == -1) /* Qemu could not access this memory: memory was not allocated */
  {
    /* This is the error path: we were not able to get the memory from Qemu.
       However it's not a definite indication of a bug in the kernel: if it happends due
       to a page fault over a user space address it's not a bug.
       In such case (user space address failed) Linux kernel does not Oops.
       Instead EAX becomes -EFAULT (== -14), the value "read" from
       the user space is 0; execution continues at address of the
               instruction immediately after the faulting user access
       Source:  https://www.kernel.org/doc/Documentation/x86/exception-tables.txt
    */
    /* If it's a user space address  */
    if( (address > 0x0000700000000000) && (address < 0x00007fffffffffff) )
    {
     /* The kernel does some complicated stuff in this case (e.g. comes back from mmu fault,
      * jumps to page_fault(), etc.), but we just simulate the final result of it here */
      debug_print("Seem it's a user space address, emulatin Kernel level exception handling in Linux%s\n","");
      //exit(0);
      uc_emu_stop(uc);
      return false;
#if 0
      int ret_code = 0;
      uint64_t efault = -14;
      uc_reg_write(uc, UC_X86_REG_RAX, &efault);
      if(ret_code = uc_mem_map(uc, PAGE_START(address), PAGE_ALIGNED(size), UC_PROT_ALL)) {
        printf("error: uc_mem_map() (%s)\n", uc_strerror(ret_code));
	return false;
      }
      return true;
#endif
    }
    else /* Kernel space => we found a bug (yay!) */
      //raise(SIGSEGV);
      return false;
  }
  if(err == -2) /* Qemu is not running, stop the emulation */
  {
    printf("Stopping emulation due to errors\n");
    uc_emu_stop(uc);
    return false;
  }
  /* We were able to get the memory from Qemu, retru the instruction */
  return true;
}

/* Print usage and exit */
void usage()
{
  printf("\nusage: emulate [-h] -a SYSCALL [-s System.map] [-f AFLINPUT]\n");
  printf("Emulate code from ./memdumps and ./registers\n\n");
  printf("OPTIONS:\n\n");
  printf(" -h         Help message\n\n");
  printf(" -f FILE    Consume this file for fuzzing (e.g. afl)\n\n");
  printf(" -a SYSCALL System call to fuzz, can be one of (read,write,open,ioctl)\n\n"
         "            You need to speficy this this because we fuzz different arguments\n"
         "            for different system calls\n\n");
  printf(" -s FILE    Path to System.map for kernel which was used\n"
         "            to compile the module under test.\n\n"
	 "            This is used to get addresses of function we want to skip.\n"
	 "            Most probably it was extracted by prepare-emulation.sh\n"
         "            script and put into the current directory\n");
  exit(0);
}

/* Convert system call name to system call number 
   return -1 if system call was not recognized or is not currently supported */
int syscallname2num(char *syscall_name)
{
  if(syscall_name == NULL)
    return -1;

  if(strncmp(syscall_name, "read", sizeof("read")) == 0)
    return SYS_READ;

  if(strncmp(syscall_name, "write", sizeof("write")) == 0)
    return SYS_WRITE;

  if(strncmp(syscall_name, "open", sizeof("open")) == 0)
    return SYS_OPEN;

  if(strncmp(syscall_name, "ioctl", sizeof("ioctl")) == 0)
    return SYS_IOCTL;

  if(strncmp(syscall_name, "getsockopt", sizeof("getsockopt")) == 0)
    return SYS_GETSOCKOPT;

  if(strncmp(syscall_name, "aiowrite", sizeof("aiowrite")) == 0)
    return SYS_AIOWRITE;

  if(strncmp(syscall_name, "iosubmit", sizeof("iosubmit")) == 0)
    return SYS_IOSUBMIT;

  return -1;
}

int fuzz_syscall = -1;
int arg_parse(int argc, char **argv)
{
  int opt;
  while ((opt = getopt (argc, argv, "hs:f:a:")) != -1)
  {
    switch (opt)
    {
      case 'a':
                //printf ("[+] Going to fuzz \"%s\"\n", optarg);
		fuzz_syscall = syscallname2num(optarg);
                break;
      case 'f':
                //printf ("[+] Using file \"%s\" to alf fuzz\n", optarg);
		afl_input_filepath = optarg;
                break;
      case 'h':
                usage();
                break;
      case 's':
                //printf ("[+] Using file \"%s\" to find symbol addresses\n", optarg);
		systemmap_path = optarg;
                break;
    }
  }
  //printf("fuzz_syscall = %d\n", fuzz_syscall);
  if( (afl_input_filepath != NULL) && (fuzz_syscall == -1) )
  {
    printf("error: please specify which system call you'd like to fuzz with '-a'\n");
    return -1;
  }
  return 0;
}

#define MAX_INST_SIZE_X86 15
/* Search for a 'ret' instruction starting from <s_addr> */
target_ulong seek_function_end(uc_engine *uc, target_ulong s_addr)
{
  csh handle;
  cs_insn *insn;
  size_t count;
  const int insts_to_read = 1; /* we are going to read 1 instruction at a time */
  void *buf = alloca(insts_to_read*MAX_INST_SIZE_X86);
  //uint32_t offset = 0;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return -1;

  for(;;)
  {
    //printf("Disassembling at %lx\n", s_addr);
    if(uc_mem_read(uc, s_addr, buf, insts_to_read*MAX_INST_SIZE_X86)) {
      printf("error: uc_mem_read() called from seek_function_ret\n");
      exit(0);
    }
    count = cs_disasm(handle, buf, insts_to_read*MAX_INST_SIZE_X86, s_addr, insts_to_read, &insn);
    for (int j = 0; j < count; j++) {
      printf("    0x%"PRIx64":\t\t%s\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
      if(insn[j].id == X86_INS_RET)
      {
        //debug_print("Function ends at %lx\n", insn[j].address);
        return insn[j].address;
      }
    }
    s_addr = insn[count-1].address+insn[count-1].size;
    cs_free(insn, count);
  }
  printf("Warning: function end was not found, returning 0!\n");
  exit(0);
  return 0;
}

#define NOP 0x90
/* Replace a single the first two bytes with NOP's, execute, put original bytes back.
   We cannot just execute the first instruction, as it will change registers (e.g. 'push rbp'
   will change rsp)
*/
uc_err execute_single_nop(uc_engine *uc)
{
  uint8_t b1,b2;
  uint8_t nop = NOP;
  uc_err err;
  uc_mem_read(uc, cpu_state.rip, &b1, 1);
  uc_mem_read(uc, cpu_state.rip+1, &b2, 1);
  uc_mem_write(uc, cpu_state.rip, &nop, 1);
  uc_mem_write(uc, cpu_state.rip+1, &nop, 1);
 
  /* This is where is the fork server spins off */
  err=uc_emu_start(uc, cpu_state.rip, cpu_state.rip+1, 0, 1);

  uc_mem_write(uc, cpu_state.rip, &b1, 1);
  uc_mem_write(uc, cpu_state.rip+1, &b2, 1);
  return err;

}

/* Replace user input for 'io_submit' system call with afl mutated input 
 * 
 * The system call is of the following form:
 *
 * io_submit( (1) aio_context_t ctx_id, (2) long nr, (3) struct iocb ** iocbpp)
 * 
 * <iocbpp> is an array of pointers to struct iocb. We assumet that the test program
 * which is used to get the memory dumps puts only one element in this array, and
 * <nr> is thus set to 1.
 *   Note that  
 *       struct iocb {
 *           __u64   aio_data;
 *           __u32   PADDED(aio_key, aio_reserved1);
 *           __u16   aio_lio_opcode;
 *           __s16   aio_reqprio;
 *           __u32   aio_fildes;
 *           __u64   aio_buf;
 *           __u64   aio_nbytes;
 *           __s64   aio_offset;
 *           ...
 *      };
 * 
 *  Currently we want to leave the <aio_buf> as it is and fuzz values of
 *  <aio_nbytes> and <aio_offset>.
 *
 * User-level applications use as integer registers for passing the sequence
 * (1) %rdi, (2) %rsi, (3) %rdx, (4) %rcx, %r8 and %r9.
 *
 * The kernel interface uses 
 * (1) %rdi, (2) %rsi, (3) %rdx, (4) %r10, %r8 and %r9
 *
 * This means we need to get the address of <iocbpp> from RDX.
 * In order to fuzz <aio_nbytes> we need offset 8+4+4+2+2+4+8=32
 * In order to fuzz <aio_offset> we need offset 8+4+4+2+2+4+8+8=40
 * 
 */
uc_err prepare_fuzz_io_submit(uc_engine *uc)
{
  char *afl_input;
  size_t afl_input_size;
  uint64_t iocbpp; /* Points to list of pointers */ 
  uint64_t iocbp;  /* Points to the first element iocb */
  uint64_t aio_nbytesp; /* Points to aio_nbytes field */
  uint64_t aio_offsetp; /* Points to aio_offset field */
  uint64_t aio_nbytes;
  uint64_t aio_offset;
  if(afl_input_filepath == NULL)
    return -1;

  uc_reg_read(uc, UC_X86_REG_RDX, &iocbpp);
  if(uc_mem_read(uc, iocbpp, &iocbp, TARGET_ADDRESS_SIZE_BYTES))
  {
    debug_print("prepare_fuzz_io_submit(): could not fetch memory for address 0x%lx\n", iocbpp);
    return -1;
#if 0
    int err = qmp_get_memory(uc, iocbpp, 8);
    if(err < 0)
      return -1;
    /* retry */
    if(uc_mem_read(uc, iocbpp, &iocbp, TARGET_ADDRESS_SIZE_BYTES))
      return -1;
#endif
  }
  aio_nbytesp = iocbp+32;
  aio_offsetp = iocbp+40;

#if 0
  {
    long nr;
    uc_reg_read(uc, UC_X86_REG_RSI, &nr);
    uc_mem_read(uc, aio_nbytesp, &aio_nbytes, 8);
    uc_mem_read(uc, aio_offsetp, &aio_offset, 8);
    debug_print("prepare_fuzz_io_submit(): nr = 0x%08lx\n", nr);
    debug_print("prepare_fuzz_io_submit(): iocbpp = 0x%016lx\n", iocbpp);
    debug_print("prepare_fuzz_io_submit(): iocbp = 0x%016lx\n", iocbp);
    debug_print("prepare_fuzz_io_submit(): aio_nbytes = 0x%016lx\n", aio_nbytes);
    hexdump(&aio_nbytes, 8);
    debug_print("prepare_fuzz_io_submit(): aio_offset = 0x%016lx\n", aio_offset);
    hexdump(&aio_offset, 8);
    exit(0);
  }
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size);
  /* We need exactly 8+8=16 bytes for two fields */ 
  if(afl_input_size  != 16)
    return -2;

  uc_mem_write(uc, aio_nbytesp, afl_input,   8);
  uc_mem_write(uc, aio_offsetp, afl_input+8, 8);

  //debug_print("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
  free(afl_input);
  return 0;
}

/* Replace user input for 'aio_write' system call with afl mutated input 
 * 
 * The system call is of the following form:
 * static ssize_t tun_chr_aio_write((1) struct kiocb *iocb, (2) const struct iovec *iv,
 *                               (3) unsigned long count, (4) loff_t pos)
 *
 *
 *   Note that  
 *      struct iovec {
 *           void __user *iov_base; 
 *           __kernel_size_t iov_len;
 *      };
 * 
 *  So we need to put the data to .iov_base and the lenght to .iov_len
 *  We leave <count> as it is
 *
 * The first six integer or pointer arguments are passed in
 * registers (1) RDI, (2) RSI, (3) RDX, (4) RCX, (5) R8, (6) R9.
 * This means we need to get the address of <iv> from RSI.
 * In order to fuzz the contents of <iov_base> we need offset 0 from this address.
 * We need to update <iov_len> at offset 8
 * 
 */
uc_err prepare_fuzz_aio_write(uc_engine *uc)
{
  char *afl_input;
  size_t afl_input_size;
  uint64_t iv; 
  uint64_t iov_base; 
  uint64_t iov_len;
  char fb;
  if(afl_input_filepath == NULL)
    return -1;

  uc_reg_read(uc, UC_X86_REG_RSI, &iv);
  uc_mem_read(uc, iv, &iov_base, sizeof(iov_base));
  uc_mem_read(uc, iv+8, &iov_len, sizeof(iov_len));


#if 0
  {
    uc_mem_read(uc, iov_base, &fb, 1);
    debug_print("prepare_fuzz_aiowrite(): iov_base = 0x%lx\n", iov_base);
    debug_print("prepare_fuzz_aiowrite(): iov_len = 0x%lx\n", iov_len);
    debug_print("prepare_fuzz_aiowrite(): iov_base[0] = %c\n", fb);
    exit(0);
  }
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size);

  uc_mem_write(uc, iov_base, afl_input, afl_input_size);
  uc_mem_write(uc, iov_len, &afl_input_size, sizeof(afl_input_size));

  //debug_print("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
  free(afl_input);
  return 0;
}

/* Replace user input for 'getsockopt' system call with afl mutated input 
 * 
 * The system call is of the following form:
 *   int getsockopt( (1)struct socket *sock, (2) int level, 
 *                  (3) int optname, (4) char __user *optval, (5) int __user *optlen)
 * We want to point <optval> parameter to AFL's mutated input and set optlen
 * approprately. The first six integer or pointer arguments are passed in
 * registers (1) RDI, (2) RSI, (3) RDX, (4) RCX, (5) R8, (6) R9.
 * This means we need to change registers RCX and R8.
 * 
 */
uc_err prepare_fuzz_getsockopt(uc_engine *uc)
{
  char *afl_input;
  size_t afl_input_size;
  uint64_t optval; 
  uint64_t optlen;
  if(afl_input_filepath == NULL)
    return -1;
  uc_reg_read(uc, UC_X86_REG_RCX, &optval);
  uc_reg_read(uc, UC_X86_REG_R8, &optlen);

#if 0
  /* For DEBUG purposes */
  debug_print("prepare_fuzz_getsockopt(): optval = 0x%lx\n", optval);
  int tmp_len;
  uc_mem_read(uc, optlen, &tmp_len, sizeof(tmp_len));
  char *tmp_val = alloca(tmp_len);
  uc_mem_read(uc, optval, tmp_val, tmp_len);
  debug_print("prepare_fuzz_getsockopt(): *optlen = %d\n", tmp_len);
  //debug_print("prepare_fuzz_getsockopt(): *optval = %s","\n");
  for(int i = 0; i < tmp_len; i++)
    printf("%02hhx", *(tmp_val+i));
  printf("\n");
  exit(0);
  /* For DEBUG purposes */
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size);

  uc_mem_write(uc, optval, afl_input, afl_input_size);
  uc_mem_write(uc, optlen, &afl_input_size, sizeof(afl_input_size));

  //debug_print("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
  free(afl_input);
  //exit(0);
  return 0;
}

/* Replace user input for 'ioctl' system call with afl mutated input 
 * 
 * Read register RDX which is the third argument that contains the
 * pointer to user's data. Write afl mutated input to this address.
 */
uc_err prepare_fuzz_ioctl(uc_engine *uc)
{
  if(afl_input_filepath == NULL)
    return -1;
  size_t afl_input_size;
  /* Third argument is in RDX; it's a long integer which can either be just an
   * integer or a pointer to user's data */
  uint64_t user_data; 
  uc_reg_read(uc, UC_X86_REG_RDX, &user_data);

  printf("prepare_fuzz_ioctl(): user_data = %lx\n", user_data);
  /* Try to read from this location, if we can read, probably it's third argument is a pointer */
  char buf[100];
  if(uc_mem_read(uc, user_data, buf, 100)) {
    printf("prepare_fuzz_ioctl(): Cannot acess memory, seems like thrid arg is not a pointer\n");
    printf("Try to run emulation (i.e. not -f option) once, and then retry fuzzing\n");
    exit(0); /* FIXME: DEBUG exit */
  };
  
  char *afl_input = read_whole_file(afl_input_filepath, &afl_input_size);

  uc_mem_write(uc, user_data, afl_input, afl_input_size);

  free(afl_input);
  return 0;
}

/* Replace user input for 'read' system call with afl mutated input 
 * 
 * Read register RSI which is the second argument that contains the
 * pointer to user's data. Write afl mutated input to this address 
 */
uc_err prepare_fuzz_read(uc_engine *uc)
{
  if(afl_input_filepath == NULL)
    return -1;
  size_t afl_input_size;
  uint64_t user_address; /* Pointer to user-space buffer */
  uint64_t user_len;     /* Length, specified by the user */
  /* Get original second and third arguments, which are stored in RSI and RDX,
     the second is the most important as it contains the pointer to the user's input
     that we need to mutate */
  uc_reg_read(uc, UC_X86_REG_RSI, &user_address);
  uc_reg_read(uc, UC_X86_REG_RDX, &user_len);
  //printf("user_address = %lx\n", user_address);
  //printf("user_len = %lu\n", user_len);

  char *afl_input = read_whole_file(afl_input_filepath, &afl_input_size);
  //printf("afl_input = %02hhx:%02hhx\n", afl_input[0],afl_input[1]);
  //printf("afl_input_size = %lu\n", afl_input_size);

  uc_mem_write(uc, user_address, afl_input, afl_input_size);
  uc_reg_write(uc, UC_X86_REG_RDX, &afl_input_size);

  //char buf[1024];
  //uc_mem_read(uc, user_address, buf, user_len);
  //printf("new_user_input = %02hhx:%02hhx\n", buf[0],buf[1]);
  //exit(0);
  free(afl_input);
  return 0;
}

uc_err prepare_fuzzer(uc_engine *uc)
{
  
  switch(fuzz_syscall) {

     case SYS_READ :
       return prepare_fuzz_read(uc);
     break;

     case SYS_IOCTL :
       return prepare_fuzz_ioctl(uc);
     break;

     case SYS_GETSOCKOPT :
       return prepare_fuzz_getsockopt(uc);
     break;

     case SYS_AIOWRITE :
       return prepare_fuzz_aio_write(uc);
     break;

     case SYS_IOSUBMIT :
       return prepare_fuzz_io_submit(uc);
     break;

     default :
       return -1;
   };
}

int main(int argc, char **argv, char **envp)
{
  clock_t tstart, tend;
  double cpu_time_used;
  tstart = clock();
  uc_engine *uc;
  uc_err err;

  if(arg_parse(argc, argv) < 0)
  {
    printf("Failed to parse arguments\n");
    return -1;
  }

  /* 1. Initialize emulator in X86-64bit mode */
  err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  /* 2. Read register and memory dumps dumps */
  printf("[+] Initializing registers from registers/qmp-registers.txt\n");
  init_registers_from_qmp(uc);
  if(DEBUG)
    dump_registers(uc);
  printf("[+] Initializing memory from dumps in ./memdumps/ folder\n");
  init_memory_from_dumps(uc);

  /* 3. Add hooks */
  if(DEBUG)
  {
    uc_hook hh_code;
    uc_hook_add(uc, &hh_code, UC_HOOK_CODE, code_hook, NULL, 1, 0);
  }
  //uc_hook hh_fetch;
  //uc_hook_add(uc, &hh_fetch, UC_HOOK_MEM_FETCH_UNMAPPED, mem_fetch_unpammedhook, NULL, 1, 0);
  // hook interrupts for syscall
  uc_hook trace1;
  if(uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_sysret, NULL, 1, 0, UC_X86_INS_SYSRET))
  {
    printf("error: uc_hook_add() for UC_HOOK_INSN_SYSRET\n");
    exit(0);
  }
  uc_hook hh_unmapped;
  if(uc_hook_add(uc, &hh_unmapped, UC_HOOK_MEM_UNMAPPED, mem_unmapped_hook, NULL, 1, 0))
  {
    printf("error: uc_hook_add() for UC_HOOK_MEM_UNMAPPED\n");
    exit(0);
  }

  tend = clock();
  cpu_time_used = ((double) (tend - tstart)) / CLOCKS_PER_SEC;
  printf("Initialization took %f seconds\n", cpu_time_used);
  tstart = clock();
  /* 4. Optionally prepare AFL */
  if( (afl_input_filepath != NULL) && (fuzz_syscall >= 0) ){
    /* emulate a single instruction; this will force a block to be translated which will run the forkserver */
    if(execute_single_nop(uc)) {
      printf("execute_single_nop() failed\n");
      exit(0);
    }

    /* Specific for fuzzing 'read' system call: buffer address and and
     * buffer size are passed  to the callback in RSI and RDX respectively */
    if(prepare_fuzzer(uc) < 0) {
      printf("prepare_fuzzer() failed, segfaulting!\n");
      raise(SIGSEGV);
      //exit(0);
    }
  }

  /* 5 emulate code in infinite time & unlimited instructions */
  //target_ulong emulation_end_addr = seek_function_end(uc, cpu_state.rip);
  //printf("[+] Starting emulation from [0x%lx] to [0x%lx]\n", cpu_state.rip, emulation_end_addr);
  err=uc_emu_start(uc, cpu_state.rip, 0, 0, 0);
  //err=uc_emu_start(uc, cpu_state.rip, emulation_end_addr, 0, 3);
  if (err) { /* This is set if there were memory unmapped errors due to bugs in the kernel */
    printf("Warning: uc_emu_start() %u: %s\n", err, uc_strerror(err));
    raise(SIGSEGV);
    //if(!sysret_reached) {
    //  printf("[+] it's not sysret, firing segfault\n");
    //  raise(SIGSEGV);
    //} else {
    //  printf("[+] This happened because we reached the end of emulation, all is good!\n");
    //}
  }

  // now print out some registers
  uint64_t reg;
  uc_reg_read(uc, UC_X86_REG_RSP, &reg);
  printf(">>> RiP = 0x%lx\n", reg);
  tend = clock();
  cpu_time_used = ((double) (tend - tstart)) / CLOCKS_PER_SEC;
  printf("Emulation only took %f seconds\n", cpu_time_used);

  //void *buf = alloca(256);
  //uc_mem_read(uc, 0x6010a0, buf, 8);
  //printf("[0x0x6010a0] = %lx\n", *(long int unsigned *)buf);

  //uc_mem_read(uc, 0xffffffffa0000520, buf, 256);
  //printf("[0xffffffffa0000520] = %7s\n", (char *)buf);

  uc_close(uc);

  return 0;
}

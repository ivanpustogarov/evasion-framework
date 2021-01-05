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
#include <sys/mman.h>
#include "emulate-arm64.h"
#include "qmp-settings.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <execinfo.h>
//#include "cpreg_util.h"

#define USE_MALLOC 0
#define USE_MMAP 1

/* Set this to true if we reached sysret */
bool sysret_reached = false;

CPUARM64State cpu_state;
char *afl_input_filepath = NULL;
char *afl_input_start = NULL;
char *afl_input = NULL;
size_t afl_input_size = 0;
const char *ioctl_schema_filename = NULL;
unsigned long ioctl_cmd = 0;
xmlDocPtr doc = NULL; /* ioctl struct xml scheme from file */
//iotctl_scheme_t reciostruct; /* Recovered IOCTL structure */
#ifdef DYNAMICRECOVERY
xmlNodePtr copy_from_user_array = NULL; /* This variable contains the xml array node that was processed by access_ok() and is going to to to __copy_from_user(). We use it to update 'kaddr' property of this array. */
//const char *xmlschemetmp = XMLSCHEMETMP;
char *xmlschemetmp = NULL;
#endif

int print_hex(void *p, int len)
{
  unsigned char *c = (unsigned char *)p;
  for (int i = 0; i < len; i++)
  {
    printf("%02hhx ", *c); 
    c++;
  }
  printf("%s","\n");
  return 0;
}

/* Conver byte array <src> of length <src_len> to a string <result>
 * The caller should allocate the proper amount of memory for the result */
int byte2hex(void *src, int src_len, char *result)
{
  unsigned char *c = (unsigned char *)src;
  int i = 0;
  for (i = 0; i < src_len; i++)
  {
    sprintf(result+2*i, "%02hhx", *c); 
    c++;
  }
  return i;
}

/* Obtain a backtrace and print it to stdout. */
void
print_trace (void)
{
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  printf ("Obtained %zd stack frames.\n", size);

  for (i = 0; i < size; i++)
     printf ("%s\n", strings[i]);

  free (strings);
}

int uc_print_mem(uc_engine *uc, ADDR_T address, uint64_t len)
{
  char buf[4096];
  if(len >= 4096)
  {
    printf("%s(): len larger than 4096 are not suported\n", __func__);
    return -1;
  }
  printf("[DEBUG]: uc memory at address 0x%lx: ", address);
  uc_mem_read(uc, address, buf, len);
  print_hex(buf, len);
  return 0; 
}

/* TODO: check that the reg is a valid register */
void print_register(uc_engine *uc, uc_arm64_reg reg)
{
  REG_T reg_val = 0;
  char reg_name[4];
  //uc_reg_read(uc, UC_ARM64_REG_X0+reg_num, &reg_val);
  uc_reg_read(uc, reg, &reg_val);
  reg_to_str_gdb(reg_name ,reg);
  printf("    %s= 0x%lx\n", reg_name, reg_val);
  return;
}

/* User space allocator, you should watch "Charlie the Unicorn" */
void init_charlie_allocator(uc_engine *uc)
{
  ADDR_T base = 0x10000000;
  uint32_t size = 1 << 20; /* 1MB */
  if(uc_mem_map(uc, PAGE_START(base), PAGE_ALIGNED(size), UC_PROT_ALL)) {
    printf("error: uc_mem_map() during charlie allocator initialization\n");
    exit(0);
  }
  return;
}

/* Return the current value of brk, and then increase it by <size> */
ADDR_T charlie_memalloc(uint32_t size)
{
  static ADDR_T brk = 0x10000000; 
  ADDR_T prev_brk = brk;
  brk = brk + size;
  return prev_brk;
}

/* Kernel space allocator (candy mountain) */
void init_candy_allocator(uc_engine *uc)
{
  ADDR_T base = 0x11000000;
  uint32_t size = 1 << 22; /* 4MB */
  if(uc_mem_map(uc, PAGE_START(base), PAGE_ALIGNED(size), UC_PROT_ALL)) {
    printf("error: uc_mem_map() during candy allocator initialization\n");
    exit(0);
  }
  return;
}

/* Return the current value of brk, and then increase it by <size> */
ADDR_T candy_memalloc(uint32_t size)
{
  static ADDR_T brk = 0x11000000; 
  ADDR_T prev_brk = brk;
  brk = brk + size;
  if(brk > 0x11400000)
  {
    printf("error: candy allocator is out of memory (4MB)\n");
    exit(0);
  }
  return prev_brk;
}



/* Disassemble the dump and find inlined copy_from_user() functions.
   In fact we are looking for __access_ok() function (which is a macros itself)
   that precedes the call to __copy_from_user() (note the __ at the beginning).
   sequence of instructions: adds ...
                             csel ...
			     csinv ...
			     sbcs ...
			     cset

   0x0800016c      214000b1       adds x1, x1, 0x10
   0x08000170      e083809a       csel x0, xzr, x0, hi
   0x08000174      21309fda       csinv x1, x1, xzr, lo
   0x08000178      3f0000fa       sbcs xzr, x1, x0
   0x0800017c      e1879f9a       cset x1, ls


Note that registers can change, so we only search for instruction types

@return Return the number of times copy_from_user() was identified
@param recovered_addresses Linked list containing addresses of copy_from_user() 'calls'.
                           The list should be initialized by the caller (use ugly_list_init()).

*/
int get_copyfromuser_uses(char *mem_image, long unsigned int image_vaddr, size_t image_sz, ugly_list_t *recovered_addresses_lst)
{
  csh handle;
  cs_insn *all_insn;
  size_t count;
  size_t total_disassembled=0;
  uint64_t offset = 0;

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
    return -1;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

  /* There can be invalid instructions (like literal addresses) between
   * functions in which case capstone will stop disassemling. This is why we
   * need to check if we reached the end of the memory dump, and restart
   * disassembling if not */
  do {
    count = cs_disasm(handle, mem_image+offset, image_sz-offset, image_vaddr+offset, 0, &all_insn);
    total_disassembled=total_disassembled+count;
    //if(count) {DBG("%s(): Disassembled %lu instructions starting from 0x%lx", __func__, count, image_vaddr+offset);}
    if (count > 4) 
    {
      size_t j;
      for (j = 0; j < count-5; j++)
      {
        cs_insn *i0 = &(all_insn[j]);
        cs_insn *i1 = &(all_insn[j+1]);
        cs_insn *i2 = &(all_insn[j+2]);
        cs_insn *i3 = &(all_insn[j+3]);
        cs_insn *i4 = &(all_insn[j+4]);

        if ( (i0->id == ARM64_INS_ADD) &&  (i1->id == ARM64_INS_CSEL) && 
             (i2->id == ARM64_INS_CSINV) &&  (i3->id == ARM64_INS_SBC)  && (i4->id == ARM64_INS_CSET) ) 
        {
          /* For the first instruction, adds, we should have 3 operands: reg, reg, reg or imm */
          assert(i0->detail->arm64.op_count == 3);
	  DBG("  access_ok():");
          DBG("    0x%lx:    %s    %s", i0->address, i0->mnemonic, i0->op_str);
          DBG("    0x%lx:    %s    %s", i1->address, i1->mnemonic, i1->op_str);
          DBG("    0x%lx:    %s    %s", i2->address, i2->mnemonic, i2->op_str);
          DBG("    0x%lx:    %s    %s", i3->address, i3->mnemonic, i3->op_str);
          DBG("    0x%lx:    %s    %s", i4->address, i4->mnemonic, i4->op_str);
          
          //DBG("    Number of operands in the first instruction: %u\n", i0->detail->arm64.op_count);
          const int num_of_adds_operands = 3;
          pair_t *op_details = malloc(num_of_adds_operands * sizeof(pair_t));
          int k;
          /* We are at 'adds' instrution. It has 3 operands, we need to store
           * register numbers and the value of the immediate (if present) */
          for (k = 0; k < num_of_adds_operands; k++)
          {
            op_details[k].type = i0->detail->arm64.operands[k].type;
            if(op_details[k].type == CS_OP_REG) {
              op_details[k].value = i0->detail->arm64.operands[k].reg;
              //DBG("operand %d is X%ld\n", k, op_details[k].value-UC_ARM64_REG_X0);
            }
            else if(op_details[k].type == CS_OP_IMM) {
              op_details[k].value = i0->detail->arm64.operands[k].imm;
              //DBG("operand %d is imm=%lx\n", k, op_details[k].value);
            }
            else
            {
              printf("error: wrong type of adds operand when looking for copy_from_user function, report the bug to ivan@ipust.net.\n");
              exit(-1);
            }
          } /* for 'k' loop */
          ugly_list_add(recovered_addresses_lst, i0->address, op_details);
        }
      } /* for 'j' loop */
    } /* if count > 4 */ 

    if(count > 0)
      offset = all_insn[count-1].address - image_vaddr + INST_SIZE;
    else
      offset = offset+INST_SIZE; /* if not instructions at this address, move to the next 4 bytes */

    cs_free(all_insn, count);
  } while ( (offset+INST_SIZE) < image_sz );
  DBG("%s(): Disassembled %lu instructions", __func__, total_disassembled);
  return 0;
}


/* Disassemble the dump and find get_user macros's.

#define __get_user_check(x, ptr, err)					\
({									\
	__typeof__(*(ptr)) __user *__p = (ptr);				\
	might_fault();							\
	if (access_ok(VERIFY_READ, __p, sizeof(*__p))) {		\  <---- we already have access_ok()
		__p = uaccess_mask_ptr(__p);				\  <---- we search for these 3 instructions (see below)
		__get_user_err((x), __p, (err));			\  <---- and these 4 instructions (see below)
	} else {							\
		(x) = 0; (err) = -EFAULT;				\
	}								\
})

uaccess_mask_pt:
    bics    xzr, x1, x3
    csel    x2, x1, xzr, eq
    csdb                    

__get_user_err:
    nop
    mov     w0, #0x0  <--- this is one is optional
    ldrh    w1, [x2]  <--- this can be: ldrb, ldrh, ldr
    nop

Note that registers can change, so we only search for instruction types

@param recovered_addresses Linked list containing addresses of copy_from_user() 'calls'.
                           The list should be initialized by the caller (use ugly_list_init()).

*/
int is_load_insn(cs_insn *i)
{
  unsigned int id = i->id;
  if( (id == ARM64_INS_LDRB)  ||
      (id == ARM64_INS_LDRH)  ||
      (id == ARM64_INS_LDR)   ||
      (id == ARM64_INS_LDTRB) ||
      (id == ARM64_INS_LDTRH) ||
      (id == ARM64_INS_LDTR)) return 1;
  return 0;
}
int load_insn_get_dest_size(cs_insn *i)
{
  unsigned int id = i->id;
  uc_arm64_reg reg = i->detail->arm64.operands[0].reg; /* if it's wn, then ldr copies 32bits, if xn, then 64bits */
  if( (id==ARM64_INS_LDRB) || (id==ARM64_INS_LDTRB) ) return 1;
  if( (id==ARM64_INS_LDRH) || (id==ARM64_INS_LDTRH) ) return 2;
  if( (id==ARM64_INS_LDR)  || (id==ARM64_INS_LDTR ) )
  {
    if( (reg >= UC_ARM64_REG_W0) && (reg <= UC_ARM64_REG_W30) ) return 4;
    if( (reg >= UC_ARM64_REG_X0) && (reg <= UC_ARM64_REG_X28) ) return 8; /* Let's hope the assembler never chooses X29 and X30 for ldr instruction */
  }
  assert(0); /* bug: if this happens we either picked the wrong intruction or did not forsee something */
}
int get_getuser_uses(char *mem_image, long unsigned int image_vaddr, size_t image_sz, ugly_list_t *recovered_addresses_lst)
{
  csh handle;
  cs_insn *all_insn;
  size_t count;
  size_t total_disassembled=0;
  uint64_t offset = 0;

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
    return -1;
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON

  /* There can be invalid instructions (like literal addresses) between
   * functions in which case capstone will stop disassemling. This is why we
   * need to check if we reached the end of the memory dump, and restart
   * disassembling if not */
  do {
    count = cs_disasm(handle, mem_image+offset, image_sz-offset, image_vaddr+offset, 0, &all_insn);
    total_disassembled=total_disassembled+count;
    if (count >= 7) 
    {
      size_t j;
      for (j = 0; j < count-7; j++)
      {
        cs_insn *i0 = &(all_insn[j]);
        cs_insn *i1 = &(all_insn[j+1]);
        cs_insn *i2 = &(all_insn[j+2]);
        cs_insn *i3 = &(all_insn[j+3]);
        cs_insn *i4 = &(all_insn[j+4]); /* movz which might not be present */
        cs_insn *i5 = &(all_insn[j+5]); /* this one the load instruction with the address we need */
        cs_insn *i6 = &(all_insn[j+6]);

        if ( (i0->id == ARM64_INS_BIC) &&  
             (i1->id == ARM64_INS_CSEL) && 
	     (i2->id == ARM64_INS_HINT)  && 
	     (i3->id == ARM64_INS_NOP)  && 
	     /* ivan: 'mov' as i4 might not be there */
	     (
               ( (is_load_insn(i4)) &&  (i5->id == ARM64_INS_NOP) ) ||
               ( (is_load_insn(i5)) &&  (i6->id == ARM64_INS_NOP) )
	     )
	   )
        {
	  DBG("  get_user():");
          DBG("    0x%lx:    %s    %s", i0->address, i0->mnemonic, i0->op_str);
          DBG("    0x%lx:    %s    %s", i1->address, i1->mnemonic, i1->op_str);
          DBG("    0x%lx:    %s    %s", i2->address, i2->mnemonic, i2->op_str);
          DBG("    0x%lx:    %s    %s", i3->address, i3->mnemonic, i3->op_str);
          DBG("    0x%lx:    %s    %s", i4->address, i4->mnemonic, i4->op_str);
          DBG("    0x%lx:    %s    %s", i5->address, i5->mnemonic, i5->op_str);
          DBG("    0x%lx:    %s    %s", i6->address, i6->mnemonic, i6->op_str);

          //assert(i5->detail->arm64.operands[1].type == CS_OP_REG); /* second operand for 'ldr w0, [Xn]' instruction */

	  /* It's convenient to use a pair as we need to pass two
	   * values: ldr destination size (1, 2, 4, or 8 bytes which depends on the instruction and the first operand),
	   * and base register number (which is the second operand).*/
	  cs_insn *ldr=NULL;
          if(is_load_insn(i4)) ldr=i4;
          if(is_load_insn(i5)) ldr=i5;
	  assert(ldr);

          pair_t *aux_data = malloc(sizeof(aux_data));
	  aux_data->type = load_insn_get_dest_size(ldr);
	  aux_data->value = ldr->detail->arm64.operands[1].reg; /* base reg for ldr instruction, i.e. the one in square brackets */
          ugly_list_add(recovered_addresses_lst, ldr->address, aux_data); /* creates and adds a new node with val=ldr->address and aux_data */
        }
      } /* for 'j' loop */
    } /* if count >= 7 */ 

    if(count > 0)
      offset = all_insn[count-1].address - image_vaddr + INST_SIZE;
    else
      offset = offset+INST_SIZE; /* if not instructions at this address, move to the next 4 bytes */

    cs_free(all_insn, count);
  } while ( (offset+INST_SIZE) < image_sz );
  DBG("%s(): Disassembled %lu instructions", __func__, total_disassembled);
  return 0;
}


/* Patch some known functions that we do not want to track.
 *
 * We do this by replacing the first instruction of the function
 * by a return instruction 'bx lr'
 *
 * Note: System.map consists of line of the following format: 
 * ...
 * 803a69f0 T _cond_resched 
 * ...             ^
 *                 [we get this position]
*/
/* Path to System.map file, we set with command line args (see arg_parse() function) */
char *systemmap_path = NULL;
/* Function names to patch */
const char *symbols[] = {" T printk\n", 
                         //" T _cond_resched\n",  /* if CONFIG_PREEMT is enabled, this function already just returns 0 */
			 " T mutex_lock\n",
			 " T mutex_unlock\n",
			 " T generic_stub_0\n", /* to get rid of complex functionality and just return 0 */
                         " T kmem_cache_alloc_trace\n", /* to use candy allocator and then return immediately */
                         " T __kmalloc\n", /* to use candy allocator and then return immediately */
                         " T kmalloc_order_trace\n", /* to use candy allocator and then return immediately */
                         " T krealloc\n", /* to use candy allocator and then return immediately */
                         " T kfree\n", /* Since we are allocating memory using candy allocator, we need to skip kree, otherwise it will be called with bogus to the kernel address */
                         " T vmalloc\n", /* to use candy allocator and then return immediately */
                         " T vfree\n", /* Since we are allocating memory using candy allocator, we need to skip kree, otherwise it will be called with bogus to the kernel address */
                         " T i2c_smbus_write_byte_data\n", /* to set r0 to zero and return */
                         " T i2c_smbus_read_byte_data\n" /* to set r0 to zero and return */
};
//const char *symbols[] = {" T printk\n" };
#define n_symbols (sizeof (symbols) / sizeof (const char *))
#define ARM_ADDRESS_HEX_LENGTH 8
#define ARM64_ADDRESS_HEX_LENGTH 16
int patch_kernel(char *mem_image, long unsigned int image_vaddr, size_t image_sz)
{
  if (systemmap_path == NULL)
    return 0;

  unsigned long int s_offset = 0; /* Function offset in the kernel image */
  char *s_loc = NULL; /* Symbol location in System.map */
  size_t sz = 0;
  char s_addr_s[ARM64_ADDRESS_HEX_LENGTH+1];
  unsigned long int s_addr; /* Symbol address */
  char *content = read_whole_file(systemmap_path, &sz, USE_MALLOC);
  for (int i = 0; i < n_symbols; i++) {
    s_loc = strstr(content, symbols[i]);
    if(s_loc)
    {
      strncpy(s_addr_s, s_loc - ARM64_ADDRESS_HEX_LENGTH, ARM64_ADDRESS_HEX_LENGTH);
      s_addr_s[ARM64_ADDRESS_HEX_LENGTH] = 0;
      s_addr = strtoul(s_addr_s, NULL, 16); // Address in System.map are in hex => base=16
      if( (s_addr < image_vaddr) || (s_addr > image_vaddr + image_sz) ) 
        continue;
      /* Symbol address in System.map is a virtual address, 
         but we want to change the content of our physical mem dump,
         so we need to compute symbol's offset. */
      s_offset = s_addr-image_vaddr;
      DBG("Patching %s @ [0x%lx, offset=0x%lx]\n", symbols[i], s_addr, s_offset);
      assert(s_offset < image_sz);
      /* Patch with ret wich is: mov r0, #0; 
                                 bx lr        */
#if 0
      mem_image[s_offset+0] = 0x00; //rasm2 -a arm -b 32 'mov r0, #0' => 0000a0e3
      mem_image[s_offset+1] = 0x00;
      mem_image[s_offset+2] = 0xa0;
      mem_image[s_offset+3] = 0xe3;
      mem_image[s_offset+4] = 0x1e; // rasm2 -a arm -b 32 'bx lr' => 1eff2fe1
      mem_image[s_offset+5] = 0xff;
      mem_image[s_offset+6] = 0x2f;
      mem_image[s_offset+7] = 0xe1;
#endif
      mem_image[s_offset+0] = 0xc0; // rasm2 -a arm -b 64 'ret' => c0035fd6
      mem_image[s_offset+1] = 0x03;
      mem_image[s_offset+2] = 0x5f;
      mem_image[s_offset+3] = 0xd6;
    } else {
      printf("Warning: %s: could not find symbol '%s' in System.map file\n", __func__, symbols[i]);
    }
  }
  free(content);
  return 0;
}

/* Search for the address of a symbol in System.map file 
*
* @param symbolname Symbol name to search
* @return Address of the symbol or 0 if symbol was not found
*/
ADDR_T get_symbol_address(char *symbolname)
{
  //assert(systemmap_path);
  if(!symbolname)
    return 0;
  void *systemmap = NULL;
  size_t systemmap_size = 0;
  char *cp; /* current position */
  char *extended_symbolname;
  uint64_t symboladdress = 0;
  systemmap = read_whole_file(SYSTEMMAP_PATH, &systemmap_size, USE_MALLOC);
  extended_symbolname = malloc(strlen(symbolname)+3); /* +3 due to space, \n, \0 */
  strncpy(extended_symbolname, " ", 1);  
  strncpy(extended_symbolname+1, symbolname, strlen(symbolname));  
  strncpy(extended_symbolname+strlen(symbolname)+1, "\n\0", 2);  
  //printf("extended_symbolname = %s\n", extended_symbolname);
  cp = strstr(systemmap, extended_symbolname); /* Beginning of module mappings section */
  if(!cp)
    return 0;
  
  /* go back until the prev line */
  while( (*cp != '\n') && (cp != systemmap) )
    cp--;
  symboladdress = strtoul(cp+1, NULL, 16);
  free(systemmap);
  free(extended_symbolname);
  return symboladdress;
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
int read_dump(char *pathname, void *dest, size_t size, int use_mmap)
{
  struct stat statbuf; // To get file size
  ssize_t sz;
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
  
  sz = read(fd, dest, size);
  close(fd);
  return sz;
}



/* Convert numerical value of the register (as in arm64.h) to string
 * representation in qmp format (i.e. X04, PC)
 * <dst> should be allocated by the caller */
int reg_to_str(char *dst, uc_arm64_reg reg)
{
  //printf("reg = %d\n", reg);
  if(!dst)
    return -1;

  if     ( (reg >= UC_ARM64_REG_X0) && (reg <= UC_ARM64_REG_X28) )
    sprintf(dst, "X%02d", reg-UC_ARM64_REG_X0); // Going to be e.g. 'X04'

  else if( reg == UC_ARM64_REG_X29 )
    sprintf(dst, "X29");

  else if( reg == UC_ARM64_REG_X30 )
    sprintf(dst, "X30");

  else if( reg == UC_ARM64_REG_SP )
    sprintf(dst, "SP");

  else if( reg == UC_ARM64_REG_PC )
    sprintf(dst, "PC");

  else 
  {
    DBG("%s(): warnining: register %d is not supported\n", __func__, reg);
    return -1;
  }

  return 0;
}

/* Convert numerical value of the register (as in arm64.h) to string
 * representation in gdb format (i.e. x4, pc)
 * <dst> should be allocated by the caller */
int reg_to_str_gdb(char *dst, uc_arm64_reg reg)
{
  //printf("reg = %d\n", reg);
  if(!dst)
    return -1;

  if     ( (reg >= UC_ARM64_REG_X0) && (reg <= UC_ARM64_REG_X28) )
    sprintf(dst, "x%d", reg-UC_ARM64_REG_X0); // Going to be e.g. 'x4'

  else if( reg == UC_ARM64_REG_X29 )
    sprintf(dst, "x29");

  else if( reg == UC_ARM64_REG_X30 )
    sprintf(dst, "x30");

  else if( reg == UC_ARM64_REG_SP )
    sprintf(dst, "sp");

  else if( reg == UC_ARM64_REG_PC )
    sprintf(dst, "pc");

  else 
  {
    DBG("%s(): warnining: register %d is not supported\n", __func__, reg);
    return -1;
  }

  return 0;
}

/* Read cpu register value from QMP dump and write it both to global
 * cpu_state and to uc context.
 *
 * @param uc    Unicorn context
 * @param s_loc Point to inside the string that hold the qmp register dump
 * @param reg    Regiser number as in include/unicorn/arm64.h
 * @return     Advance the start of the string <s_loc> and return updated pointer.
 *
 * TODO: give this function a better name
 * */
char *_read_reg_from_qmp_dump(uc_engine *uc, char *s_loc, uc_arm64_reg reg)
{
  char search_pattern[16];
  int rc = reg_to_str(search_pattern, reg); /* <search_patter> is set to something like 'X01' */
  assert(rc != -1);
  s_loc = strstr(s_loc, search_pattern);
  //printf("%s(): search_patter=%s, s_loc=%p\n", __func__, search_pattern, s_loc);
  sscanf(s_loc+strlen(search_pattern)+1, "%16lx", &cpu_state.regs[reg]);
  uc_reg_write(uc, reg, &cpu_state.regs[reg]);
  return s_loc;
}

/* Parse output from Qemu 'info registers' over QMP */
int init_registers_from_qmp(uc_engine *uc)
{
  size_t sz;
  char *s_loc = NULL; /* Location of the registers in the register dump file */
  char *content = read_whole_file(REGISTERS_PATH, &sz, USE_MALLOC); // This will allocate memory, don't forget to free it
  s_loc = content;

  int i = 0;

  /* In the code below we use register indices from file unicorn/include/unicorn/arm64.h
     We read in the same order they appear in qemp-registers.txt
     These indices are sequential for registers except for [X00-X28] */

  /* Read registers PC and SP */
  s_loc = _read_reg_from_qmp_dump(uc, s_loc, UC_ARM64_REG_PC);
  s_loc = _read_reg_from_qmp_dump(uc, s_loc, UC_ARM64_REG_SP);

  /* Read registers x0,...,x28 */
  for(i=0;i<=28;i++)
    s_loc = _read_reg_from_qmp_dump(uc, s_loc, UC_ARM64_REG_X0+i);

  /* Read registers X29 and X30 */
  s_loc = _read_reg_from_qmp_dump(uc, s_loc, UC_ARM64_REG_X29);
  s_loc = _read_reg_from_qmp_dump(uc, s_loc, UC_ARM64_REG_X30);

  free(content);
  return 0;
}

/* Read cpu register values from GDB output and write it both to global
 * cpu_state and to uc context.
 *
 * @param uc                    Unicorn context
 * @param all_gdb_registers_str String containing all registers and values
 * @param reg                   Regiser number as in include/unicorn/arm64.h
 * @return                      Advance the start of the string <s_loc> and return updated pointer.
 *
 * TODO: give this function a better name
 * */
char *_read_reg_from_gdb(uc_engine *uc, char *all_gdb_registers_str, uc_arm64_reg reg)
{
  char *s_loc;
  char search_pattern[16];
  int rc = reg_to_str_gdb(search_pattern, reg); /* <search_pattern> is set to something like 'x1', 'pc' */
  assert(rc != -1);
  s_loc = strstr(all_gdb_registers_str, search_pattern);
  sscanf(s_loc+strlen(search_pattern)+1, "0x%lx", &cpu_state.regs[reg]);
  uc_reg_write(uc, reg, &cpu_state.regs[reg]);
  return s_loc;
}

/* Parse output from 'gdb-regiters.txt' generated by 'prepare-emulation-arm.pl' 
   Here is the file format:
    x26 0x1d
    x30 0xffff000008244660
    sp_el0 0xffff80000486c000
*/
int init_registers_from_gdb(uc_engine *uc)
{
  size_t sz;
  char *s_loc = NULL; /* Location of the registers in the register dump file */
  char *content = read_whole_file(GDB_REGISTERS_PATH, &sz, USE_MALLOC); // This will allocate memory, don't forget to free it

  int i = 0;

  /* In the code below we use register indices from file unicorn/include/unicorn/arm64.h
     These indices are sequential for registers except for [X00-X28] */

  /* Read registers PC and SP */
  _read_reg_from_gdb(uc, content, UC_ARM64_REG_PC);
  _read_reg_from_gdb(uc, content, UC_ARM64_REG_SP);

  /* Read registers x0,...,x28 */
  for(i=0;i<=28;i++)
    _read_reg_from_gdb(uc, content, UC_ARM64_REG_X0+i);

  /* Read registers X29 and X30 */
  _read_reg_from_gdb(uc, content, UC_ARM64_REG_X29);
  _read_reg_from_gdb(uc, content, UC_ARM64_REG_X30);

  free(content);
  return 0;
}

void sprintreg(uc_engine *uc, char *dst, uc_arm64_reg reg)
{
  char reg_name[16];
  uc_reg_read(uc, reg, &cpu_state.regs[reg]);
  reg_to_str(reg_name, reg);
  sprintf(dst, "%s=%16lx", reg_name, cpu_state.regs[reg]);
}

void dump_registers(uc_engine *uc)
{
  int i = 0;
  char buffer[64];
  sprintreg(uc, buffer, UC_ARM64_REG_PC);
  printf("%s ", buffer);
  sprintreg(uc, buffer, UC_ARM64_REG_SP);
  printf("%s \n", buffer);
  for(i=0;i<=28;i++)
  {
    sprintreg(uc, buffer, UC_ARM64_REG_X0+i);
    printf("%s ", buffer);
    if( ( (i+1) % 4 == 0) ) printf("\n");
  }

  sprintreg(uc, buffer, UC_ARM64_REG_X29);
  printf("%s ", buffer);
  sprintreg(uc, buffer, UC_ARM64_REG_X30);
  printf("%s \n", buffer);

}

/* Reads the data, and returns the pointer and the size. The caller is
 * responsible of freeing the memory.
 * 
 * @param pathname(in) Memdump file
 * @param dump_size(out) Size of the memory dump, set by this function
 * @param use_mmap Can be either USE_MALLOC=0 or USE_MMAP=1; specifies how to allocate memory
 * @return Pointer to the memory dump
 */
void *read_whole_dump(char *pathname, size_t *dump_size, int use_mmap)
{
  struct stat statbuf;
  void *buf;
  size_t len_file;
  if(stat(pathname,&statbuf) == -1) {
    printf("stat(): Could not access file '%s'\n", pathname);
    exit(-1);
  }

  int fd = open(pathname, O_RDONLY);
  if (fd < 0) {
    printf("open(): Could not open file '%s'\n", pathname);
    exit(-1);
  }

  len_file = statbuf.st_size;

  if(use_mmap)
  {
    if ((buf = mmap(NULL,len_file,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0)) == MAP_FAILED)
    {
        perror("Error in mmap");
	exit(-1);
        //return NULL;
    }
    *dump_size = len_file;
  } else // use malloc
  {
    buf = malloc(statbuf.st_size);
    *dump_size = read(fd, buf, len_file);
  }
  close(fd);
  return buf;
}

/* @param n Number of entries in moduledump_filenames */
int is_module_dump(char *dump_name, char moduledump_filenames[MAX_MODULES][MAX_FILENAME], int n)
{
  int i;
  for(i=0; i<n; i++)
  {
    if (strncmp(moduledump_filenames[i], dump_name, 22) == 0)
      return 1;
  }
  return 0;
}


/* Search for copy_from_user and get_user inline functions uses inside
 * memory dump and set code hooks */
int set_access_ok_code_hooks(uc_engine *uc, void *dump, ADDR_T dump_vaddr, size_t dump_size)
{
  
  /* access_ok() uses */
  DBG("Searching for access_ok() instances");
  ugly_list_t *accessok_lst = malloc(sizeof(ugly_list_t)); /* To store addresses of copy_from_user() inside the module's code */ 
  ugly_list_init(accessok_lst);
  get_copyfromuser_uses(dump, dump_vaddr, dump_size, accessok_lst);
  ugly_list_node *node = accessok_lst->head;
  while(node)
  {
    uint64_t addr = node->val;
    DBG("Setting code hook for access_ok() at 0x%lx (list %p)\n", node->val, accessok_lst);

    uc_hook hh_copy_from_user;
    if(uc_hook_add(uc, &hh_copy_from_user, UC_HOOK_CODE, code_hook_copy_from_user, node, addr, addr+1))
    {
      printf("error: uc_hook_add() for UC_HOOK_CODE(access_ok)\n");
      exit(0);
    }
    node = node->next;
  }

  /* get_user() uses */
  DBG("Searching for get_user() instances");
  ugly_list_t *getuser_lst = malloc(sizeof(ugly_list_t));
  ugly_list_init(getuser_lst);
  get_getuser_uses(dump, dump_vaddr, dump_size, getuser_lst);
  node = getuser_lst->head;
  while(node)
  {
   /* node->val points to the ldr intruction of get_user():
    * 'ldrh w1, [x2]' */
    uint64_t addr = node->val; 
    DBG("Setting code hook for get_user() at 0x%lx (list %p)\n", node->val, getuser_lst);

    uc_hook hh_getuser;
    if(uc_hook_add(uc, &hh_getuser, UC_HOOK_CODE, code_hook_getuser, node, addr, addr+1))
    {
      printf("error: uc_hook_add() for UC_HOOK_CODE(getuser)\n");
      exit(0);
    }
    node = node->next;
  }


  return 0;
}

/* Read memdumps files and write them to Unicorn 
 * 
 * IMPORTANT NOTE
 * Filenames MUST have the following format:
 * ffff0000009e0000-ffff0000009e1000.dump
 *  ^               ^
 *  |               '---.
 *  |                   |
 * [start address]   [end address]
 * 
 */
int init_memory_from_dumps(uc_engine *uc)
{

  DIR *dfd;
  struct dirent *dump_file;
  char *dash_loc = NULL; /* dash in-between start and end address in the dump filename */
  //char s_addr_s[17];
  //char e_addr_s[17];
  unsigned long int dump_vaddr; /* Virtual address of the dump, sizeof(unsigned long int)=8 */
  void *dump = NULL;
  size_t dump_size = 0;
  void *krnlmemmap = NULL;
  size_t krnlmemmap_size = 0;
  char *cp /*current position*/, *ep /*end position*/ ,*dashp /*dash(-) position*/;
  int num_modules = 0; /* Number of actual entries in ---[ Modules ]--- section in kernmapping.txt file */
  char moduledump_filenames[MAX_MODULES][MAX_FILENAME]; /* Used to parse kernel_page_tables.txt file (aka KERNELMAPPING_PATH) */
  ADDR_T video_usercopy_addr = 0;
  //ugly_list_t cpyfrmusr_lst; /* To store addresses of copy_from_user() inside the module's code */ 
  //ugly_list_init(&cpyfrmusr_lst);

  /* Find out what dump contains module's code. We need it to find out places
   * where it calls copy_from_user(), which is an inline function */
  krnlmemmap = read_whole_file(KERNELMAPPING_PATH, &krnlmemmap_size, USE_MALLOC);
  //tmp1 = strstr(krnlmemmap, "Modules");
  cp = strstr(krnlmemmap, "---[ Modules start ]---"); /* Beginning of module mappings section */
  ep = strstr(krnlmemmap, "---[ Modules end ]---"); /* End of module mappings section */
  if(!cp) {
    printf("error: kernel memory map file (%s) does not contain 'Modules' section\n", KERNELMAPPING_PATH);
    exit(0);
  }
  /* Extract the first module mapping */
  cp = strstr(cp, "\n")+1; /* Mappings is at the next line */

  while(cp < ep) /* Read while we are in the Modules section */
  {
    dashp = strstr(cp, "-");
    /* we need to get rid of '0x' prefices, this is why we copy in three steps */
    memcpy(moduledump_filenames[num_modules], cp+2, 17); /* start address: from '0x' to '-' (inclusive) */
    memcpy(moduledump_filenames[num_modules]+17, dashp+3, 16);  /* end address: from '-0x', 16 hex digits */
    memcpy(moduledump_filenames[num_modules]+33, ".dump\0", 6);  /* add '.dump' to the filename */
    DBG("    module dump filename = %s", moduledump_filenames[num_modules]);
    num_modules++;
    cp = strstr(cp, "\n")+1; /* Find next module mapping */
    assert( (num_modules < MAX_MODULES) && "NOT IMPLEMENTED: only 16 modules are supported in this version");
  }

  free(krnlmemmap);
 
  video_usercopy_addr = get_symbol_address("video_usercopy");

  /* Open the folder with memory dump files */
  dfd = opendir(MEMDUMPS_PATH);
  if(dfd == NULL) {
    printf("opendir(): Could not open dir '%s'\n", MEMDUMPS_PATH);
    exit(-1);
  }
  /* Read each memory dump and copy it Unicorn emulated memory */
  while ((dump_file = readdir(dfd))) 
  {
    if (!strcmp (dump_file->d_name, "."))
        continue;
    if (!strcmp (dump_file->d_name, ".."))    
        continue;
  

    /* Read the dump */
    char *fullpath = malloc(sizeof(MEMDUMPS_PATH) + strlen(dump_file->d_name) + 1);
    strncpy(fullpath, MEMDUMPS_PATH, sizeof(MEMDUMPS_PATH));
    strncat(fullpath, dump_file->d_name, strlen(dump_file->d_name));
    dump = read_whole_dump(fullpath, &dump_size, USE_MMAP);
    free(fullpath);

    /* Get start and end addresses from the filename */
    dump_vaddr = strtoul(dump_file->d_name, NULL, 16); /* will read until '-' in between */
    dash_loc = strchr(dump_file->d_name, '-');
    assert(dash_loc && "wrong memdump filename format (should look like '7f223344-7f667788.dump')!");
    unsigned long int dump_vaddr_end; /* End virtual address of the dump, for debugging only */
    dump_vaddr_end = strtoul(dash_loc+1, NULL, 16);
    DBG("vaddr: [0x%lx] s:[0x%lx] -> [0x%lx] s:[0x%lx] aligned\n", 
             dump_vaddr, dump_size, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size));
    assert(dump_size == (dump_vaddr_end-dump_vaddr));

    /* Replace some kernel functions such as printk with 'ret 0' instruction */
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

    /* Now add code hooks for every copy_from_user() 'call' inside the module.
     * (copy_from_user() is inlined, hence such troubles: searching for
     * corresponding assembly instructions). We search copy_from_user() only
     * inside the module's code here; and we do this only if in fuzzing mode */
    if( (is_module_dump(dump_file->d_name, moduledump_filenames, num_modules))  && 
	  (afl_input_filepath != NULL) ) 
    {
      set_access_ok_code_hooks(uc, dump, dump_vaddr, dump_size);
      //ugly_list_t cpyfrmusr_lst; /* To store addresses of copy_from_user() inside the module's code */ 
      //ugly_list_init(&cpyfrmusr_lst);
      //get_copyfromuser_uses(dump, dump_vaddr, dump_size, &cpyfrmusr_lst);
      //ugly_list_node *node = cpyfrmusr_lst.head;
      //while(node)
      //{
      //  uint64_t addr = node->val;
      //  DBG("Setting code hook for at 0x%lx (list %p)\n", node->val, &cpyfrmusr_lst);

      //  uc_hook hh_copy_from_user;
      //  if(uc_hook_add(uc, &hh_copy_from_user, UC_HOOK_CODE, code_hook_copy_from_user, node, addr, addr+1))
      //  {
      //    printf("error: uc_hook_add() for UC_HOOK_CODE(copy_from_user)\n");
      //    exit(0);
      //  }
      //  node = node->next;
      //}
    }

    /* We also need to search for copy_from_user() occurences in video_usercopy() function */
    if( (dump_vaddr < video_usercopy_addr) && (video_usercopy_addr  < dump_vaddr_end) ) 
    {
      ADDR_T func_offset = video_usercopy_addr - dump_vaddr;
      ADDR_T func_size = 1396; /* FIXME: got this from vmlinux, the proper way is to get it dynamically */
      set_access_ok_code_hooks(uc, dump+func_offset, dump_vaddr+func_offset, func_size);
      //ugly_list_t cpyfrmusr_lst; /* To store addresses of copy_from_user() inside the module's code */ 
      //ugly_list_init(&cpyfrmusr_lst);
      //ADDR_T func_offset = video_usercopy_addr - dump_vaddr;
      //ADDR_T func_size = 1396; /* FIXME: got this from vmlinux, the proper way is to get it dynamically */
      //get_copyfromuser_uses(dump+func_offset, dump_vaddr+func_offset, func_size, &cpyfrmusr_lst);
      //ugly_list_node *node = cpyfrmusr_lst.head;
      //while(node)
      //{
      //  uint64_t addr = node->val;
      //  DBG("Setting code hook for at 0x%lx (list %p)\n", node->val, &cpyfrmusr_lst);

      //  uc_hook hh_copy_from_user;
      //  if(uc_hook_add(uc, &hh_copy_from_user, UC_HOOK_CODE, code_hook_copy_from_user, node, addr, addr+1))
      //  {
      //    printf("error: uc_hook_add() for UC_HOOK_CODE(copy_from_user)\n");
      //    exit(0);
      //  }
      //  node = node->next;
      //}

    }
    //free(dump);
    munmap(dump, dump_size);
  }
}

#define SKELETON_CMD 0x12345678
/* This function is used specifically to recovery ioctl cmd's which
   are originally placed into r1 with value 0x12345678 by skeleton test
   program, so we check of this value in one of the registers. But note
   that you can also provide this number as '-c' option */
int get_cmp_args(uc_engine *uc, cs_insn *insn)
{
  uint64_t op0_val = 0;
  uint64_t op1_val = 0;

  assert(insn->detail->arm.op_count == 2);
  int op0_type = insn->detail->arm.operands[0].type;
  int op1_type = insn->detail->arm.operands[1].type;;

  if(op0_type == CS_OP_REG) {
      uc_reg_read(uc, insn->detail->arm.operands[0].reg, &op0_val);
      printf("op0_val=%lx\n", op0_val);
      if(op0_val == SKELETON_CMD) {
        if(op1_type == CS_OP_REG) 
          uc_reg_read(uc, insn->detail->arm.operands[1].reg, &op1_val);
        if(op1_type == CS_OP_IMM) 
          op1_val = insn->detail->arm.operands[1].imm;
	printf("cmd = %lu\n", op1_val);
	return 0;
      }
  }

  if(op1_type == CS_OP_REG) {
      uc_reg_read(uc, insn->detail->arm.operands[1].reg, &op1_val);
      if(op1_val == SKELETON_CMD) {
        if(op0_type == CS_OP_REG) 
          uc_reg_read(uc, insn->detail->arm.operands[0].reg, &op0_val);
        if(op0_type == CS_OP_IMM) 
          op0_val = insn->detail->arm.operands[0].imm;
	printf("cmd = %lu\n", op0_val);
	return 0;
      }
  }

  return 0;
}

int disass(uc_engine *uc, void *buf, uint32_t size, uint64_t address)
{
  // Capstone
  csh handle;
  cs_insn *insn;
  size_t count;
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
    return -1;

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
  count = cs_disasm(handle, buf, size, address, 0, &insn);
  if (count > 0) 
  {
     size_t j;
     for (j = 0; j < count; j++) 
     {
       printf("    0x%"PRIx64":\t\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
       //print_register(uc, UC_ARM64_REG_X1);
//#define RECOVER_IOCTL_CMDS
#ifdef RECOVER_IOCTL_CMDS
       assert(0 && "NOT IMPLEMENTED FOR ARM64");
       if(insn[j].id == ARM_INS_CMP) 
       {
         //printf("  it is a cmp instruction, insn=%p; &insn[j]=%p\n", insn, &insn[j]);
         printf("  it is a cmp instruction\n");
	 get_cmp_args(uc, &insn[j]);
       }
#endif
       //for(int k =0; k<insn[j].size; k++)
         //printf("%02hhx",insn[j].bytes[k]);
       //printf("\n");
     }
     cs_free(insn, count);
  } else
    return -1;
  return 0;
}

bool x = true;
void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
  assert(size < 16);
  void *buf = alloca(16);
  uc_mem_read(uc, address, buf, size);
  disass(uc, buf, size, address);
  //printf("func %s is at %p\n", __func__, code_hook);
  //print_trace();
  //exit(0);
}


/* @param offset[out] If the node containting the pointer is an array, this field
                      specifies the offset from the beginning of the array in bytes.
*/
int find_pointer(uc_engine *uc, xmlNodePtr cur, ADDR_T pointer, xmlNodePtr *result, int *offset)
{
  xmlChar *size_prop;
  xmlChar *vaddr_prop;
  xmlChar *value_prop;
  vaddr_prop = xmlGetProp(cur, (const xmlChar *)"vaddr");
  size_prop  = xmlGetProp(cur, (const xmlChar *)"size");
  value_prop  = xmlGetProp(cur, (const xmlChar *)"value"); /* Not null only for 'pointer' elements */
  assert(vaddr_prop != NULL);
  //assert(size_prop  != NULL);
  ADDR_T vaddr = strtoul(vaddr_prop, NULL, 0);
  REG_T size  = size_prop ? strtoul(size_prop,  NULL, 0) : 0;
  ADDR_T value  = value_prop ? strtoul(value_prop,  NULL, 0) : 0;
  int num_results = 0;
  DBG("Searching pointer in xml node '%s' (vaddr = 0x%lx, size = %s, value=%s)\n",
                  cur->name, vaddr, size_prop, value_prop);

  /* It's a struct whose vaddr equals <pointer> */
  if( (vaddr == pointer) && (cur == xmlDocGetRootElement(doc)))
  {
    //assert(size==0); /* if size is not zero, then the driver used copy_from_user() on the same address twice, which does not normally happen */
    DBG("Pointer address coincides with the vaddr of top-level struct (vaddr=0x%lx)\n", vaddr);
    *result = cur;
    *offset = -1; /* The node itself */
    num_results++;
    //return 1;
  }
 
  /* It's pointer whose value equals <pointer> */
  if(value_prop && (value == pointer))
  {
    *offset = -1; /* The node itself */
    *result = cur;
    DBG("Pointer address coincides with the value of 'pointer' node (vaddr=0x%lx, value=0x%lx)\n", vaddr, value);
    num_results++;
    //return 1;
  }

  /* If array, check array contents for the pointer*/
  if(!xmlStrcmp(cur->name, (const xmlChar *)"array"))
  {
    uint8_t *buf = (uint8_t *)alloca(size);
    if(uc_mem_read(uc, vaddr, buf, size)) {
      DBG("%s(): Could not read memory from unicorn, report this bug to ivan@ipust.net\n", __func__);
      exit(-1);
    }
    int i = 0; 
    ADDR_T *val;
    for(i=0;i<size;i++)
    {
      val = (ADDR_T *)&buf[i];
      //printf("Comparing %x(val) and %x(pointer)\n", *val, pointer);
      if(pointer == *val)
      {
        DBG("Found pointer inside array (vaddr=0x%lx, size=%ld) at offset %d", vaddr, size, i);
        *offset = i;
	*result = cur;
	num_results++;
      }
    }
  }

  /* If cur is 'struct' or 'pointer', check all child nodes */
  if(!xmlStrcmp(cur->name, (const xmlChar *)"struct") || 
    !xmlStrcmp(cur->name, (const xmlChar *)"pointer"))
  {
    /* Parse children */
    //printf("Checking children nodes\n");
    //DBG("  it is a struct/pointer, will check inner nodes now");
    xmlNodePtr child;
    //xmlNodePtr ret = NULL;
    int ret = 0;
    child = cur->xmlChildrenNode;
    assert(child);
    while (child != NULL) {
      if(child->type == 1) /* normal node */
      {
        ret = find_pointer(uc, child, pointer, result, offset);
	num_results = num_results+ret;
	if(num_results > 1)
	  return num_results;
      }
      //if(ret)
      //{
      //  return ret; /* Offset should already be set inside the above call to find_pointer() */
      //}
      child = child->next;
    }
  }

  return num_results; /* Nothing found */
}


/* Get free memory from charlie allocator, and write afl input to
 * the same memory in unicorn.
 * 
 * @param uc   Unicorn
 * @param size Size of the memory chunk to allocate
 * @return     Address of the allocated chunk
*/
ADDR_T allocate_and_write_afl_input_to_uc(uc_engine *uc, uint32_t size)
{
  int ret_code = 0;
  ADDR_T allocated_addr = 0;
  if( (afl_input+size) > (afl_input_start + afl_input_size) )
  {
    printf("error: not enough afl input (requested %u bytes, but %lu bytes is left)\n", size, afl_input_start + afl_input_size - afl_input);
    exit(0);
  }
  allocated_addr = charlie_memalloc(size);
  //assert(vaddr == allocated_addr);
#ifdef DEBUG
  printf("[DEBUG]: writing the following bytes to [0x%lx-0x%lx]: ", allocated_addr, allocated_addr+size);
  print_hex(afl_input, size);
#endif
  if(ret_code = uc_mem_write(uc, allocated_addr, afl_input, size))
  {
     printf("error: uc_mem_write() failed to write to memory (%s)\n", uc_strerror(ret_code));
     exit(0);
  }
  afl_input = afl_input + size;
  return allocated_addr;
}


/* Should land us at 'ldrh w1, [x2]' instruction, see the second half of
 * function set_access_ok_code_hooks() 
 * We don't need to allocate any memory as it was already done in access_ok hook */
bool code_hook_getuser(uc_engine *uc, uint64_t instr_address, uint32_t instr_size, void *user_data)
{ 
  ADDR_T original_addr; /* Source user address */
  ugly_list_node *node = (ugly_list_node *)user_data;
  pair_t *aux_data = node->aux_data; /* register number of the second operand of ldr instruction */
  int dest_size = aux_data->type;
  uc_arm64_reg base_reg = aux_data->value;
  uc_reg_read(uc, base_reg, &original_addr);
  DBG("%s(): Inside, PC=0x%lx. dest_size=%d, base_reg=x%u=0x%lx", __func__, instr_address, dest_size, base_reg-UC_ARM64_REG_X0, original_addr);

  //ADDR_T new_addr = allocate_and_write_afl_input_to_uc(uc, 1);
  //DBG("__get_user_1(x, 0x%x,...), replaced with userspace address 0x%x", original_addr, new_addr);
  //uc_reg_write(uc, UC_ARM_REG_R0, &new_addr);

  //DBG("getuser() hook NOT IMPLEMENTED. Stopping emulation");
  //uc_emu_stop(uc);
  return true;
}

/* This should be called when the code enters copy_from_user(to, from, n)
   We should be at the beginning of:

static inline unsigned long __must_check copy_from_user(void *to, const void __user *from, unsigned long n)
	if (access_ok(VERIFY_READ, from, n))   #     <------ WE ARE HERE
		res = __arch_copy_from_user(to, from, n);
...
#define access_ok(type, addr, size)	__range_ok((unsigned long)(addr), size)
...

  This function is equivalent to the following test:
  (u65)addr + (u65)size <= (u65)current->addr_limit + 1
static inline unsigned long __range_ok(unsigned long addr, unsigned long size) # <---- Note that it is 'from' userspace address
{
	unsigned long limit = current_thread_info()->addr_limit;

	asm volatile(
	"	adds	%0, %0, %2\n"
	"	csel	%1, xzr, %1, hi\n"
	"	csinv	%0, %0, xzr, cc\n"
	"	sbcs	xzr, %0, %1\n"
	"	cset	%0, ls\n"
	: "+r" (addr), "+r" (limit) : "Ir" (size) : "cc");

	return addr;


 This is compiled into someting like this:

   0x0800016c   adds x1, x1, 0x10
   0x08000170   csel x0, xzr, x0, hi
   0x08000174   csinv x1, x1, xzr, lo
   0x08000178   sbcs xzr, x1, x0
   0x0800017c   cset x1, ls


 Rewriting the first instruction with variables:

    0x0800016c   adds addr, addr, size     // addr is 'from', i.e. source userspace address
    ...

 * It means that we need to consider the 'adds' instructon:
 *  the second operand is the 'addr' (i.e. <from>), and the third operand is
 *  'size' (i.e. <n>) ' */
bool code_hook_copy_from_user(uc_engine *uc, uint64_t instr_address, uint32_t instr_size, void *user_data)
{
  ADDR_T from; /* Source address for __copy_from_user() */
  REG_T len;   /* Number of bytes to copy using __copy_from_user() */
  
  ugly_list_node *node = (ugly_list_node *)user_data;
  pair_t *op_details = (pair_t *)node->aux_data;

  /* First two operands are always registers, the 3rd operand can be either reg or imm */
  /* This code hook is for 'adds', instruction; we pass info about its
     arguments in 'op_details'; specifically, it contains the register ID for
     the first two operands and reg or immediate for the third operand */
  uc_reg_read(uc, op_details[1].value, &from); /* adds addr, _addr_, size */
  if(op_details[2].type ==  CS_OP_REG)                    /*     ^       */
    uc_reg_read(uc, op_details[2].value, &len);
  else if(op_details[2].type ==  CS_OP_IMM)
    len = op_details[2].value;
  else {
    printf("error: wrong type of operand\n");
    exit(0);
  }

  DBG("We entered access_ok(0x%lx, %ld)\n", from, len);

  /* Go through memory pointed by all the copied nodes */
  xmlNodePtr root = xmlDocGetRootElement(doc); 
  int offset = -2;
  //xmlNodePtr cur = find_pointer(uc, root, from, &offset);
  xmlNodePtr cur = NULL; /* 'cur' will point to xml 'array' node containing pointer 'from', 'offset' is the offset from the beginning of this array */
  int num_found = find_pointer(uc, root, from, &cur, &offset);
  if(num_found > 1)
  {
    DBG("Pointer value was found in at least %d different places. Input is not random enough, safely stopping emulation", num_found);
    uc_emu_stop(uc);
    return true;
  }

  /* offset = -1 means that the copy_from_user() argument coincided with vaddr
   * of one of the 'struct' or 'pointer' elements  */
  if(cur && (offset == -1)) 
  { /* It's a top level struct for which we know the address, but don't know the size */
    xmlChar *cur_vaddr_prop = xmlGetProp(cur, (const xmlChar *)"vaddr");
    assert(cur_vaddr_prop);
    ADDR_T cur_vaddr = strtoul(cur_vaddr_prop, NULL, 0);
    xmlChar *size_prop = xmlGetProp(cur, (const xmlChar *)"size");
    ADDR_T size = size_prop ? strtoul(size_prop, NULL, 0) : 0;
    /* This is the case when we only started fuzzing with empty top-level
     * struct. The driver copies this top-level struct and its size is unknown */
    if(!xmlStrcmp(cur->name, (const xmlChar *)"struct") && (size==0)) { 
      char temp_buf[64]; // To temporary hold property values as a strings
      /* As we don't know anything about struct's members yet, let's put a byte array here */
      xmlNodePtr new_child = xmlNewChild(cur, NULL, "array", NULL);
      sprintf(temp_buf, "%lu", len); 
      xmlNewProp(new_child, "size", temp_buf); /* Set size for the new child array */
      xmlSetProp(cur, "size", temp_buf);       /* Set size for the current structure */
      //DBG("%s(): Created a new array child for node %s, size = %d. Stopping emulation now (you need to rerun emulation to make use of updated xml scheme).\n", __func__, cur->name, len);
      DBG("The struct was not allocated before, created a new array child for node %s, size = %lu.\n", cur->name, len);

      /* Now let's fill the array with afl data; we don't change the pointer in uc
       * memory: this is the top level struct (at 0x10000000) and it is also the first
       * call to charlie allocator with non-zero size (and will return 0x10000000 too). */
      xmlChar *vaddr_prop = xmlGetProp(cur, (const xmlChar *)"vaddr");
      assert(vaddr_prop);
      ADDR_T vaddr = strtoul(vaddr_prop, NULL, 0);
      ADDR_T allocated_addr = allocate_and_write_afl_input_to_uc(uc, len);
      assert((vaddr == allocated_addr) && "charlie allocator returned non-initial address");

      sprintf(temp_buf, "0x%lx", allocated_addr); 
      xmlNewProp(new_child, "vaddr", temp_buf); /* Set size for the new child array. Array will have the same address as the embedding struct */
      copy_from_user_array = new_child;         /* Save new_child to update its kaddr property later */
#ifdef DEBUG
      uc_print_mem(uc, allocated_addr, len);
#endif
    } else 
    {
      DBG("This pointer (->0x%lx) was already allocated\n", from);
      //assert(size==len); /* Make sure that we don't have two different sizes for the same top level struct */
      /* Since the the size of a array pointed by a pointer can be computed dinamically 
       * (i.e. sizeof(struct some_struct)*num_of_elements, 'num_of_elements' is provided by the userspace)
       * we need to increase the size if it's too small. We don't care if the already allocated size is bigger */
      if(size < len) /* size is the xml property, len is the argument to copy_from_user() */
      {
        /* >> it might happen if the driver first used copy_from_user() and then
	      copy_to_user(); charlie has 1MB, so uc should not crash when writing to userspace
	      with copy_to_user() */
        DBG("It looks that the initially allocated size of element '%s' @0x%lx (%ld bytes) (new is %ld bytes) is too small. This is probably due to copy_to_user() (deemped safe). We ignore it by now. I might fix it in the future", cur->name, cur_vaddr, size, len);

#if 0 /* TODO: we need to somehow increase the size of the original array */
        DBG("It looks that the initially allocated size is too small. Increasing size of element '%s' @0x%x from %d to %d", cur->name, cur_vaddr, size, len);
        char temp_buf[32]; // To temporary hold property values as a strings
        sprintf(temp_buf, "%u", len); 
        xmlSetProp(cur, "size", temp_buf);       /* Set size for the current structure */
        xmlNodePtr tail_inner_array_node = xmlNewChild(cur, NULL, "array", NULL); /* new child array */
        sprintf(temp_buf, "%u", len-size);  
        xmlNewProp(tail_inner_array_node, "size", temp_buf);
#endif

      }
      //assert(0); // IVAN DEBUG
    }
  } else if(cur) { /* cur should be an 'array' that contains the pointer*/
    assert(!xmlStrcmp(cur->name, (const xmlChar *)"array"));
    /* Split the array into two. 'cur' is the array that needs to splitted.
       We do it in three steps: 1. Change the size of the original array to 'offset';
                                2. Create a new pointer with a new array as a child
                                3. Create new array of size 'old_size-offset-8' (i.e. the remaning part of the original array) */
    DBG("This looks like an invalid pointer, splitting the array and creating a new pointer inside");
    char temp_buf[64]; // To temporary hold property values as a strings, we reuse it for every new property 
    xmlChar *cur_size_prop = xmlGetProp(cur, (const xmlChar *)"size");
    xmlChar *cur_vaddr_prop = xmlGetProp(cur, (const xmlChar *)"vaddr");
    xmlChar *cur_kaddr_prop = xmlGetProp(cur, (const xmlChar *)"kaddr");
    assert(cur_size_prop);
    assert(cur_vaddr_prop);
    assert(cur_kaddr_prop);
    REG_T cur_size = strtoul(cur_size_prop, NULL, 0);
    REG_T old_size = cur_size;
    ADDR_T cur_vaddr = strtoul(cur_vaddr_prop, NULL, 0);
    ADDR_T cur_kaddr = strtoul(cur_kaddr_prop, NULL, 0);

    /* Reduce the size property of the original array by 4 */
    assert( (old_size - offset - POINTER_SIZE) >= 0);
    sprintf(temp_buf, "%d", offset);  /* offset is int */
    xmlSetProp(cur, (const xmlChar *)"size", temp_buf);
    
    /* New pointer with inner array */
    xmlNodePtr new_pointer_node = xmlNewNode(NULL, "pointer"); 
    xmlAddNextSibling(cur, new_pointer_node);
    xmlNodePtr inner_array_node = xmlNewChild(new_pointer_node, NULL, "array", NULL); /* new child array */
    /* Update their properties */
    sprintf(temp_buf, "%lu", len);  
    xmlNewProp(new_pointer_node, "size", temp_buf); /* The 'size' property of the pointer is the size of the memory it points to */
    xmlNewProp(inner_array_node, "size", temp_buf);


    /* ivanp: This code dynamically fills the userspace pointer */
    sprintf(temp_buf, "0x%lx", cur_vaddr+offset);  /* vaddr property for the new pointer */
    xmlNewProp(new_pointer_node, "vaddr", temp_buf);

    /* Write afl input to memory pointed by the pointer, update 'value' and 'vaddr' properties for the pointer and the inner array */
    ADDR_T inner_array_vaddr = allocate_and_write_afl_input_to_uc(uc, len);
    DBG("The new pointer now points to 0x%lx, and it is located at vaddr=0x%lx", inner_array_vaddr, cur_vaddr+offset);
    sprintf(temp_buf, "0x%lx", inner_array_vaddr); 
    xmlNewProp(inner_array_node, "vaddr", temp_buf); 
    xmlNewProp(new_pointer_node, "value", temp_buf);
    /* Replace the value of the register (adds instr.) and memory */
    DBG("Updating register x%lu and memory 0x%lx (writing new pointer there)", op_details[1].value-UC_ARM64_REG_X0, cur_vaddr+offset);
    uc_reg_write(uc, op_details[1].value, &inner_array_vaddr);
    uc_mem_write(uc, cur_vaddr+offset, &inner_array_vaddr, TARGET_ADDRESS_SIZE_BYTES); /* 8 bytes for arm64 */
    DBG("The kaddr of the array containing the new pointer: [%s], updating this memory at offset %d", cur_kaddr_prop, offset);
    uc_mem_write(uc, cur_kaddr+offset, &inner_array_vaddr, TARGET_ADDRESS_SIZE_BYTES);
    copy_from_user_array = inner_array_node; /* We save this for __copy_from_user() where we will need to update its kaddr property */

    /* The remainig part of the orignal array becomes a new array */
    if( (old_size - offset - POINTER_SIZE) != 0)
    {
      xmlNodePtr tail_array_node = xmlNewNode(NULL, "array");
      xmlAddSibling(cur, tail_array_node);
      sprintf(temp_buf, "%lu", old_size - offset - POINTER_SIZE); 
      xmlNewProp(tail_array_node, "size", temp_buf);
      sprintf(temp_buf, "0x%lx",  cur_vaddr+offset+POINTER_SIZE); 
      xmlNewProp(tail_array_node, "vaddr", temp_buf);
      sprintf(temp_buf, "0x%lx",  cur_kaddr+offset+POINTER_SIZE); 
      xmlNewProp(tail_array_node, "kaddr", temp_buf);
    }
    if(offset == 0) /* Delete old array if its new size is zero, we do it at the end because up to this point we needed <cur> */
    {
      xmlUnlinkNode(cur);
      xmlFreeNode(cur);
    }
#if 0
    uc_print_mem(uc, cur_vaddr, cur_size);
#endif
    //getc(stdin);
  }
  else
  {
    /* In case we did not find the pointer, there can be two cases: a) the
     * pointer invalid which is a bug in the driver => cause copy_from_user() will fail and we'll detect it.
     * b) access_ok is for get_user(), in which case the pointer should be somewhere in charlie allocator's range. In
     * this case we allocate memory an proceed */
    DBG("%s(): Could not find pointer 0x%lx\n", __func__, from);
    ADDR_T charlie_start = 0x10000000;
    ADDR_T charlie_end = 0x10100000;
    if( (from > charlie_start) && (from+len < charlie_end) )
    {
      ADDR_T allocated_addr = allocate_and_write_afl_input_to_uc(uc, len);
      DBG("The pointer falls within charlie allocator range (get_user case?), allocated memory @ %lx\n", allocated_addr);
      assert(allocated_addr == from); /* for now we only consier case where get_user access memory sequentially */
    }

  }
#ifdef GETCDEBUG
  xmlSaveFormatFile(ioctl_schema_filename, doc, 1);
  getc(stdin);
#endif
  //exit(0);

#if 0
  /* Check if we can accesss the memory */
  void *buf = alloca(len);
  if(uc_mem_read(uc, from, buf, len))
    printf("%s(): Cannot acess user-space memory...\n", __func__);
    //printf("%s(): Cannot acess user-space memory, let's allocate it and update the xml scheme\n", __func__);
#endif
  
  return true;
}

/* Code hook for __copy_from_user(), it's different from copy_from_user(),
 * We recover the kernel space destination (i.e. 'to' ) from this function and update 'kaddr' property
   of the corresponding xml node,
   see arch/arm64/lib/copy_from_user.S for __arch_copy_from_user() prototype */
bool code_hook__copy_from_user(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
  //DBG("%s(): Inside", __func__);
  ADDR_T to;
  ADDR_T from;
  ADDR_T from_access_ok; /* 'from' as was set in access_ok hook */
  REG_T n;
  uc_reg_read(uc, UC_ARM64_REG_X0, &to);
  uc_reg_read(uc, UC_ARM64_REG_X1, &from);
  uc_reg_read(uc, UC_ARM64_REG_X2, &n);
  DBG("__arch_copy_from_user(0x%lx,0x%lx,%ld)", to, from, n);

  assert(copy_from_user_array && "__arch_copy_from_user without  access_ok check!"); /* This global variable contains the xml node 'array' containing the newly allocated userspace array from access_ok() hook */

  /* It may happen that access_ok got 'from' from one registers (e.g. x2), and
   * __arch_copy_from_user() from
     a different register (e.g. x1). In this case x2 was updated with an
     address from charlie allocator, but x1 wasn't. We need to do it now.  */
  xmlChar *vaddr_prop = xmlGetProp(copy_from_user_array, (const xmlChar *)"vaddr"); /* 'from' from access_ok hook */
  from_access_ok = strtoul(vaddr_prop, NULL, 0);
  if(from != from_access_ok)
  {
    DBG("x1 is set to original random value from afl. Updating with vaddr value obtained in access_ok hook");
    uc_reg_write(uc, UC_ARM64_REG_X1, &from_access_ok);
  }

  char temp_buf[64]; // To temporary hold property values as a strings, we reuse it for every new property 
  sprintf(temp_buf, "0x%lx", to); 
  xmlNewProp(copy_from_user_array, "kaddr", temp_buf); /* vaddr of this node is in the userspce, kaddr corresponds to where it is going to be copied by copy_from_user() */ 
#ifdef DEBUG
  //xmlChar *vaddr_prop = xmlGetProp(copy_from_user_array, (const xmlChar *)"vaddr");
  DBG("Setting kaddr property (i.e. where it is going to be copied in kernel space) of userspace 'array' node (vaddr=%s) to %s", vaddr_prop, temp_buf);
#endif
#ifdef GETCDEBUG
  xmlSaveFormatFile(ioctl_schema_filename, doc, 1);
  getc(stdin);
#endif
  copy_from_user_array = NULL; /* This will be set again at access_ok() hook */
}


bool code_hook__kmalloc(uc_engine *uc, uint64_t address, uint32_t inst_size, void *user_data)
{
  DBG("%s(): Inside", __func__);
  REG_T size;
  REG_T flags;
  ADDR_T addr; /* Newly allocated memory */
  uc_reg_read(uc, UC_ARM64_REG_X0, &size);
  uc_reg_read(uc, UC_ARM64_REG_X1, &flags);

  if(size == 0)
    addr = 0x10; // ZERO_SIZE_PTR
  else
    addr = candy_memalloc(size);
  DBG("__kmalloc(%lu, 0x%lx), returning address 0x%lx", size, flags, addr);
  uc_reg_write(uc, UC_ARM64_REG_X0, &addr);

}

/* void *vmalloc(unsigned long size) */
bool code_hook_vmalloc(uc_engine *uc, uint64_t address, uint32_t inst_size, void *user_data)
{
  //DBG("%s(): Inside", __func__);
  REG_T size;
  ADDR_T addr; /* Newly allocated memory */
  uc_reg_read(uc, UC_ARM64_REG_X0, &size);

  if(size == 0)
    addr = 0x10; // ZERO_SIZE_PTR
  else
    addr = candy_memalloc(size);
  DBG("vmalloc(%ld), returning address 0x%lx", size, addr);
  uc_reg_write(uc, UC_ARM64_REG_X0, &addr);
}

/* NOTE: (important) This code hook work in conjuction with path_kernel where kmem_cache_alloc()
         is replaced by 'bx lr'. This allows us to use a new addr returned by candy allocator
	 and then immediately return to the caller */
bool code_hook_kmem_cache_alloc_trace(uc_engine *uc, uint64_t address, uint32_t inst_size, void *user_data)
{
  DBG("%s(): Inside", __func__);
  REG_T size;
  REG_T flags;
  ADDR_T addr; /* Newly allocated memory */
  uc_reg_read(uc, UC_ARM64_REG_X1, &flags);
  uc_reg_read(uc, UC_ARM64_REG_X2, &size);
  if(size == 0)
    addr = 0x10; // ZERO_SIZE_PTR
  else
    addr = candy_memalloc(size);
  DBG("kmem_cache_alloc_trace(kmem_cache, flags = 0x%lx, size=%ld); Using candy allocator, allocated addres: 0x%lx", flags, size, addr);
  uc_reg_write(uc, UC_ARM64_REG_X0, &addr);
}

/* NOTE: (important) This code hook works in conjuction with path_kernel where kmem_cache_alloc()
         is replaced by 'bx lr'. This allows us to use a new addr returned by candy allocator
	 and then immediately return to the caller 
  here is the function prorotye: void *krealloc(const void *p, size_t new_size, gfp_t flags) */
bool code_hook_krealloc(uc_engine *uc, uint64_t address, uint32_t inst_size, void *user_data)
{
  DBG("%s(): Inside", __func__);
  REG_T p;
  REG_T new_size;
  REG_T flags;
  ADDR_T addr; /* Newly allocated memory */
  uint8_t *p_content;
  uc_reg_read(uc, UC_ARM64_REG_X0, &p);
  uc_reg_read(uc, UC_ARM64_REG_X1, &new_size);
  uc_reg_read(uc, UC_ARM64_REG_X2, &flags);

  /* copy memory from <p>. We don't know the previous size so we copy new_size bytes  */
  p_content = malloc(new_size);
  if(uc_mem_read(uc, p, p_content, new_size)) {
    printf("error: uc_mem_read() called from %s\n", __func__);
    exit(0);
  }
  addr = candy_memalloc(new_size);
  if(uc_mem_write(uc, addr, p_content, new_size))
  {
    printf("error: uc_mem_write() called from %s\n", __func__);
    exit(0);
  }

  DBG("krelloc(p=0x%lx, new_size=%ld, flags = 0x%lx); Using candy allocator, allocated addres: 0x%lx", p, new_size, flags, addr);
  uc_reg_write(uc, UC_ARM64_REG_X0, &addr);
}

bool code_hook_generic_stub_0(uc_engine *uc, uint64_t address, uint32_t inst_size, void *user_data)
{
  DBG("%s(): Inside, setting return value to 0", __func__);
  REG_T func_ret = 0;
  uc_reg_write(uc, UC_ARM64_REG_X0, &func_ret);
}

/* We basically have a top level struct and all other elements are
  * either arrays or pointers. For pointers, the value is already set. */
#define XML_PROPERTY_MAX_SIZE 512
int update_xmlnode_with_data(uc_engine *uc, xmlNodePtr cur)
{
  xmlChar *size_prop;
  xmlChar *vaddr_prop;
  REG_T cur_size;
  ADDR_T cur_vaddr;
  uint8_t value[XML_PROPERTY_MAX_SIZE];
  char value_prop[2*XML_PROPERTY_MAX_SIZE+1]; /* Each byte is 2 hex digits */
  memset(value_prop, 0, 2*XML_PROPERTY_MAX_SIZE+1);

  /* Note that we already allocated memory as a part of parent struct/pointer */
  if(!xmlStrcmp(cur->name, (const xmlChar *)"array"))
  {
    /* Get size */
    assert(xmlHasProp(cur, "size"));
    size_prop = xmlGetProp(cur, (const xmlChar *)"size");
    cur_size = strtoul(size_prop, NULL, 0);
    //printf("%s(): cur_size = %d\n", __func__, cur_size);
    assert(xmlHasProp(cur, "vaddr"));
    vaddr_prop = xmlGetProp(cur, (const xmlChar *)"vaddr");
    cur_vaddr = strtoul(vaddr_prop, NULL, 0);
    //printf("%s(): cur_vaddr = 0x%x\n", __func__, cur_vaddr);
    //printf("cur_size = %d\n", cur_size);
    assert(cur_size < XML_PROPERTY_MAX_SIZE);

    if(uc_mem_read(uc, cur_vaddr, value, cur_size)) {
      printf("error: uc_mem_read() called from seek_function_ret\n");
      exit(0);
    }
    byte2hex(value, cur_size, value_prop);
    xmlNewProp (cur, "value", value_prop);
  }

  /* Parse children */
  xmlNodePtr child;
  child = cur->xmlChildrenNode;
  while (child != NULL) {
      if(child->type == 1) /* normal node */
      {
        update_xmlnode_with_data(uc, child);
      }
      child = child->next;
  }

  return 0;
}

/* Parse the xml scheme (stored in global <doc> variable) and include binary
 * data as value property for each of the elements */
int update_xmlscheme_with_data(uc_engine *uc)
{
  xmlNodePtr cur;
  cur = xmlDocGetRootElement(doc);
  assert(cur);
  update_xmlnode_with_data(uc, cur); /* 0 means don't fuzz by default, look for fuzz=yes flag */
  //xmlSaveFormatFile(ioctl_schema_filename, doc, 1);
  return 0;

}

/* The emulated code could not read <size> butes of memory at location <address> */
bool mem_unmapped_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
  DBG("Memory unmapped error when trying to access [0x%lx]; size = %d; value = 0x%lx.\n", address, size, value);
  return false;
}


/* Print usage and exit */
void usage()
{
  printf("\nusage: emulate [-h] -a SYSCALL [-s System.map] [-f AFLINPUT]\n");
  printf("Emulate code from ./memdumps and ./registers\n\n");
  printf("OPTIONS:\n\n");
  printf(" -h         Help message\n\n");
  printf(" -f FILE    Consume this file for fuzzing (e.g. afl)\n\n");
  printf(" -x FILE    Use ioctl struct schema from this file during fuzzing\n\n");
  printf(" -c NUM     Fuzz this ioctl command (use symbex.py to recover possible commands)\n"
         "            NUM is either a hex (preceded by 0x) or a decimal number\n\n");
  printf(" -a SYSCALL System call to fuzz, can be one of (read,write,open,ioctl)\n\n"
         "            You need to specify this this because we fuzz different arguments\n"
         "            for different system calls. Default is IOCTL.\n\n");
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

int fuzz_syscall = SYS_IOCTL; /* default: fuzz ioctl */
int arg_parse(int argc, char **argv)
{
  int opt;
  while ((opt = getopt (argc, argv, "hs:f:x:a:c:")) != -1)
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
      case 'x':
                //printf("setting\n\n");
                ioctl_schema_filename = optarg;
                //printf("setting: %s\n\n", ioctl_schema_filename);
		//exit(0);
		break;
      case 'c':
                ioctl_cmd = strtoul(optarg, NULL, 0);
                xmlschemetmp = malloc(64);
                sprintf(xmlschemetmp, "recovered-ioctlscheme-cmd-%lu", ioctl_cmd);
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

  if (systemmap_path == NULL)
  {
    printf("error: no -s option specified. System.map is required (use -h for details)\n");
    return -1;
  }
  return 0;
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
    DBG("prepare_fuzz_io_submit(): could not fetch memory for address 0x%lx\n", iocbpp);
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
    DBG("prepare_fuzz_io_submit(): nr = 0x%08lx\n", nr);
    DBG("prepare_fuzz_io_submit(): iocbpp = 0x%016lx\n", iocbpp);
    DBG("prepare_fuzz_io_submit(): iocbp = 0x%016lx\n", iocbp);
    DBG("prepare_fuzz_io_submit(): aio_nbytes = 0x%016lx\n", aio_nbytes);
    print_hex_(&aio_nbytes, 8);
    DBG("prepare_fuzz_io_submit(): aio_offset = 0x%016lx\n", aio_offset);
    print_hex(&aio_offset, 8);
    exit(0);
  }
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC);
  /* We need exactly 8+8=16 bytes for two fields */ 
  if(afl_input_size  != 16)
    return -2;

  uc_mem_write(uc, aio_nbytesp, afl_input,   8);
  uc_mem_write(uc, aio_offsetp, afl_input+8, 8);

  //DBG("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
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
    DBG("prepare_fuzz_aiowrite(): iov_base = 0x%lx\n", iov_base);
    DBG("prepare_fuzz_aiowrite(): iov_len = 0x%lx\n", iov_len);
    DBG("prepare_fuzz_aiowrite(): iov_base[0] = %c\n", fb);
    exit(0);
  }
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC);

  uc_mem_write(uc, iov_base, afl_input, afl_input_size);
  uc_mem_write(uc, iov_len, &afl_input_size, sizeof(afl_input_size));

  //DBG("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
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
  DBG("prepare_fuzz_getsockopt(): optval = 0x%lx\n", optval);
  int tmp_len;
  uc_mem_read(uc, optlen, &tmp_len, sizeof(tmp_len));
  char *tmp_val = alloca(tmp_len);
  uc_mem_read(uc, optval, tmp_val, tmp_len);
  DBG("prepare_fuzz_getsockopt(): *optlen = %d\n", tmp_len);
  //DBG("prepare_fuzz_getsockopt(): *optval = %s","\n");
  for(int i = 0; i < tmp_len; i++)
    printf("%02hhx", *(tmp_val+i));
  printf("\n");
  exit(0);
  /* For DEBUG purposes */
#endif

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC);

  uc_mem_write(uc, optval, afl_input, afl_input_size);
  uc_mem_write(uc, optlen, &afl_input_size, sizeof(afl_input_size));

  //DBG("prepare_fuzz_getsockopt(): afl_input_size = %lu\n", afl_input_size);
  free(afl_input);
  //exit(0);
  return 0;
}


/*
  @param addr Address where to put the node
  @param fuzz 1 if we need to fuzz this node, 0 otherwise
*/
int reconstruct_xmlnode_in_memory(uc_engine *uc, xmlDocPtr doc, xmlNodePtr cur, 
                   ADDR_T cur_addr, const char *afl_input, const char *afl_input_end,
		   int fuzz) 
{
  xmlChar *varname_prop;
  xmlChar *fuzz_prop;
  ADDR_T next_addr = 0;
  int ret_code = 0;

  //printf("\n");
  //printf("%s(): node '%s' @ 0x%x\n", __func__, cur->name, cur_addr);
  DBG("%s(): node '%s' @ 0x%lx\n", __func__, cur->name, cur_addr);
#if 0
  varname_prop = xmlGetProp(cur, (const xmlChar *)"varname");
  if(varname_prop)
    printf("%s(): node with varname '%s'\n", __func__, varname_prop);
#endif

  /* Note that fuzz might have been already set to 1 by the parent node, which
     is totally fine */
  fuzz_prop = xmlGetProp(cur, (const xmlChar *)"fuzz");
  if(fuzz_prop && (!xmlStrcmp(fuzz_prop, (const xmlChar *)"yes") || !xmlStrcmp(fuzz_prop, (const xmlChar *)"1")))
    fuzz = 1;

 
  /* if the node is a struct, which is a meta node, allocate space and simply pass the fuzz flag down the line */
  if(!xmlStrcmp(cur->name, (const xmlChar *)"struct"))
  {
    xmlChar *size_prop;
    REG_T size;
    size_prop = xmlGetProp(cur, (const xmlChar *)"size");
    size = size_prop ? strtoul(size_prop,  NULL, 0) : 0;
    /* If size is zero, make sure that the struct does not contain any elements (yet) */
    if(size == 0 && (xmlChildElementCount(cur) != 0))
    {
      printf("error: parsing xml ioctl scheme: struct size is 0 but has elements (did you modify ioctl scheme manually?)\n");
      exit(-1);
    }
    
    charlie_memalloc(size);
    next_addr = cur_addr; /* We only preallocate memory but don't actually move the current address, the child elements will do it */

  }

  /* If the node is a pointer, create and put a new pointer to 
     the next 4 bytes and assign its value to the address of the next 4 bytes*/
  else if(!xmlStrcmp(cur->name, (const xmlChar *)"pointer"))
  {
    if(!fuzz)
    {
      /* Read the value of the pointer as we need to follow it */
      assert(0 && "Mixed fuzzing (ie with concrete and random data) is no implemented yet (pointer case)!");
      if(uc_mem_read(uc, cur_addr, &next_addr, 4)) {
        printf("%s(),%d: Cannot acess memory\n", __func__, __LINE__);
        exit(0);
      };
    } else
    {

      /* Pointer needs to contain the size of the pointed data */
      xmlChar *size_prop;
      size_prop = xmlGetProp(cur, (const xmlChar *)"size");
      REG_T size = strtoul(size_prop,  NULL, 0);

      /* If size is zero, make sure that the pointer does not contain any elements (yet) */
      if(size == 0 && (xmlChildElementCount(cur) != 0))
      {
        printf("error: parsing xml ioctl scheme: pointed data size is 0 but has pointer node has child elements (did you modify ioctl scheme manually?)\n");
        exit(-1);
      }

      char temp_buf[64]; // To temporary hold property values as a strings, we reuse it for every new property 
      if(size == 0)
        size = POINTER_SIZE;
      //next_addr = charlie_memalloc(POINTER_SIZE); /* This should allocate space after the struct containing this pointer */
      next_addr = charlie_memalloc(size); /* This should allocate space after the struct containing this pointer */
      sprintf(temp_buf, "0x%lx", next_addr); 

      if(xmlHasProp(cur, "value")) /* The 'value' property is the actual value of the pointer (i.e. where it points in memory) */
        xmlSetProp(cur, "value", temp_buf);
      else
        xmlNewProp (cur, "value", temp_buf);

      //xmlNewProp (cur, "value", temp_buf); <<< You need to update this property
      if(ret_code = uc_mem_write(uc, cur_addr, &next_addr, POINTER_SIZE))
      {
         printf("error: uc_mem_write() failed to write to memory (%s)\n", uc_strerror(ret_code));
         exit(0);
      }
    }
  }

  /* If it is a base type node, we might need to replace its content with fuzzed data */
  /* Note that we already allocated memory for this pointer as a part of parent struct/pointer */
  else if(!xmlStrcmp(cur->name, (const xmlChar *)"u32"))
  {
    if(fuzz)
    {
      /* Sanity check that we did not run out of afl input */
      if(afl_input+4 >= afl_input_end)
      {
        printf("%s(): we ran out of afl_input, provide a larger seed!\n", __func__);
        return -1;
      }
      //next_addr = charlie_memalloc(POINTER_SIZE);
      if(ret_code = uc_mem_write(uc, cur_addr, afl_input, 4))
      {
         printf("error: uc_mem_write() failed to write to memory (%s)\n", uc_strerror(ret_code));
         exit(0);
      }
      afl_input = afl_input + 4;
    } else 
      assert(0 && "Mixed fuzzing (ie with concrete and random data) is no implemented yet (u32 case)!");
      
    //printf("%s(): type u32, advancing 4 bytes\n", __func__);
    next_addr = cur_addr + 4;
    DBG("%s(): type u32, advancing 4 bytes, next_addr=0x%lx\n", __func__, next_addr);
  } 

  /* Note that we already allocated memory as a part of parent struct/pointer */
  else if(!xmlStrcmp(cur->name, (const xmlChar *)"array"))
  {
    //assert(xmlHasProp(cur, "size")); /* Size property should always be present (either from the user or automatically discovered during previous runs  */
    if(!xmlHasProp(cur, "size")) /* Size property should always be present (either from the user or automatically discovered during previous runs  */
    {
      printf("error: parsing xml ioctl schema: array does not have size property\n");
      exit(-1);
    }
    xmlChar *size_prop;
    size_prop = xmlGetProp(cur, (const xmlChar *)"size");
    REG_T size = strtoul(size_prop,  NULL, 0);
    if(size == 0)
    {
      printf("error: parsing xml ioctl scheme: array size is 0 (did you modify ioctl scheme manually?)\n");
      exit(-1);
    }

    if(fuzz)
    {
     /* Copy this many aflinput bytes */
      /* Sanity check that we did not run out of afl input */
      if(afl_input+size >= afl_input_end)
      {
        printf("%s(): we ran out of afl_input, provide a larger seed!\n", __func__);
        return -1;
      }
      if(ret_code = uc_mem_write(uc, cur_addr, afl_input, size))
      {
         printf("error: uc_mem_write() failed to write to memory (%s)\n", uc_strerror(ret_code));
         exit(0);
      }
      afl_input = afl_input + size;
    } else
      assert(0 && "concrete fuzzing not supported yet (array)");
    next_addr = cur_addr + size;
    DBG("%s(): type array, advancing %ld bytes, next_addr=0x%lx\n", __func__, size, next_addr);
  }

  //assert(next_addr != 0);

  /* Parse children */
  xmlNodePtr child;
  child = cur->xmlChildrenNode;
  assert(!(child && !next_addr));
  while (child != NULL) {
      if(child->type == 1) /* normal node */
      {
        //printf("%s", child->name);
        next_addr = reconstruct_xmlnode_in_memory(uc, doc, child, next_addr, afl_input, afl_input_end, fuzz);
	DBG("%s(): %s: next_addr = 0x%lx\n", __func__, child->name, next_addr);
      }
      child = child->next;
  }


  /* Figure out the next address */
  ADDR_T ret;
  if(!xmlStrcmp(cur->name, (const xmlChar *)"pointer")) {
    ret = cur_addr+POINTER_SIZE; 
  } else if(!xmlStrcmp(cur->name, (const xmlChar *)"u32")) {
    ret = cur_addr+4; 
  } else { /* struct or array */
    ret = next_addr;
  }
#if 0
  uint32_t ret;
  if(!xmlStrcmp(cur->name, (const xmlChar *)"struct")) {
    ret = next_addr;
  } else if(!xmlStrcmp(cur->name, (const xmlChar *)"pointer")) {
    ret = addr+4; 
  } else if(!xmlStrcmp(cur->name, (const xmlChar *)"u32")) {
    ret = addr+4; 
  };
#endif

  char temp_buf[64]; // To temporary hold xml property values as a strings
  sprintf(temp_buf, "0x%lx", cur_addr); 
  if(xmlHasProp(cur, "vaddr"))
    xmlSetProp(cur, "vaddr", temp_buf);
  else
    xmlNewProp (cur, "vaddr", temp_buf);

  return ret;
}

/* Parse xml description of ioctl struct, recreate it in the memory and
   write the afl input there. afl_input is used as a source of bytes here 

   @param addr Address in virtual memory where ioctl struct starts
*/
uc_err reconstruct_ioctl_struct_in_memory(uc_engine *uc, ADDR_T addr, 
                                          const char *afl_input, size_t afl_input_size)
{
  //xmlDocPtr doc;
  assert(doc == NULL);
  xmlNodePtr cur;

  /* First, initialize the xml library. We create an empty struct schema if file does not exist */
  if(access( ioctl_schema_filename, F_OK ) == -1 ) 
  {
    int fd = open(ioctl_schema_filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR); 
    if(fd == -1)
    {
      printf("error: provided ioctl scheme file does not exist and I could not create one\n");
      exit(-1);
    }
    char tmp_buf[128];
    write(fd, "<?xml version=\"1.0\"?>\n", sizeof("<?xml version=\"1.0\"?>\n")-1); /* -1 is to remove the '\0' byte */
    
    sprintf(tmp_buf, "<struct cmd=\"%lu\" varname=\"userdata\" fuzz=\"yes\">\n", ioctl_cmd);
    //write(fd, "<struct varname=\"userdata\" fuzz=\"yes\">\n", sizeof("<struct varname=\"userdata\" fuzz=\"yes\">\n")-1);
    write(fd, tmp_buf, strlen(tmp_buf));
    write(fd, "</struct>", sizeof("</struct>")-1);
    close(fd);
  }

  doc = xmlParseFile(ioctl_schema_filename);
  
  if (doc == NULL ) {
  	fprintf(stdout,"Document not parsed successfully. \n");
  	return -1;
  }
  
  cur = xmlDocGetRootElement(doc);
  
  if (cur == NULL) {
  	fprintf(stdout,"empty document\n");
  	xmlFreeDoc(doc);
  	return -1;
  }

  /* Sanity check of the cmd */
  xmlChar *cmd_prop;
  cmd_prop = xmlGetProp(cur, (const xmlChar *)"cmd");
  if(cmd_prop)
  {
    unsigned long cmd = strtoul(cmd_prop,  NULL, 0);
    if(cmd != ioctl_cmd)
    {
      printf("error: ioctl cmd specified in the command line does not match the cmd from xml\n");
      exit(-1);
    }
  }


  /* Now we are ready for xml tree traversal */
  DBG("%s(): going to traverse root\n", __func__);
  /* This will update the size and virtual addresses of the ioctl struct */
  reconstruct_xmlnode_in_memory(uc, doc, cur, addr, afl_input, afl_input+afl_input_size, 0); /* 0 means don't fuzz by default, look for fuzz=yes flag */
  /* Save the updated scheme, we will reuse whenever copy_from_user() fails */
  //xmlSaveFormatFile ("updatedioctl.xml", doc, 1);
#ifndef DYNAMICRECOVERY
  xmlSaveFormatFile(ioctl_schema_filename, doc, 1);
#endif
  return 0;
}

/* Replace user input for 'ioctl' system call with afl mutated input 
 * 
 * Read register x2 which is the third argument that contains the
 * pointer to user's data. Write afl mutated input to this address.
 */
uc_err prepare_fuzz_ioctl(uc_engine *uc)
{
  if(afl_input_filepath == NULL)
    return -1;
  //size_t afl_input_size;

  init_charlie_allocator(uc);
  /* Register $2 contains ioctl's argp arguments (i.e. pointer to user data).
     Since there might be not enought space in the memory area pointed by the
     original value of argp, we move it to our own location */
  REG_T orig_cmd;  /* Just for debug purpose */
  REG_T orig_argp;  /* Just for debug purpose */
  //uint32_t orig_size;  /* Just for debug purpose */
  REG_T new_cmd = ioctl_cmd;
  ADDR_T new_argp = charlie_memalloc(0);  /* This will return the current value of brk, and since it's the first call, this value equals the base address (0x10000000) */

  uc_reg_read(uc, UC_ARM64_REG_X2, &orig_argp);
  uc_reg_read(uc, UC_ARM64_REG_X1, &orig_cmd);

  DBG("%s: original argp=0x%lx; moving to 0x%lx; original cmd = %lu (0x%lx), changing to %lu\n", 
            __func__, orig_argp, new_argp, orig_cmd, orig_cmd, new_cmd);
  uc_reg_write(uc, UC_ARM64_REG_X1, &new_cmd);
  uc_reg_write(uc, UC_ARM64_REG_X2, &new_argp);

#ifdef DYNAMICRECOVERY
  ioctl_schema_filename = xmlschemetmp;
  unlink(ioctl_schema_filename); /* Remove whatever remained from the previous fuzzing sessions, we'll create a new one with an empty structure */
  assert(ioctl_schema_filename);
#endif
  if(ioctl_schema_filename == NULL) /* For non-dynamic recover we need to provide scheme filename (the actual file might not exist, which is fine) that will be gradually updated */
  {
    //printf("%s(): no ioctl schema is given, falling back to linear\n", __func__);
    //uc_mem_write(uc, argp, afl_input, afl_input_size);
    printf("error: fuzzing in [static] mode requires ioctl schema. If you don't have a scheme, you can specify a path name, and I will create such scheme for you. Use this file afterwards.\n");
    exit(0);
  }

  afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC); /* note: afl_input is global */
  //print_hex(afl_input, 12);
  //getc(stdin);
  afl_input_start = afl_input;
  reconstruct_ioctl_struct_in_memory(uc, new_argp, afl_input, afl_input_size);

  
  /* note: afl_input is global, so we don't free it here */
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

  char *afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC);
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

/* Replace user input for 'write' system call handler with afl mutated input 
 * 
 * r0 to r3: used to hold argument values passed to a subroutine 
 * Read register r1 which is the second argument that contains the
 * pointer to user's data. Write afl mutated input to this address 
 */
uc_err prepare_fuzz_write(uc_engine *uc)
{
  if(afl_input_filepath == NULL)
    return -1;
  size_t afl_input_size;
  uint64_t user_address; /* Pointer to user-space buffer */
  uint64_t user_len;     /* Length, specified by the user */
  /* Get original second and third arguments, which are stored in r1 and r2,
     the second is the most important as it contains the pointer to the user's input
     that we need to mutate */
  uc_reg_read(uc, UC_ARM_REG_R1, &user_address);
  uc_reg_read(uc, UC_ARM_REG_R2, &user_len);
  //printf("user_address = %lx\n", user_address);
  //printf("user_len = %lu\n", user_len);

  char *afl_input = read_whole_file(afl_input_filepath, &afl_input_size, USE_MALLOC);
  //printf("afl_input = %02hhx:%02hhx\n", afl_input[0],afl_input[1]);
  //printf("afl_input_size = %lu\n", afl_input_size);

  /* Now write afl input to the user buffer and also set register r2 to afl data length*/
  uc_mem_write(uc, user_address, afl_input, afl_input_size);
  uc_reg_write(uc, UC_ARM_REG_R2, &afl_input_size);

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

     case SYS_WRITE :
       return prepare_fuzz_write(uc);
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

/* 
   We used setup_cpregs.bin for arm32  to set up coprocessor registers, thus the name.
   For arm64 we just map a nop instruction. We do this to start afl fork server */
#define CPREG_CODE_VADDR 0x30000000
//#define CPREGS_CODE "\x1f\x20\x03\xd5" /* rasm2 -a arm -b 64 'nop' --> 1f2003d5 */
#define CPREGS_CODE_PATH "setup_cpregs.bin"
//#define CPREGS_CODE_SZ 4
size_t map_cpregs_code(uc_engine *uc)
{
  void *dump = NULL;
  int ret_code = 0;
  size_t dump_size;
  unsigned long int dump_vaddr = CPREG_CODE_VADDR; /* Virtual address of the dump */
  dump = read_whole_dump(CPREGS_CODE_PATH, &dump_size, USE_MALLOC);

  if(ret_code = uc_mem_map(uc, PAGE_START(dump_vaddr), PAGE_ALIGNED(dump_size), UC_PROT_ALL)) {
    printf("error: uc_mem_map() for nop code (%s)\n", uc_strerror(ret_code));
    exit(0);
  }

  /* Write dumps to emulated memory */
  if(ret_code = uc_mem_write(uc, PAGE_START(dump_vaddr), dump, dump_size)) {
    printf("error: uc_mem_write() failed to write emulation code (%s) to memory (%s)\n", "nop", uc_strerror(ret_code));
    exit(0);
  }

  /* Return the size of instructions only; the code dump contains 64bit .word's that cannot be executed */
  csh handle;
  size_t count;
  cs_insn *all_insn;
  cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle); // TODO: check if cs_open does not fail
  count = cs_disasm(handle, dump, dump_size, CPREG_CODE_VADDR, 0, &all_insn);
  return count*INST_SIZE;
  //return dump_size-12; /* the last two 64bit values in the dump are not instructions (but system register values) */
}

int set_kmalloc_code_hooks(uc_engine *uc)
{
#ifdef DYNAMICRECOVERY
  /* Dynamic ioctl recover requires us to hook __copy_from_user() in order to
   * find out where the invalid userspace pointer was copied and replace it.
   * ivanp: __copy_from_user() is used in kernel v3.4. In kernel v.4.9, they
   * use arm_copy_from_user() */
  ADDR_T __copy_from_user_addr = get_symbol_address("__copy_from_user");
  if(!__copy_from_user_addr)
    __copy_from_user_addr = get_symbol_address("__arch_copy_from_user");
  assert(__copy_from_user_addr);
  uc_hook hh__copy_from_user;
  uc_hook_add(uc, &hh__copy_from_user, UC_HOOK_CODE, 
            code_hook__copy_from_user, NULL, __copy_from_user_addr, __copy_from_user_addr+1);
#endif

  /* Hook to check the size passed to kmalloc, otherwise we'll get too many
   * false positive on failed kmalloc (since our VM was only limited RAM) */
  ADDR_T __kmalloc_addr = get_symbol_address("__kmalloc");
  assert(__kmalloc_addr);
  uc_hook hh__kmalloc;
  uc_hook_add(uc, &hh__kmalloc, UC_HOOK_CODE, 
            code_hook__kmalloc, NULL, __kmalloc_addr, __kmalloc_addr+1);
  ADDR_T kmalloc_order_trace_addr = get_symbol_address("kmalloc_order_trace");
  assert(kmalloc_order_trace_addr);
  uc_hook hh_kmalloc_order_trace;
  uc_hook_add(uc, &hh_kmalloc_order_trace, UC_HOOK_CODE, 
            code_hook__kmalloc, NULL, kmalloc_order_trace_addr, kmalloc_order_trace_addr+1); /* we use code_hook__kmalloc() intentionally */
  ADDR_T vmalloc_addr = get_symbol_address("vmalloc");
  assert(vmalloc_addr);
  uc_hook hh_vmalloc;
  uc_hook_add(uc, &hh_vmalloc, UC_HOOK_CODE, 
            code_hook_vmalloc, NULL, vmalloc_addr, vmalloc_addr+1);
  ADDR_T kmem_cache_alloc_trace_addr = get_symbol_address("kmem_cache_alloc_trace");
  assert(kmem_cache_alloc_trace_addr);
  uc_hook hh_kmem_cache_alloc_trace;
  uc_hook_add(uc, &hh_kmem_cache_alloc_trace, UC_HOOK_CODE, 
            code_hook_kmem_cache_alloc_trace, NULL, kmem_cache_alloc_trace_addr, kmem_cache_alloc_trace_addr+1);
  ADDR_T krealloc_addr = get_symbol_address("krealloc");
  assert(krealloc_addr);
  uc_hook hh_krealloc;
  uc_hook_add(uc, &hh_krealloc, UC_HOOK_CODE, 
            code_hook_krealloc, NULL, krealloc_addr, krealloc_addr+1);

  /* Hook generic_stub_0. This function has a complext body to print the original function that
     was replaced. We don't need this complex functionality here, just want to return 0 */
  ADDR_T generic_stub_0_addr = get_symbol_address("generic_stub_0");
  assert(generic_stub_0_addr);
  uc_hook hh_generic_stub_0;
  uc_hook_add(uc, &hh_generic_stub_0, UC_HOOK_CODE, 
            code_hook_generic_stub_0, NULL, generic_stub_0_addr, generic_stub_0_addr+1);

  /* Just return 0 for i2c read/write (works together with patch_kernel); TODO add other i2c functions*/
  ADDR_T i2c_smbus_write_byte_data_addr = get_symbol_address("i2c_smbus_write_byte_data");
  assert(i2c_smbus_write_byte_data_addr);
  uc_hook hh_i2c_smbus_write_byte_data;
  uc_hook_add(uc, &hh_i2c_smbus_write_byte_data, UC_HOOK_CODE, 
            code_hook_generic_stub_0, NULL, i2c_smbus_write_byte_data_addr, i2c_smbus_write_byte_data_addr+1);
  ADDR_T i2c_smbus_read_byte_data_addr = get_symbol_address("i2c_smbus_read_byte_data");
  assert(i2c_smbus_read_byte_data_addr);
  uc_hook hh_i2c_smbus_read_byte_data;
  uc_hook_add(uc, &hh_i2c_smbus_read_byte_data, UC_HOOK_CODE, 
            code_hook_generic_stub_0, NULL, i2c_smbus_read_byte_data_addr, i2c_smbus_read_byte_data_addr+1);

  return 0;
}

bool code_hook_stop_emu(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
  DBG(%s(): Emulation reached destination address. Stopping, __func__);
  uc_emu_stop(uc);
  return true;
}

int set_stop_emul_hook(uc_engine *uc, ADDR_T end_address)
{
  uc_hook hh_stop_emu;
  uc_hook_add(uc, &hh_stop_emu, UC_HOOK_CODE, code_hook_stop_emu, NULL, end_address, end_address+1);
  return 0;
}

int run_cpregs_code(uc_engine *uc, size_t code_size)
{
  uc_err err;
  /* cpreg_code uses x1 to store transfer values to coprocessor register,
     so we need to save it now and then restore */
  REG_T x1;
  uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
  err=uc_emu_start(uc, CPREG_CODE_VADDR, CPREG_CODE_VADDR+code_size, 0, 0);
  if (err) {
    printf("Warning: while executing setup_cpregs code: uc_emu_start() %u: %s\n", err, uc_strerror(err));
  }
  uc_reg_write(uc, UC_ARM64_REG_X1, &x1);
  uc_emu_stop(uc);
  return err;
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

  /* 1. Initialize emulator in arm64 mode */
  err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  /* 2. Read register and memory dumps dumps */
  DBG("[+] Initializing registers from registers/gdb-registers.txt");
  init_registers_from_gdb(uc);
#ifdef DEBUG
  DBG("[+] Dumping registers\n");
  dump_registers(uc);
#endif
  DBG("[+] Initializing memory from dumps in ./memdumps/ folder");
  init_memory_from_dumps(uc);

  /* 3. Add hooks */
#ifdef DEBUG
  //if(DEBUG)
  //{
    uc_hook hh_code;
    uc_hook_add(uc, &hh_code, UC_HOOK_CODE, code_hook, NULL, 1, 0);
  //}
#endif
  uc_hook hh_unmapped; /* TODO: we don't really do anything this hook, just return false which causes uc_emu_start() to stop with non-zero error code which leads to raise(SIGSEGV) */
  if(uc_hook_add(uc, &hh_unmapped, UC_HOOK_MEM_UNMAPPED, mem_unmapped_hook, NULL, 1, 0))
  {
    printf("error: uc_hook_add() for UC_HOOK_MEM_UNMAPPED\n");
    exit(0);
  }

  set_kmalloc_code_hooks(uc);
  //set_getuser_code_hooks(uc); /* FIXME: these functions use access_ok(), need to deal with them */
  //set_putuser_code_hooks(uc);

  tend = clock();
  cpu_time_used = ((double) (tend - tstart)) / CLOCKS_PER_SEC;
  ADDR_T ret_fast_syscall_addr = get_symbol_address("ret_fast_syscall"); /* We do it before starting the fork server */
  DBG(ret_fast_syscall_addr=%lx, ret_fast_syscall_addr);

  set_stop_emul_hook(uc, ret_fast_syscall_addr); /* by some reason unicorn hangs when it reaches the end of emulation */

  size_t cpregs_code_size = map_cpregs_code(uc); /* We map it before running the fork server */
  if(afl_input_filepath == NULL)
    printf("warning: not in fuzz mode (-f was not specified) copy_from_user() will not be tracked for ioctl struct recovery. If there is a call to copy_from_user() in the code, the emulation will fail an assertion!\n");
  printf("Initialization took %f seconds\n", cpu_time_used);
  tstart = clock();

  /* 4. Setup coprocessor registers, we do it in assembly since unicorn does not provide and API to do that 
     This will also start the fork server if we did not start */
  run_cpregs_code(uc, cpregs_code_size);
  init_candy_allocator(uc); /* kernel allocator; TODO: think of moving init charlie allocator here too */

  /* 5. Optionally prepare AFL */
  if(afl_input_filepath != NULL){
    /* We load afl input here, note that we need to emulate at least on instruction before loading afl input */
    if(prepare_fuzz_ioctl(uc) < 0) {
      printf("prepare_fuzzer() failed, segfaulting!\n");
      raise(SIGSEGV);
    }
  }
  
  /* 6. emulate code in infinite time & unlimited instructions until 'ret_fast_syscall()' which is at 0x8000df00.
     See the following for why we chose this stop function :https://stackoverflow.com/questions/24176570/how-does-a-system-call-travels-from-user-space-to-kernel-space-and-back-to-user 
  */
  //err=uc_emu_start(uc, cpu_state.regs[UC_ARM64_REG_PC], ret_fast_syscall_addr, 0, 0);
  err=uc_emu_start(uc, cpu_state.regs[UC_ARM64_REG_PC], 0, 0, 0);
  //err=uc_emu_start(uc, cpu_state.regs[UC_ARM64_REG_PC], 0xffff000008244660, 0, 0);
  if (err) { /* This is set if there were memory unmapped errors due to bugs in the kernel */
    printf("Warning: uc_emu_start() %u: %s\n", err, uc_strerror(err));
    //dump_registers(uc);
    if(afl_input_filepath) /* Only if we fuzz or provide external input (we don't recover the ioctl struct otherwise */
      update_xmlscheme_with_data(uc); /* Sets 'value' property for each recovered ioctl struct field */
    xmlSaveFormatFile(ioctl_schema_filename, doc, 1);
    raise(SIGSEGV);
  }

  // now print out some registers
  ADDR_T reg;
  uc_reg_read(uc, UC_ARM64_REG_PC, &reg);
  DBG(">>> PC = 0x%lx", reg);
  tend = clock();
  cpu_time_used = ((double) (tend - tstart)) / CLOCKS_PER_SEC;
  printf("Emulation only took %f seconds\n", cpu_time_used);
  if(afl_input_filepath) /* Only if we fuzz or provide external input (we don't recover the ioctl struct otherwise */
    update_xmlscheme_with_data(uc); /* Sets 'value' property for each recovered ioctl struct field */
  xmlSaveFormatFile(ioctl_schema_filename, doc, 1);

  uc_close(uc);

  return 0;
}

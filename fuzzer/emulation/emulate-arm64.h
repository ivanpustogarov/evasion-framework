#define PAGE_SIZE 0x1000
#define PAGE_MASK 0xfffffffffffff000
#define KMALLOC_SIZE_LIMIT 512 /* in bytes */
#define PAGE_ALIGNED(sz)  ( sz ? (((sz-1) & PAGE_MASK) + PAGE_SIZE) : 0 )
#define PAGE_START(addr)  (addr & PAGE_MASK)
#define read_whole_file read_whole_dump
#define XMLSCHEMETMP "/tmp/updatedioctl.xml"

#define MAX_MODULES 16
#define MAX_FILENAME 64

//#define DEBUG 1 // ivanp: This is now defined throug makefile
//#define debug_print(fmt, ...) \
//            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

/* Uncomment the next line to pause (with getc()) inside codehooks */
//#define GETCDEBUG 
#ifdef DEBUG
#define DBG(fmt, ...) fprintf(stdout, "[DEBUG]: " #fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) \
            do { } while (0)
#endif

#define MEMDUMPS_PATH      "./memdumps/"
#define REGISTERS_PATH     "./registers/qmp-registers.txt"
#define GDB_REGISTERS_PATH "./registers/gdb-registers.txt"
#define KERNELMAPPING_PATH "./memmappings/kernel_page_tables.txt"
#define SYSTEMMAP_PATH     "./memmappings/System.map"

// Sys call numbers for arm: https://github.com/torvalds/linux/blob/master/arch/arm/tools/syscall.tbl
#define SYS_READ 3
#define SYS_WRITE 4
#define SYS_OPEN 5
#define SYS_IOCTL 16
#define SYS_GETSOCKOPT 55
#define SYS_IOSUBMIT 209
#define SYS_AIOWRITE 5000

#define TARGET_LONG_BITS 64
#define TARGET_ADDRESS_SIZE_BYTES 8
#define POINTER_SIZE TARGET_ADDRESS_SIZE_BYTES
#define TARGET_LONG_SIZE (TARGET_LONG_BITS / 8)
#define INST_SIZE 4 /* size of an arm64 instruction is 4 bytes */

typedef uint64_t ADDR_T;
typedef uint64_t REG_T; /* type of register: ARM64 are 64 bits */

typedef struct CPUARM64State { 
    /* Regs for current mode.  */
    REG_T regs[UC_ARM64_REG_ENDING];
} CPUARM64State;

/* Extracted from uc_priv.h */
struct hook {
    int type;            // UC_HOOK_*
    int insn;            // instruction for HOOK_INSN
    int refs;            // reference count to free hook stored in multiple lists
    uint64_t begin, end; // only trigger if PC or memory access is in this address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
};
/* ** */

/* Ugly list operatons */
typedef struct ugly_list_node {
   void *aux_data;
   uint64_t val;
   struct ugly_list_node *next;
} ugly_list_node;

typedef struct ugly_list {
   ugly_list_node *head;
   ugly_list_node *tail;
} ugly_list_t;

typedef struct pair {
  int type;
  uint64_t value;
} pair_t;

void ugly_list_init(ugly_list_t *lst) {
  lst->head = NULL;
  lst->tail = NULL;
};

ugly_list_node *ugly_list_add(ugly_list_t *lst, uint64_t v, void *aux_data) {
  ugly_list_node *newel = malloc(sizeof(ugly_list_node));
  if(!(lst->head))
  {
    lst->head = newel;
    lst->tail = newel;
  } else {
    lst->tail->next = newel;
    lst->tail = newel;
  }
  newel->val = v;
  newel->aux_data = aux_data;
  newel->next = NULL;
};

void ugly_list_deepclear(ugly_list_t *lst) {
  ugly_list_node *cur = lst->head;
  ugly_list_node *nxt = NULL;
  while(cur)
  {
    nxt = cur->next;
    free(cur->aux_data);
    free(cur);
    cur = nxt;
  }
}

/* ** */

#define streq(x,y) (strcmp(x,y)==0)

void dump_registers(uc_engine *uc);
void *read_whole_dump(char *pathname, size_t *dump_size, int use_mmap);
bool code_hook_copy_from_user(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
int reg_to_str_gdb(char *dst, uc_arm64_reg reg);
bool code_hook_getuser(uc_engine *uc, uint64_t instr_address, uint32_t instr_size, void *user_data);

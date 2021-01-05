#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <inttypes.h> // For PRIx64 format in printf
#include <assert.h> // For assert() function

// code to be emulated
//#define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx
#define ARM_CODE "\x00\x00\xa0\xe3\x04\x00\xa0\xe1" // MOV r0, #0; MOV r0, r4 (intel flavour)

// memory address where emulation starts
#define ADDRESS 0x1000000


int disass(void *buf, uint32_t size, uint64_t address)
{
  // Capstone
  csh handle;
  cs_insn *insn;
  size_t count;
  if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK)
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


void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
  assert(size < 16);
  void *buf = alloca(16);
  uc_mem_read(uc, address, buf, size);
  disass(buf, size, address);
}


int main(int argc, char **argv, char **envp)
{
  uc_engine *uc;
  uc_err err;
  int r0 = 0x1234;     // ECX register
  int r4 = 0x7890;     // EDX register

  printf("Emulate ARM code\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  // map 2MB memory for this emulation
  uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE) - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return -1;
  }

  // initialize machine registers
  uc_reg_write(uc, UC_ARM_REG_R0, &r0);
  uc_reg_write(uc, UC_ARM_REG_R4, &r4);

  uc_hook hh_code;
  uc_hook_add(uc, &hh_code, UC_HOOK_CODE, code_hook, NULL, 1, 0);

  // emulate code in infinite time & 2 instructions
  err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) - 1, 0, 2);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n",
      err, uc_strerror(err));
  }

  // now print out some registers
  printf("Emulation done. Below is the CPU context\n");

  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_R4, &r4);
  printf(">>> r0 = 0x%x\n", r0);
  printf(">>> r4 = 0x%x\n", r4);

  uc_close(uc);

  return 0;
}

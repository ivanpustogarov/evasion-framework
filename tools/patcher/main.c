#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <capstone/capstone.h>
#include <inttypes.h>


/* This program modifies reloaction table in an arm32 elf file
   @author:  ivan pustogarov
   @date:    20 Nov 2018
   @license: GPL
*/

#define ERROR printf
# define DO_386_32(S, A)	((S) + (A))
# define DO_386_PC32(S, A, P)	((S) + (A) - (P))
# define ELF_RELOC_ERR -1




typedef struct {
  Elf32_Sym *base;
  uint32_t  value; // usually offset from the start of the section where the symbol is defined
  uint32_t ndx; // Index of this symbol in the corresponding symbol table
  uint32_t symtab_sh_ndx; // Index of the corresponding symbol table (where this symbol belogns)
  char name[256]; // Symbol name
  uint32_t abs_offset; // Offset from the file start
} Elf32_simple_symbol;

typedef struct {
  Elf64_Sym *base;
  uint64_t  value; // usually offset from the start of the section where the symbol is defined
  uint32_t ndx; // Index of this symbol in the corresponding symbol table
  uint32_t symtab_sh_ndx; // Index of the corresponding symbol table (where this symbol belogns)
  char name[256]; // Symbol name
  uint32_t abs_offset; // Offset from the file start
} Elf64_simple_symbol;

int get_reloc_caller(Elf32_Ehdr *hdr, unsigned int offset, Elf32_simple_symbol *symbol);
int get_reloc64_caller(Elf64_Ehdr *hdr, unsigned int offset, Elf64_simple_symbol *symbol);
int find_symbol_by_name(Elf32_Ehdr *hdr, const char* name, Elf32_simple_symbol *symbol);

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
    //return -1;
    printf("ERROR: Failed to disassemble given code!\n");

  return 0;
}


/*
 1) reloction_section
      /      \
     /        \
    v          v
   sh_link    sh_info
      =           =
symbol_table    section where to patch

  2) reloc_entry
      |
      --- symbol index
      |
      --- patch offset from the section start

*/
typedef struct {
  Elf32_Rel *base;
  Elf32_simple_symbol symbol;
  uint32_t reltab_sh_ndx; // Index of the corresponding relocation table
  uint32_t abs_offset; // Offset from the file start
} Elf32_simple_reloc;


/* Return pointer to ELF section header 
   @param hdr Start of ELF file
*/
static inline Elf32_Shdr *elf_sheader(Elf32_Ehdr *hdr) {
	return (Elf32_Shdr *)((char *)hdr + hdr->e_shoff);
}

static inline Elf64_Shdr *elf64_sheader(Elf64_Ehdr *hdr) {
	return (Elf64_Shdr *)((char *)hdr + hdr->e_shoff);
}
 
static inline Elf32_Shdr *elf_section(Elf32_Ehdr *hdr, int idx) {
	return &elf_sheader(hdr)[idx];
}

static inline Elf64_Shdr *elf64_section(Elf64_Ehdr *hdr, int idx) {
	return &elf64_sheader(hdr)[idx];
}

static inline char *elf_str_table(Elf32_Ehdr *hdr) {
	if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
	return (char *)hdr + elf_section(hdr, hdr->e_shstrndx)->sh_offset;
}
 
static inline char *elf_lookup_string(Elf32_Ehdr *hdr, int offset) {
	char *strtab = elf_str_table(hdr);
	if(strtab == NULL) return NULL;
	return strtab + offset;
}

/*
 * @param symtabl_sh_idx Symbol table index number
 * @param symbol_idx Symbol index in the symbol table
*/
//static inline char *elf_get_symbolname(Elf32_Ehdr *hdr, int symtab_sh_idx, int sybmol_idx) {
//        	
//        Elf32_Shdr *symtab_sh = elf_section(hdr, symtab_sh_idx);
//        Elf32_Shdr *strtab_sh = elf_section(hdr, symtab_sh->sh_link);
//
//        Elf32_Sym *symbol = &((Elf32_Sym *)symaddr)[idx];
//	char *strtab = elf_str_table(hdr);
//	if(strtab == NULL) return NULL;
//	return strtab + offset;
//}


int print_sections(Elf32_Ehdr *hdr)
{
  Elf32_Shdr *sect; // = elf_section(hdr, 1);
  char *sh_name = NULL;
  printf("Here are section names:\n");
  for(int i=0; i < hdr->e_shnum; i++)
  {
    sect = elf_section(hdr, i);
    if(sect->sh_type == SHT_NULL)
      continue;
    if(sect->sh_name != SHN_UNDEF)
      sh_name = elf_lookup_string(hdr, sect->sh_name);
    char sh_type_str[16];
    switch(sect->sh_type) {
        case SHT_NULL     : strcpy(sh_type_str, "NULL"); break;
	case SHT_PROGBITS : strcpy(sh_type_str, "PROGBITS"); break;
	case SHT_SYMTAB   : strcpy(sh_type_str, "SYMTAB"); break;
	case SHT_STRTAB   : strcpy(sh_type_str, "STRTA"); break;
	case SHT_RELA     : strcpy(sh_type_str, "RELA"); break;
	case SHT_NOBITS   : strcpy(sh_type_str, "NOBITS"); break;
	case SHT_REL	  : strcpy(sh_type_str, "REL"); break;
    }
    printf("%8s Section #%02d %s\n", sh_type_str, i, (sh_name ? sh_name : "NULL"));
  }
  return 0;
}

void zero_out_symbol(Elf32_simple_symbol *s)
{
  s->base=NULL;
  s->value=0;
  s->ndx=0;
  s->symtab_sh_ndx=0;
  //strcpy(s->name, "");
  s->abs_offset=0; 
}
void zero_out_symbol_64(Elf64_simple_symbol *s)
{
  s->base=NULL;
  s->value=0;
  s->ndx=0;
  s->symtab_sh_ndx=0;
  //strcpy(s->name, "");
  s->abs_offset=0; 
}

/* Get symbol by its index from a symbol table
 *
 * @param table Symbol table section number
 * @param idx   Symbol index in the symbol table
*/
static int elf_get_symbol(Elf32_Ehdr *hdr, int table, uint idx, Elf32_simple_symbol *out) {
  if(table == SHN_UNDEF || idx == SHN_UNDEF) return -1;
  if(!out) return -2;

  zero_out_symbol(out);

  Elf32_Shdr *symtab = elf_section(hdr, table);
  
  uint32_t symtab_entries = symtab->sh_size / symtab->sh_entsize;
  if(idx >= symtab_entries) {
  	printf("Symbol Index out of Range (%d:%u).\n", table, idx);
  	return -3;
  	//return ELF_RELOC_ERR;
  }
 
  /* symaddr points to the actual section, while symtab is section hader */
  char *symaddr = (char *)hdr + symtab->sh_offset;
  Elf32_Sym *symbol = &((Elf32_Sym *)symaddr)[idx];

  Elf32_Shdr *strtab = elf_section(hdr, symtab->sh_link);
  const char *name = NULL;
  if(symbol->st_name != 0)
  {
    name = (const char *)hdr + strtab->sh_offset + symbol->st_name;
    strcpy(out->name, name);
  } else
    strcpy(out->name, "");
    //out->name = NULL;
  if( (symbol->st_shndx != SHN_ABS) && (symbol->st_shndx != SHN_COMMON) && 
      (symbol->st_shndx != SHN_UNDEF) )
  {
    Elf32_Shdr *symbol_section = elf_section(hdr, symbol->st_shndx);
    //printf("symbol %s is defined in section #%d\n", out->name, symbol->st_shndx);
    out->abs_offset = symbol_section->sh_offset + symbol->st_value;
    //out->abs_offset = elf_section(hdr, symbol->st_shndx)->sh_offset + symbol->st_value;
    //out->abs_offset =  symbol->st_value;
  }
  out->base = symbol;
  out->ndx = idx;
  out->symtab_sh_ndx = table;
  out->value = symbol->st_value;
  return 0;
 
 /*
  if(symbol->st_shndx == SHN_UNDEF) 
  {
    // External symbol, lookup value
    Elf32_Shdr *strtab = elf_section(hdr, symtab->sh_link);
    const char *name = (const char *)hdr + strtab->sh_offset + symbol->st_name;
    
    extern void *elf_lookup_symbol(const char *name);
    void *target = elf_lookup_symbol(name);
    
    if(target == NULL) {
    	// Extern symbol not found
    	if(ELF32_ST_BIND(symbol->st_info) & STB_WEAK) {
    		// Weak symbol initialized as 0
    		return 0;
    	} else {
    		ERROR("Undefined External Symbol : %s.\n", name);
    		return ELF_RELOC_ERR;
    	}
    } else {
    	return (int)target;
    }
  } else if(symbol->st_shndx == SHN_ABS) 
  {
  	// Absolute symbol
  	return symbol->st_value;
  } else 
  {
  	// Internally defined symbol
  	Elf32_Shdr *target = elf_section(hdr, symbol->st_shndx);
  	return (int)hdr + symbol->st_value + target->sh_offset;
  }
  */
}


/* Get symbol by its index from a symbol table
 *
 * @param table Symbol table section number
 * @param idx   Symbol index in the symbol table
*/
static int elf64_get_symbol(Elf64_Ehdr *hdr, int table, uint idx, Elf64_simple_symbol *out) {
  if(table == SHN_UNDEF || idx == SHN_UNDEF) return -1;
  if(!out) return -2;

  zero_out_symbol_64(out);

  Elf64_Shdr *symtab = elf64_section(hdr, table);
  
  uint32_t symtab_entries = symtab->sh_size / symtab->sh_entsize;
  if(idx >= symtab_entries) {
  	printf("Symbol Index out of Range (%d:%u).\n", table, idx);
  	return -3;
  	//return ELF_RELOC_ERR;
  }
 
  /* symaddr points to the actual section, while symtab is section hader */
  char *symaddr = (char *)hdr + symtab->sh_offset;
  Elf64_Sym *symbol = &((Elf64_Sym *)symaddr)[idx];

  Elf64_Shdr *strtab = elf64_section(hdr, symtab->sh_link);
  const char *name = NULL;
  if(symbol->st_name != 0)
  {
    name = (const char *)hdr + strtab->sh_offset + symbol->st_name;
    strcpy(out->name, name);
  } else
    strcpy(out->name, "");
    //out->name = NULL;
  if( (symbol->st_shndx != SHN_ABS) && (symbol->st_shndx != SHN_COMMON) && 
      (symbol->st_shndx != SHN_UNDEF) )
  {
    Elf64_Shdr *symbol_section = elf64_section(hdr, symbol->st_shndx);
    //printf("symbol %s is defined in section #%d\n", out->name, symbol->st_shndx);
    out->abs_offset = symbol_section->sh_offset + symbol->st_value;
    //out->abs_offset = elf_section(hdr, symbol->st_shndx)->sh_offset + symbol->st_value;
    //out->abs_offset =  symbol->st_value;
  }
  out->base = symbol;
  out->ndx = idx;
  out->symtab_sh_ndx = table;
  out->value = symbol->st_value;
  return 0;
 
}



/*
  Given a caller and a callee names, find relocation offset from the filestart

 1) reloction_section (@param reltab)
      /      \
     /        \
    v          v
   sh_link    sh_info
      =           =
symbol_table    section where to patch

  2) reloc_entry (@param rel)
      |
      --- symbol index
      |
      --- patch offset from the section start

*/
static int get_reloc_offset_by_name(Elf32_Ehdr *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab, char *target_funcname, char *probe_funcname) 
{

  Elf32_Shdr *target_secheader = elf_section(hdr, reltab->sh_info);
  Elf32_Shdr *symbol_secheader = elf_section(hdr, reltab->sh_link);
  
  char *target_sec = (char *)hdr + target_secheader->sh_offset;
  char *symbol_sec = (char *)hdr + target_secheader->sh_offset;
  
  char *ref = target_sec + rel->r_offset;
  int patch_fileoffset = target_secheader->sh_offset + rel->r_offset;
  
  Elf32_simple_symbol symbol; /* The symbol that should go in place of relocation target */
  Elf32_simple_symbol caller;
  
  if(elf_get_symbol(hdr,  reltab->sh_link, ELF32_R_SYM(rel->r_info), &symbol))
  {
    printf("%s(): could not find symbol for relocation (bug?)\n", __func__);
    exit(0);
  }
  
  //printf("target_address(file offset)=0x%x; symbol_name=%s %s\n", 
  int ret = 0;
  /* Consider only relocations for imported symbols */
  if(symbol.base->st_shndx == SHN_UNDEF)
  {
  //  printf("reloc_fileoffset=0x%x; symbol_name=%s symbol_size=0x%x type=%d  %s\n", 
  //                   patch_fileoffset, symbol.name, symbol.base->st_size, 
  //                    ELF32_ST_TYPE(symbol.base->st_info),
  //		   (symbol.base->st_shndx == SHN_UNDEF) ? "UNDEF" : "");
  
     if(!get_reloc_caller(hdr, patch_fileoffset, &caller))
     {
       if(!strcmp(caller.name, probe_funcname) && !strcmp(symbol.name, target_funcname))
       {
         printf("%s+0x%x/0x%x -> %s\n", caller.name, 
                            patch_fileoffset-caller.abs_offset,
  			  caller.base->st_size, symbol.name);
         return patch_fileoffset;
       }
     }
     
  }
  return 0;
}


/*
 1) reloction_section (@param reltab)
      /      \
     /        \
    v          v
   sh_link    sh_info
      =           =
symbol_table    section where to patch

  2) reloc_entry (@param rel)
      |
      --- symbol index
      |
      --- patch offset from the section start

*/
static int elf_print_reloc(Elf32_Ehdr *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab) 
{

	Elf32_Shdr *target_secheader = elf_section(hdr, reltab->sh_info);
	Elf32_Shdr *symbol_secheader = elf_section(hdr, reltab->sh_link);

	char *target_sec = (char *)hdr + target_secheader->sh_offset;
	char *symbol_sec = (char *)hdr + target_secheader->sh_offset;

	char *ref = target_sec + rel->r_offset;
	int patch_fileoffset = target_secheader->sh_offset + rel->r_offset;

	Elf32_simple_symbol symbol; /* The symbol that should go in place of relocation target */
	Elf32_simple_symbol caller;

	if(elf_get_symbol(hdr,  reltab->sh_link, ELF32_R_SYM(rel->r_info), &symbol))
	{
	  printf("%s(): could not find symbol for relocation (bug?)\n", __func__);
	  exit(0);
	}

	//printf("target_address(file offset)=0x%x; symbol_name=%s %s\n", 
	int ret = 0;
	/* Consider only relocations for imported symbols */
	if(symbol.base->st_shndx == SHN_UNDEF)
	{
	//  printf("reloc_fileoffset=0x%x; symbol_name=%s symbol_size=0x%x type=%d  %s\n", 
	//                   patch_fileoffset, symbol.name, symbol.base->st_size, 
        //                    ELF32_ST_TYPE(symbol.base->st_info),
	//		   (symbol.base->st_shndx == SHN_UNDEF) ? "UNDEF" : "");

           if(!get_reloc_caller(hdr, patch_fileoffset, &caller))
	   {
	     printf("%s+0x%x/0x%x -> %s\n", caller.name, 
	                          patch_fileoffset-caller.abs_offset,
				  caller.base->st_size, symbol.name);
           }
	   
	}
	return 0;

}

/*
 1) reloction_section (@param reltab)
      /      \
     /        \
    v          v
   sh_link    sh_info
      =           =
symbol_table    section where to patch

  2) reloc_entry (@param rel)
      |
      --- symbol index
      |
      --- patch offset from the section start

*/
static int elf64_print_reloc(Elf64_Ehdr *hdr, Elf64_Rel *rel, Elf64_Shdr *reltab) 
{

	Elf64_Shdr *target_secheader = elf64_section(hdr, reltab->sh_info);
	Elf64_Shdr *symbol_secheader = elf64_section(hdr, reltab->sh_link);

	char *target_sec = (char *)hdr + target_secheader->sh_offset;
	char *symbol_sec = (char *)hdr + target_secheader->sh_offset;

	char *ref = target_sec + rel->r_offset;
	int patch_fileoffset = target_secheader->sh_offset + rel->r_offset;

	Elf64_simple_symbol symbol; /* The symbol that should go in place of relocation target */
	Elf64_simple_symbol caller;

	if(elf64_get_symbol(hdr,  reltab->sh_link, ELF64_R_SYM(rel->r_info), &symbol))
	{
	  printf("%s(): could not find symbol for relocation (bug?)\n", __func__);
	  exit(0);
	}

	//printf("target_address(file offset)=0x%x; symbol_name=%s %s\n", 
	int ret = 0;
	/* Consider only relocations for imported symbols */
	if(symbol.base->st_shndx == SHN_UNDEF)
	{
	//  printf("reloc_fileoffset=0x%x; symbol_name=%s symbol_size=0x%x type=%d  %s\n", 
	//                   patch_fileoffset, symbol.name, symbol.base->st_size, 
        //                    ELF32_ST_TYPE(symbol.base->st_info),
	//		   (symbol.base->st_shndx == SHN_UNDEF) ? "UNDEF" : "");

           if(!get_reloc64_caller(hdr, patch_fileoffset, &caller))
	   {
	     printf("%s+0x%x/0x%lx -> %s\n", caller.name, 
	                          patch_fileoffset-caller.abs_offset,
				  caller.base->st_size, symbol.name);
           }
	   
	}
	return 0;

}

/* Get offset (from file Image start, i.e. from ELF file header) for a relocation target 
  
 1) reloction_section (@param relttab)
      /      \
     /        \
    v          v
   sh_link    sh_info
      =           =
symbol_table    section where to patch

  2) reloc_entry (@param rel)
      |
      --- symbol index
      |
      --- patch offset from the section start

*/
uint32_t get_reloc_target_offset(Elf32_Ehdr *hdr, Elf32_Rel *rel, Elf32_Shdr *reltab) {

	Elf32_Shdr *target_secheader = elf_section(hdr, reltab->sh_info);
	/*
	Elf32_Shdr *symbol_secheader = elf_section(hdr, reltab->sh_link);
	*/

        /*
	char *target_sec = (char *)hdr + target_secheader->sh_offset;
	char *symbol_sec = (char *)hdr + target_secheader->sh_offset;
	char *ref = target_sec + rel->r_offset;
	*/

        /* Note that 'secheader->sh_offset' is Offset of the section in the file image,
	  thus target_offset is going to be the patch offset from the file Image start */
	int target_offset = target_secheader->sh_offset + rel->r_offset;
        // Symbol value

        /*
	Elf32_simple_symbol symbol;
	elf_get_symbol(hdr,  reltab->sh_link, ELF32_R_SYM(rel->r_info), &symbol);
	*/
        
	//printf("path_address=0x%x; symbol_name=%s\n",target_offset, symbol.name);
	return target_offset;
}

int rewrite_call_instruction(Elf32_Ehdr *hdr, char *target_funcname, char *probe_funcname)
{
  Elf32_simple_symbol probe_func;
  Elf32_simple_symbol target_func;
  if(!find_symbol_by_name(hdr, probe_funcname, &probe_func))
  {
    printf("[!] error: could not find probe function in the module. Aborting\n");
    exit(1);
  }
  if(!find_symbol_by_name(hdr, target_funcname, &target_func))
  {
    printf("[!] error: could not find target function in the module. Aborting\n");
    exit(1);
  }

  /* Itereate over relocation entries */
  Elf32_Shdr *shdr = elf_sheader(hdr);
 
  unsigned int i, idx;
  int offset = 0; /* Patch relocation target offset from the file start */
  Elf32_Rel *rel_entry;
  // Iterate over section headers
  for(i = 0; i < hdr->e_shnum; i++) 
  { /* 1 */
    Elf32_Shdr *section = &shdr[i];
    // If this is a relocation section
    if(section->sh_type == SHT_REL) 
    { /* 2 */
      // Process each entry in the table
      for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) 
      { /* 3 */
        rel_entry = &((Elf32_Rel *)((char *)hdr + section->sh_offset))[idx];
        offset = get_reloc_offset_by_name(hdr, rel_entry, section, target_funcname, probe_funcname); 
        if(offset)
	  break;
      } /* 3 */
      if(offset)
        break;
    } /* 2 */
  } /* 1 */
  //printf("offset = 0x%x\n", offset);

  /* No need to relocate anymore, so let's change relocation entry type to R_ARM_NONE which will be igonred by the kernel linker */
  /* Type is encoded in the least significant byte */
  rel_entry->r_info = rel_entry->r_info & 0xff00;

  /* And now change the instructions */ 
  char *p = (char *)hdr;
  printf("offset = 0x%x\n", offset);
  printf("%hhx%hhx%hhx%hhx\n", *(p+offset), *(p+offset+1), *(p+offset+2), *(p+offset+3));
  if(offset == 0)
    return -1;

  disass(p+offset, 4, offset-48); /* Minus header size */

  // rasm2 -a arm -b 32 'mov r0, #0' => 0000a0e3
  *((uint32_t *)(p+offset)) = 0xe3a00000;
  // e28dd04c        add     sp, sp, #76     ; 0x4c
  *((uint32_t *)(p+offset+4)) = 0xe28dd04c;
  // e8bd8ff0        pop     {r4, r5, r6, r7, r8, r9, sl, fp, pc}
  *((uint32_t *)(p+offset+8)) = 0xe8bd8ff0;
  //Patch with ret wich is 'bx lr': rasm2 -a arm -b 32 'bx lr' => 1eff2fe1
  *((uint32_t *)(p+offset+12)) = 0xe12fff1e;

  disass(p+offset, 4, offset-48); /* Minus header size */
  printf("[+] Patched!\n");
  
  return 0;

}

int binary_rewrite_call(char *module_filename, char *target_funcname, char *probe_funcname)
{
  int fd, ret;
  size_t len_file, len;
  struct stat st;
  char *addr;

  if((fd = open(module_filename, O_RDWR)) < 0)
  {
      perror("Error in file opening");
      return EXIT_FAILURE;
  }

  if ((ret = fstat(fd,&st)) < 0)
  {
      perror("Error in fstat");
      return EXIT_FAILURE;
  }

  len_file = st.st_size;

  if ((addr = mmap(NULL,len_file,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0)) == MAP_FAILED)
  {
      perror("Error in mmap");
      return EXIT_FAILURE;
  }

  if(addr[4] == 0x02)
  {
    printf("error: ELF64 is not supported yet\n");
    exit(0);
  }

  Elf32_Ehdr *hdr = (Elf32_Ehdr *)addr;
  rewrite_call_instruction(hdr, target_funcname, probe_funcname);
  
  //print_sections(hdr);
  close(fd);
  
}


static int print_relocs(char *elf_filename) {


  Elf32_Ehdr header;
  int fd, ret;
  size_t len_file, len;
  struct stat st;
  char *addr;
  uint8_t ei_class; /* either 32bit ELF or 64bit ELF */

  if((fd = open(elf_filename, O_RDWR)) < 0)
  {
      perror("Error in file opening");
      return EXIT_FAILURE;
  }

  if ((ret = fstat(fd,&st)) < 0)
  {
      perror("Error in fstat");
      return EXIT_FAILURE;
  }

  len_file = st.st_size;

  /*len_file having the total length of the file(fd).*/
  if ((addr = mmap(NULL,len_file,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0)) == MAP_FAILED)
  {
      perror("Error in mmap");
      return EXIT_FAILURE;
  }

  /* Sanity check */
  ei_class = addr[4];
  if(ei_class == 0x01) /* 32bits  start */
  {

    Elf32_Ehdr *hdr = (Elf32_Ehdr *)addr;
    Elf32_Shdr *shdr = elf_sheader(hdr);
 
    unsigned int i, idx;
    // Iterate over section headers
    for(i = 0; i < hdr->e_shnum; i++) 
    {
      Elf32_Shdr *section = &shdr[i];
      // If this is a relocation section


      if(section->sh_type == SHT_REL) {
        // Process each entry in the table
        for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
          Elf32_Rel *rel_entry = &((Elf32_Rel *)((char *)hdr + section->sh_offset))[idx];
          int result = elf_print_reloc(hdr, rel_entry, section);
          // On error, display a message and return
          if(result == ELF_RELOC_ERR) {
            ERROR("Failed to relocate symbol.\n");
            return ELF_RELOC_ERR;
          }
        } /* iterate over each reloaction entry */
      } /* if section is of type REL */

      if(section->sh_type == SHT_RELA) {
        // Process each entry in the table
        for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
          Elf32_Rela *rel_entry = &((Elf32_Rela *)((char *)hdr + section->sh_offset))[idx];
	  /* addend field comes at the end so rel_entry should be compatible with Elf64_rel */
          int result = elf_print_reloc(hdr, (Elf32_Rel *)rel_entry, section);
          // On error, display a message and return
          if(result == ELF_RELOC_ERR) {
            ERROR("Failed to relocate symbol.\n");
            return ELF_RELOC_ERR;
          }
        } /* iterate over each reloaction entry */
      } /* if section is of type REL */



    } /* iterate over section headers */
  } /*32 bit end */
  else if(ei_class == 0x02) /* 64bits  start */  
  {
    Elf64_Ehdr *hdr = (Elf64_Ehdr *)addr;
    Elf64_Shdr *shdr = elf64_sheader(hdr);
    //printf("EFL64, number of sec heades =  %d\n", hdr->e_shnum);
 
    unsigned int i, idx;
    // Iterate over section headers
    for(i = 0; i < hdr->e_shnum; i++) 
    {
      Elf64_Shdr *section = &shdr[i];
      // If this is a relocation section



      if( section->sh_type == SHT_REL ) {
        //printf("relocation section\n");
        // Process each entry in the table
        for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
          Elf64_Rel *rel_entry = &((Elf64_Rel *)((char *)hdr + section->sh_offset))[idx];
          int result = elf64_print_reloc(hdr, rel_entry, section);
          // On error, display a message and return
          if(result == ELF_RELOC_ERR) {
            ERROR("Failed to relocate symbol.\n");
            return ELF_RELOC_ERR;
          }
        } /* iterate over each reloaction entry */
      } /* if section is of type REL */


      if( section->sh_type == SHT_RELA ) {
        //printf("relocation section\n");
        // Process each entry in the table
        for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
          Elf64_Rela *rel_entry = &((Elf64_Rela *)((char *)hdr + section->sh_offset))[idx];
	  /* addend field comes at the end so rel_entry should be compatible with Elf64_rel */
          int result = elf64_print_reloc(hdr, (Elf64_Rel *)rel_entry, section);
          // On error, display a message and return
          if(result == ELF_RELOC_ERR) {
            ERROR("Failed to relocate symbol.\n");
            return ELF_RELOC_ERR;
          }
        } /* iterate over each reloaction entry */
      } /* if section is of type REL */




    } /* iterate over section headers */

  } /*64 bit end */
  return 0;
}

//static int
//Elf32_Rel *find_reloc_by_target_offset(Elf32_Ehdr *hdr, uint32_t offset) {

/* Compare offset of the patch target with offset from each relocation entry.
 * If there is a match, return the corresponding reloc entry in <out>.
 *
 * @param offset Is the offset from the file Image start, where the relocation target. 
*/
int find_reloc_by_target_offset(Elf32_Ehdr *hdr, uint32_t offset, Elf32_simple_reloc *out) {
  Elf32_Shdr *shdr = elf_sheader(hdr);
  
  unsigned int i, idx;
  // Iterate over section headers
  for(i = 0; i < hdr->e_shnum; i++) 
  {
    Elf32_Shdr *section = &shdr[i];
    // If this is a relocation section
    if(section->sh_type == SHT_REL) {

      // Process each entry in the table
      for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
        /* Note that 'section->sh_offset' is Offset of the section in the file image */
        Elf32_Rel *reltab_entry = &((Elf32_Rel *)((char *)hdr + section->sh_offset))[idx];
	/* get offset of the patch location from file Image start */
        uint32_t target_offset = get_reloc_target_offset(hdr, reltab_entry, section);
	if(offset == target_offset)
	{
	  out->base = reltab_entry;  

	  //Elf32_simple_symbol *symbol = malloc(sizeof(Elf32_simple_symbol));
	  elf_get_symbol(hdr,  section->sh_link, ELF32_R_SYM(reltab_entry->r_info), &out->symbol);
	  out->reltab_sh_ndx = i;
	  out->abs_offset = target_offset;
	  out->base = reltab_entry;
	  //out->symbol = 
	  return 0;
	}
        // On error, display a message and return
       // if(result == ELF_RELOC_ERR) {
       //   ERROR("Failed to relocate symbol.\n");
       //   return ELF_RELOC_ERR;
       // }
      }
    }
  }
  return -1;
}


/* @param offset is the offset of a relocation target from the file Image start
   return 0 if symbol is found */
int get_reloc_caller(Elf32_Ehdr *hdr, unsigned int offset, Elf32_simple_symbol *symbol)
{
  Elf32_Shdr *shdr = elf_sheader(hdr);
  //Elf32_simple_symbol symbol;
  unsigned int sec_num, idx;
  int ret = 0;

  // Iterate over section headers
  for(sec_num = 0; sec_num < hdr->e_shnum; sec_num++) 
  {
    Elf32_Shdr *section = &shdr[sec_num];
    // If this is a symbol table section
    if(section->sh_type == SHT_SYMTAB) {

      // Process each entry in the table, symbol with idx 0 is always undefined
      for(idx = 1; idx < section->sh_size / section->sh_entsize; idx++) {
	ret = elf_get_symbol(hdr, sec_num, idx, symbol);
	if(!ret && symbol->base && ELF32_ST_TYPE(symbol->base->st_info) == STT_FUNC)
	{
	  if( (offset >= symbol->abs_offset) && 
	      (offset < (symbol->abs_offset+symbol->base->st_size)) )
	  {
	    //printf("Found func '%s': [0x%x-0x%x] in the file\n", 
	    //      symbol->name, symbol->abs_offset, symbol->abs_offset+symbol->base->st_size);
            return 0;
          }
	  //  printf("Found func '%s': [0x%x-0x%x] in the file\n", 
	  //        symbol->name, symbol->abs_offset, symbol->abs_offset+symbol->base->st_size);
	  
	}
	//printf("Found symbol '%s' at offset 0x%x from the file start\n", symbol.name, symbol.abs_offset);
	//printf("%d\n", idx);
      }
    }
  }
  //exit(0);
  return -1;

}

/* @param offset is the offset of a relocation target from the file Image start
   return 0 if symbol is found */
int get_reloc64_caller(Elf64_Ehdr *hdr, unsigned int offset, Elf64_simple_symbol *symbol)
{
  Elf64_Shdr *shdr = elf64_sheader(hdr);
  //Elf32_simple_symbol symbol;
  unsigned int sec_num, idx;
  int ret = 0;

  // Iterate over section headers
  for(sec_num = 0; sec_num < hdr->e_shnum; sec_num++) 
  {
    Elf64_Shdr *section = &shdr[sec_num];
    // If this is a symbol table section
    if(section->sh_type == SHT_SYMTAB) {

      // Process each entry in the table, symbol with idx 0 is always undefined
      for(idx = 1; idx < section->sh_size / section->sh_entsize; idx++) {
	ret = elf64_get_symbol(hdr, sec_num, idx, symbol);
	if(!ret && symbol->base && ELF64_ST_TYPE(symbol->base->st_info) == STT_FUNC)
	{
	  if( (offset >= symbol->abs_offset) && 
	      (offset < (symbol->abs_offset+symbol->base->st_size)) )
	  {
	    //printf("Found func '%s': [0x%x-0x%x] in the file\n", 
	    //      symbol->name, symbol->abs_offset, symbol->abs_offset+symbol->base->st_size);
            return 0;
          }
	  //  printf("Found func '%s': [0x%x-0x%x] in the file\n", 
	  //        symbol->name, symbol->abs_offset, symbol->abs_offset+symbol->base->st_size);
	  
	}
	//printf("Found symbol '%s' at offset 0x%x from the file start\n", symbol.name, symbol.abs_offset);
	//printf("%d\n", idx);
      }
    }
  }
  //exit(0);
  return -1;

}

int find_symbol_by_name(Elf32_Ehdr *hdr, const char* name, Elf32_simple_symbol *symbol)
{
  Elf32_Shdr *shdr = elf_sheader(hdr);
  
  unsigned int sec_num, idx;
  // Iterate over section headers
  for(sec_num = 0; sec_num < hdr->e_shnum; sec_num++) 
  {
    Elf32_Shdr *section = &shdr[sec_num];
    // If this is a symbol table section
    if(section->sh_type == SHT_SYMTAB) {

      // Process each entry in the table
      for(idx = 0; idx < section->sh_size / section->sh_entsize; idx++) {
	elf_get_symbol(hdr, sec_num, idx, symbol);
	if((strlen(symbol->name)!=0) && (strcmp(name,symbol->name)==0))
	{
	  //printf("Found symbol '%s' at offset 0x%x from the file start\n", symbol->name, symbol->abs_offset);
	  //printf("%d\n", idx);
          return 1;
	}
      }
    }
  }
  return 0;

}

/* The call instruction is in function <func_name> at offset <offset> */
int patch_reloc_for_call_instruction(Elf32_Ehdr *hdr, const char *func_name, uint32_t offset, const char *stub_name)
{
  Elf32_simple_symbol func;
  //find_symbol_by_name(hdr, "res_trk_check_for_sec_session", &func);
  if(!find_symbol_by_name(hdr, func_name, &func))
  {
    printf("[!] error: could not find requested function in the module. Aborting\n");
    exit(1);
  }
  //printf("[+] Found target function '%s' at offset 0x%x from the file start (defined in section #%d at index %d, value=0x%x)\n", 
  //        func.name, func.abs_offset, func.symtab_sh_ndx, func.ndx, func.value);
  
  Elf32_simple_symbol func1;
  if(stub_name)
  {
    if(!find_symbol_by_name(hdr, stub_name, &func1))
    {
      printf("[!] error: could not find '%s' symobl in the module (type '-h' to see how to inject it). Aborting\n", stub_name);
      exit(1);
    }
  } else
  {
    if(!find_symbol_by_name(hdr, "generic_stub_0", &func1))
    {
      printf("[!] error: could not find 'generic_stub' symobl in the module (type '-h' to see how to inject it). Aborting\n");
      exit(1);
    }
  }
  //printf("[+] Found '%s' symbol at offset 0x%x from the file start (defined in section #%d at index %d, value=0x%x)\n", 
  //        func1.name, func1.abs_offset, func1.symtab_sh_ndx, func1.ndx, func1.value);

  Elf32_simple_reloc reloc;
  int ret = find_reloc_by_target_offset(hdr, func.abs_offset+offset, &reloc);
  if(ret == 0)
  {
    printf("[+] Found reloc target at offset 0x%x (entry in reltab #%d)\n"
           "    original relocation is for symbol %s\n"
	   "    r_info = %x, ELF32_R_SYM(r_info) = %x\n",
	                                        func.abs_offset+offset,
                                                reloc.reltab_sh_ndx,
	                                        reloc.symbol.name, 
						reloc.base->r_info,
						ELF32_R_SYM(reloc.base->r_info));
  }
  else
  {
    printf("[-] Cound not find relocation entry for the provided func+offset. Aborting\n");
    return -1;
  }


  /* This is just for debugging: to make sure that the original relocation
   * points to a valid symbol */
  /*
  Elf32_simple_symbol func2;
  find_symbol_by_name(hdr, reloc.symbol.name, &func2);
  printf("[+] Found function '%s' at offset 0x%x from the file start (defined in section #%d at index %d, value=0x%x)\n", 
          func2.name, func2.abs_offset, func2.symtab_sh_ndx, func2.ndx, func2.value);
  */
  
  //char *c = (char *)&reloc.base->r_info;
  //for(int i=0; i<4; i++)
  //{
  //  printf("%hhx", *c);
  //  c++;
  //}
  //patch_reloc_entry(reloc)
  //printf("\n%lu\n", sizeof(Elf32_Word));
  //printf("%lu\n", sizeof(Elf32_Addr));
 
  //printf("%x\n", (func1.ndx << 8) + ELF32_R_TYPE(reloc.base->r_info));
  
  printf("[+] Patching\n");
  uint32_t *l = (uint32_t *)&reloc.base->r_info;
  *l = (func1.ndx << 8) + ELF32_R_TYPE(reloc.base->r_info);
  return 0;
}


/* Modify a relocation entry for a call instruction with generic stub. The modification is
 * done inplace.
 *
 * @param filename Path to the relocatable object (ELF) file to patch (e.g. a kernel module)
 * @param funcname The name of the function that contains the corresponding call instruction
 * @param offset   The offset of the call instruction from the beginning of the function
 *
*/
int patch_module(const char* filename, const char *funcname, uint32_t offset, const char *stub_name) {
  // switch to Elf32_Ehdr for x86 architecture.
  Elf32_Ehdr header;
  int fd, ret;
  size_t len_file, len;
  struct stat st;
  char *addr;


  //if((fd = open(filename,O_RDWR | O_CREAT, FILEMODE)) < 0)
  if((fd = open(filename, O_RDWR)) < 0)
  {
      perror("Error in file opening");
      return EXIT_FAILURE;
  }

  if ((ret = fstat(fd,&st)) < 0)
  {
      perror("Error in fstat");
      return EXIT_FAILURE;
  }

  len_file = st.st_size;

  /*len_file having the total length of the file(fd).*/

  if ((addr = mmap(NULL,len_file,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0)) == MAP_FAILED)
  {
      perror("Error in mmap");
      return EXIT_FAILURE;
  }

  if(addr[4] == 0x02)
  {
    printf("error: ELF64 is not supported yet\n");
    exit(0);
  }

  Elf32_Ehdr *hdr = (Elf32_Ehdr *)addr;
  
  //print_sections(hdr);
  //print_relocs(hdr);
  //find_symbol(hdr, "res_trk_check_for_sec_session");
  //patch_reloc_for_call_instruction(hdr, "res_trk_check_for_sec_session", 0x14-4);
  patch_reloc_for_call_instruction(hdr, funcname, offset, stub_name);
  close(fd);
}

int print_help()
{
  printf("patcher -- (Inplace) Patch module's relocation entry\n\n"
         "Usage: patcher MODULE.ko CRASHINGFUNC OFFSET_HEX [STUB_NAME]\n\n"
         "Given a function name and the offset from the start of the function,\n"
	 "patcher tries to find the relocation entry that targest that location.\n"
	 "If found it replaces the relocation's symbol to 'generic_stub' symbol.\n"
	 "Note that 'generic_stub' symbol should be present in the module. You can inject\n"
	 "a symbol by compiling and linking the following code with the module: \n\n"

         " int generic_stub();\n"
         " \n"
         " int randomfunction()\n"
         " {\n"
         "   generic_stub();\n"
         " }\n"

	 "\n And then compile with:\n"
	 
         "$ arm-eabi-gcc -fno-short-enums -c inject.c\n"
         "$ arm-eabi-ld -r inject.o ../vidc.ko -o vidc-injected.ko\n\n"
	 "Example:\n"
	 "$ patcher vidc-injected.ko res_trk_check_for_sec_session 0x10 generic_stub_1\n\n");
  printf("     Note that the offset provided by dmesg or\n"
	 "     __builtin_return_address show the next instruction, so you\n"
	 "     actually need to provide the offset from dmesg minus 4\n");
}

int main(int argc, char **argv)
{
  /* Print help and exit */
  if (argc == 2 && strcmp(argv[1], "-h") == 0)
  {
    print_help();
    exit(0);
  }

  /* Print relocation and return */
  if (argc == 3 && strcmp(argv[1], "-p") == 0)
  {
    print_relocs(argv[2]);
    return 0;
  }

  /* Print relocation and return */
  if (argc == 5 && strcmp(argv[1], "-w") == 0)
  {
    /* agrgs are as follows: module_filename target_funcname probe_funcname */
    binary_rewrite_call(argv[2], argv[3], argv[4]);
    return 0;
  }

  if ( (argc != 4) && (argc != 5))
  {
    printf("error: wrong number of arguments\n\n");
    printf("Usage: patcher MODULE.ko CRASHINGFUNC OFFSET_HEX [STUB_NAME]\n");
    printf("       patcher -p MODULE.ko\n\n");
    printf("       patcher -w MODULE.ko FUNC_NAME PROBFUNC_NAME\n\n");
    printf("       type 'patcher -w' rewrite call instruction with return instruction inside probe function\n\n");
    printf("       type 'patcher -p' to print relocations\n\n");
    printf("       type 'patcher -h' for more help\n\n");
    printf("       Note that the offset provided by dmesg or\n"
		   "__builtin_return_address show the next instruction, so you\n"
		   "actually need to provide the offset from dmesg minus 4\n");
    exit(0);
  }
  char *module_filename = argv[1];
  char *crashing_func_name = argv[2];
  unsigned long int crashing_offset = strtoul(argv[3], NULL, 16);
  char *stub_name = NULL;
 
  if(argc == 5)
    stub_name = argv[4];

  /* Note that the offset provided by dmesg shows the next instruction, so you actually
     need to provide offset from dmesg minus 4 */
  patch_module(module_filename, crashing_func_name, crashing_offset, stub_name);
  //parse_elf32(elf_filename);
  return 0;
}

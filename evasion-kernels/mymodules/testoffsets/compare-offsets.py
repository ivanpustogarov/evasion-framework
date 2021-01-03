#! /usr/bin/python

from unicorn import *
from unicorn.arm_const import *
import os
from capstone import *
import sys
import argparse

try:
    from elftools.elf.elffile import ELFFile
except:
    print('elftools needed! try: pip install pyelftools')
    sys.exit(1)

OFFSETS1_PATH = "./offsets1.txt"  # Xiaomi config
OFFSETS2_PATH = "./offsets2.txt"  # Alien config
token2config_struct_file = {86: "CONFIG_SECURITY"}

PAGE_SIZE = 0x1000
PAGE_MASK = 0xfffffffffffff000
CODE_START = 0
STACK_TOP = 0x10000000+8192
STACK_SIZE = 1024


def PAGE_ALIGNED(sz):
    if sz != 0:
        return (((sz-1) & PAGE_MASK) + PAGE_SIZE)
    else:
        return 0


def PAGE_START(addr):
    return (addr & PAGE_MASK)

# Filter out lines that start with '>'


def filter_comments(line):
    if line[0] == '>':
        return False
    else:
        return True


def read_offsets(filename):
    with open(filename) as f:
        offsets = f.readlines()
    # remove traling '\n'
    offsets = [x.strip() for x in offsets]
    offsets = filter(filter_comments, offsets)
    return offsets


def convert_to_dict(offsets):
    ret = dict()
    for line in offsets:
        (token, offset) = line.split()
        ret[int(token)] = offset
    return ret

# @param offsets List of pairs (token,offset)
# @type list


def get_tokens(offsets):
    proj = [x for (x, y) in offsets]
    tokens = set(proj)
    return tokens

# offsets1/2 is a list of pairs (token,offset)


def compare_tokens(offsets1, offsets2):
    tokens1 = get_tokens(offsets1)
    tokens2 = get_tokens(offsets2)
    missing_tokens = tokens1-tokens2  # should add to alien kernel
    print("You should add the following tokens to the alien kernel config: {}".format(
        missing_tokens))
    print("Here is the list of known config options:")
    for token in missing_tokens:
        #if(token2config_struct_file.has_key(token)):
        if token in token2config_struct_file:
            print("{} -> {}".format(token, token2config_struct_file[token]))
    # should be removed from vanilla kernel (i.e. they add more offset then necessary)
    excess_tokens = tokens2-tokens1
    print("You should remove the following tokens from the alien kernel config: {}".format(
        excess_tokens))
    print("Here is the list of known config options:")
    for token in excess_tokens:
        if token in token2config_struct_file:
            print("{} -> {}".format(token, token2config_struct_file[token]))

    if(len(missing_tokens) != 0 or len(excess_tokens) != 0):
        return 1
    else:
        return 0

# offest is a list of pairs (token, offset)
# Note that at this stage offset1 and offsets2 should have the same tokens


def compare_pairwise_differences(offsets1, offsets2):
    for i in range(len(offsets1)-1):
        off1_cur = offsets1[i][1]
        off1_next = offsets1[i+1][1]
        diff1 = off1_next - off1_cur

        off2_cur = offsets2[i][1]
        off2_next = offsets2[i+1][1]
        diff2 = off2_next - off2_cur

        if(diff1 != diff2):
            print("There is a mismatch betwen tokens {} and {}",
                  offsets1[i][0], offsets1[i+1][0])
            return 1

    return 0


# offsets : (token, offset)
def compare_offsets(offsets1, offsets2):

    ret = compare_tokens(offsets1, offsets2)
    if(ret != 0):
        print("[-] Not comparing pairswise differences, fix tokens first")
        return 1
    else:
        print("[+] Tokens match")

    # at this stage the tokens are the same, they are also sorted by offset
    ret = compare_pairwise_differences(offsets1, offsets2)
    if(ret != 0):
        print("[-] Pairwise differences do not match")
        return 1
    else:
        print("[+] Pairwise differences match")
        return 0

# https://github.com/kudelskisecurity/sgxfun/blob/master/parse_enclave.py


def find_symbol(elffile, symname):
    t_section = None
    t_vaddr = None
    #elf = ELFFile(open("testoffsets.ko", 'rb'))
    elf = ELFFile(open(elffile, 'rb'))
    # find the symbols table(s)
    for section in elf.iter_sections():
        # print section.name
        # and (section.name == ".text"):
        if (section.header['sh_type'] == 'SHT_SYMTAB'):
            for symbol in section.iter_symbols():
                if symbol.name == symname:
                    t_vaddr = symbol.entry['st_value']
                    t_size = symbol.entry['st_size']
                    t_section = symbol.entry['st_shndx']
                    symbol_section = elf.get_section(t_section)
                    file_offset = symbol_section.header['sh_offset']
                    #print("Found symbol '{}'; t_vaddr={} with t_size={}; sh_offset={}".format(symname, hex(t_vaddr), t_size, file_offset))
                    return (t_vaddr+file_offset, t_size)
                    break
            break


def read_file(filename):
    f = open(filename, "rb")
    content = f.read()
    f.close()
    return content


count = 0


def hook_code(uc, address, size, offsets):
    global count
    #print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    #print("count = {}".format(count))
    #count += 1
    # if count >= 10:
    #  exit(0)

    inst = uc.mem_read(address, size)

    #md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    # for i in md.disasm(inst, size):
    #    print("0x%x:\t%s\t%s" %(address-0x34, i.mnemonic, i.op_str))

    inst = uc.mem_read(address, size)
    # rasm2 -a arm -b32 'bl 0' --> feffffeb
    if(inst[0] == 0xfe and inst[1] == 0xff and inst[2] == 0xff and inst[3] == 0xeb):
        r_pc = uc.reg_read(UC_ARM_REG_PC)
        r_pc += 4
        uc.reg_write(UC_ARM_REG_PC, r_pc)
        r0 = uc.reg_read(UC_ARM_REG_R0)  # offset
        r1 = uc.reg_read(UC_ARM_REG_R1)  # token
        offsets.append((r1, r0))

        # return True


def emulate(elffile, func_start, func_end):
    offsets = list()
    try:
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        code_size = os.stat(elffile).st_size
        code = read_file(elffile)
        #print("code_size = {}".format(code_size))
        # Memory for code starting at 0
        #print("Mapping memory to {} size {}".format(PAGE_START(CODE_START), PAGE_ALIGNED(code_size)))
        mu.mem_map(PAGE_START(CODE_START), PAGE_ALIGNED(code_size))
        #print("writing code")
        mu.mem_write(PAGE_START(CODE_START), code)
        #print("wrote code")

        # Memroy for stack
        #print("Mapping memory at {} size {}".format(PAGE_START(STACK_TOP), PAGE_ALIGNED(STACK_SIZE)))
        mu.mem_map(PAGE_START(STACK_TOP), PAGE_ALIGNED(STACK_SIZE))
        # print("Mapped")

        # Set stack pointer
        stack_bottom = STACK_TOP+STACK_SIZE
        mu.reg_write(UC_ARM_REG_R13, stack_bottom)

        # tracing one instruction at ADDRESS with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=func_start,
                    end=func_end, user_data=offsets)

        # print("starting!")
        mu.emu_start(func_start, func_end)

        r_pc = mu.reg_read(UC_ARM_REG_PC)
        #print(">>> PC = 0x%x" % (r_pc-0x34))

    except UcError as e:
        print("ERROR: %s" % e)
        exit(0)
    return offsets


def print_offsets(offsets1, offsets2):
    N = max(len(offsets1), len(offsets2))
    for i in range(N):
        if(i < len(offsets1)):
            sys.stdout.write(
                "t:{}->o:{}".format(offsets1[i][0], offsets1[i][1]))
        if(i < len(offsets2)):
            sys.stdout.write(
                "\tt:{}->o:{}".format(offsets2[i][0], offsets2[i][1]))
        sys.stdout.flush()
        print("")


def main(argv):
    parser = argparse.ArgumentParser(description='Find config differences.')
    parser.add_argument('-v', '--vanilla', metavar='MODULE',
                        help='Module compiled against vanilla kernel', required=True)
    parser.add_argument('-x', '--xiaomi', metavar='MODULE',
                        help='Module compiled against xiaomi kernel',  required=True)
    parser.add_argument('--dev', action='store_true',
                        help='Check file_check',  default=False)
    parser.add_argument('--file', action='store_true',
                        help='Check dev_check',  default=False)

    args = parser.parse_args(argv[1:])

    if(not args.dev and not args.file):
        print("error: you should sepcify either --dev or --file")
        print("Use -h for details")
        exit(0)

    if(args.dev and args.file):
        print("error: you should sepcify either --dev or --file but not both")
        print("Use -h for details")
        exit(0)

    if(args.file):
        func_name = "file_check"
    elif(args.dev):
        func_name = "dev_check"

    if(not os.path.exists(args.vanilla)):
        print("error: could not find file '{}'".format(args.vanilla))
        exit(0)

    if(not os.path.exists(args.xiaomi)):
        print("error: could not find file '{}'".format(args.xiaomi))
        exit(0)

    (func_offset, size) = find_symbol(args.xiaomi, func_name)
    print("[+] Emulating file_check @ {}".format(hex(func_offset)))
    offsets1 = emulate(args.xiaomi, func_offset, func_offset+size-4)

    (func_offset, size) = find_symbol(args.vanilla, func_name)
    print("[+] Emulating file_check @ {}".format(hex(func_offset)))
    offsets2 = emulate(args.vanilla, func_offset, func_offset+size-4)
    # print(offsets2)

    print("[+] Comparing offsets")
    ret = compare_offsets(offsets1, offsets2)
    if(ret != 0):
        print_offsets(offsets1, offsets2)


main(sys.argv)

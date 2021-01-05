#!/usr/bin/env python

import sys
import Queue
import struct
import itertools
import re
import logging
import argparse
import os
import operator
import threading

sys.path.append('/home/ivan/Workspaces/manticore-ivan/manticore')
from manticore import Manticore
from manticore.core.plugin import ExtendedTracer, Follower, Plugin, ExamplePlugin
from manticore.core.smtlib.constraints import ConstraintSet
from manticore.core.smtlib import Z3Solver, solver
from manticore.core.smtlib.visitors  import pretty_print as pp
from manticore.utils.helpers import issymbolic

from manticore.core.state import Concretize, TerminateState
#from .state import Concretize, TerminateState

import copy
from manticore.core.smtlib.expression import *


# Kernel space allocator (candy mountain)
def init_candy_allocator(init_state):
    base = 0x11000000;
    size = 1 << 22; # 4MB
    init_state.cpu.memory.mmap(base, size, 'rwx', name='candy_allocator')
    return 0

# Return the current value of brk, and then increase it by <size>
#candy_brk=0x11000000
#def candy_memalloc(size):
#    global candy_brk
#    prev_brk = candy_brk
#    candy_brk = candy_brk + size
#    if(candy_brk > 0x11400000):
#        printf("warning: candy allocator is out of memory (4MB)\n")
#    return prev_brk
def candy_memalloc(s, size):
    prev_brk = s.context["candy_brk"]
    s.context["candy_brk"] = s.context["candy_brk"] + size
    if(s.context["candy_brk"] > 0x11400000):
        printf("warning: candy allocator is out of memory (4MB)\n")
    return prev_brk


logger = logging.getLogger(__name__)
MAX_INSTS = 25000
class InstructionFollower(Plugin):

    #def will_execute_instruction_callback(self, state, pc, instruction):
    #    #print("will_execute_instruction {} {} {}".format(state, hex(pc), instruction))
    #    if(pc==0x8000df00):
    #        raise TerminateState("Reached 0x8000df00, terminating.", testcase=False)

    def did_execute_instruction_callback(self, state, prev_pc, target_pc, instruction):
        address = prev_pc
        if not issymbolic(address):
            count = state.context.get('instructions_count', 0)
	    if(count > MAX_INSTS):
                print "Execution reached {} instructions. Terminating".format(MAX_INSTS)
	        state.generate_testcase("sdf")
	        state.abandon()
            #if issymbolic(state.cpu.R1):
	    #    print "R1 is symbolic"
            #if issymbolic(state.cpu.R4):
	    #    print "R4 is symbolic"
            state.context['instructions_count'] = count + 1


    # Generate a solution and abandon state if we forked inside the ioctl handler 
    def did_fork_state_callback(self, child_state, expression, new_value, policy):
        #print "Forked, pc={}, new_value={}".format(hex(child_state.cpu.PC), hex(new_value))
        #print "Child fork, pc={}".format(hex(child_state.cpu.PC))
	pc = child_state.cpu.PC
        istart = child_state.context['ioctl_start_addr'] 
        iend = child_state.context['ioctl_end_addr']
        if( (pc >= istart) and (pc <= iend)):
	    x = child_state.solve_min(child_state.context['symbolic_r1'])
            with self.manticore.locked_context() as mc:
	        #x = child_state.solve_min(mc['symbolic_r1'])
	        #print "solution = {}".format(x)
		lst = mc["sols"]
		lst.append(x)
	        mc["sols"] = lst


    #def will_fork_state_callback(self, parent_state, expression, solutions, policy):
    #    #logger.info('will_fork_state %r %r %r %r', parent_state, expression, solutions, policy)
    #    #print "Parent fork, pc={}".format(hex(parent_state.cpu.PC))
    #    print "Parent fork, pc={}".format(parent_state.cpu.PC)
    #    pc = parent_state.cpu.PC
    #    istart = parent_state.context['ioctl_start_addr'] 
    #    iend = parent_state.context['ioctl_end_addr']
    #    if( (pc >= istart) and (pc <= iend)):
    #        x = parent_state.solve_min(parent_state.context['symbolic_r1'])
    #        print "solution = {}".format(x)
    #        parent_state.generate_testcase("xsd")
    #        parent_state.abandon() 


# QMP and Mantcore use slighltl different register naming convention
# This function returns a mcore register name given a qmp register name,
# e.g. 'R00' -> 'R0' or 'd08' -> 'D8'
def qmpr2mcorer(regname):
    qmp_register_names_RX = ("R00", "R01","R02","R03","R04","R05","R06","R07","R08","R09","R10","R11","R12","R13","R14","R15")
    qmp_register_names_DX = ('d00', 'd01', 'd02', 'd03', 'd04', 'd05', 'd06', 'd07', 'd08',
                         'd09', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15', 'd16',
                         'd17', 'd18', 'd19', 'd20', 'd21', 'd22', 'd23', 'd24',
                         'd25', 'd26', 'd27', 'd28', 'd29', 'd30', 'd31')
    mcore_register_names_RX = ("R0", "R1","R2","R3","R4","R5","R6","R7","R8","R9","R10","R11","R12","R13","R14","R15")
    mcore_register_names_DX = ('D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8',
                         'D9', 'D10', 'D11', 'D12', 'D13', 'D14', 'D15', 'D16',
                         'D17', 'D18', 'D19', 'D20', 'D21', 'D22', 'D23', 'D24',
                         'D25', 'D26', 'D27', 'D28', 'D29', 'D30', 'D31')
    if regname in qmp_register_names_RX:
        return mcore_register_names_RX[qmp_register_names_RX.index(regname)]
    elif regname in qmp_register_names_DX:
        return mcore_register_names_DX[qmp_register_names_DX.index(regname)]
    else:
        return None


# Read file qmp-registers.txt in the current folder and
# update Manticore registers. Note that in Manticore we dont have
# s00-s63 registers
#
# @param m Manticore instance with an initial state to be updated
# @type class Manticore
def initialize_registers(state, filename):
    #filename = "qmp-registers.txt"
    try:
        f= open(filename,"r")
    #except FileNotFoundError: # Does not exist in python2
    except OSError as e:
        if e.errno == errno.ENOENT:
            print "[-] File ", filename, " does not exist!"
	    return -1
        else:
            raise
    contents = f.read()

    # R01 -- R15
    register_names = ("R00", "R01","R02","R03","R04","R05","R06","R07","R08","R09","R10","R11","R12","R13","R14","R15")
    for regname in register_names:
        result = re.search("("+regname+")=([0-9a-f]{8})",contents)
	if result==None:
	    print "filename ", filename, " does not contains value for register ",regname,". Bug? We should abort!"
	    return -1
	mcore_regname = qmpr2mcorer(result.group(1))
	reg_value = result.group(2)
        #print "Setting ",mcore_regname," --> ",reg_value
	state.cpu.regfile.write(mcore_regname, int(reg_value, 16))

    # D01 -- R31
    register_names = ('d00', 'd01', 'd02', 'd03', 'd04', 'd05', 'd06', 'd07', 'd08',
                         'd09', 'd10', 'd11', 'd12', 'd13', 'd14', 'd15', 'd16',
                         'd17', 'd18', 'd19', 'd20', 'd21', 'd22', 'd23', 'd24',
                         'd25', 'd26', 'd27', 'd28', 'd29', 'd30', 'd31')
    for regname in register_names:
        result = re.search("("+regname+")=([0-9a-f]{16})",contents)
	if result==None:
	    print "filename ", filename, " does not contains value for register ",regname,". Bug? We should abort!"
	    return -1
	mcore_regname = qmpr2mcorer(result.group(1))
	reg_value = result.group(2)
        #print "Setting ",mcore_regname," --> ",reg_value
	state.cpu.regfile.write(mcore_regname, int(reg_value, 16))

# System.map format: '80100044 T cpu_ca8_reset'
# symbol should in the following format " T cpu_ca8_reset" (don't forget the space as the first char! check System.map for whether you need T or t)
def get_symbol_address(systemmap, symbol):
    ARM_ADDRESS_HEX_LENGTH = 8
    with open(systemmap, 'r') as content_file:
        content = content_file.read()
        s_loc = content.find(symbol)
        if s_loc == -1:
            return None
        s_addr_s = content[s_loc-ARM_ADDRESS_HEX_LENGTH:s_loc]
	#print "s_addr_s={}".format(s_addr_s)
        s_addr = int(s_addr_s, 16) # Address in System.map are in hex => base=16
	return s_addr

# We have this kind of lines:
# 7f000e00 t _ioctl_prepare_present_fence [mtk_disp_mgr]
def get_func_boundaries(systemmap, symbol):
    func_addresses = dict()
    lines = open(systemmap).read().splitlines()
    symbol_start_addr = -1
    symbol_end_addr = -1
    for line in lines: 
        tokens = line.split()
	faddr = int(tokens[0], 16)
	fname = tokens[2]
	#print "{} {}####".format(hex(addr),  fname)
	func_addresses[faddr]=fname
	if(fname == symbol):
	    symbol_start_addr = faddr
    sorted_fa = sorted(func_addresses.items(), key=operator.itemgetter(0))
    for i in range(len(sorted_fa)-1): 
        item = sorted_fa[i]
	faddr = item[0]
	if(faddr == symbol_start_addr):
	    symbol_end_addr = sorted_fa[i+1][0]
	    break
    return (symbol_start_addr, symbol_end_addr)


def main():
    parser = argparse.ArgumentParser(description='Do symbolic emulation of a memory dump and extract IOCTL cmd\'s')
    parser.add_argument('-v', '--verbose' , action='count', help='More output, -vv even more output, -vvv for lots of output')
    parser.add_argument('-m', '--memdump', help='Path to an memory dump ELF file (use dumps2elf for conversion', required=True)
    parser.add_argument('-s', '--systemmap', help='Path to System.map; used to patch printk')
    parser.add_argument('-r', '--registers', help='Path to a file with register values', required=True)
    parser.add_argument('-i', '--ioctlname', help='Ioctl handler name', required=True)
    args = parser.parse_args()

    if(not os.path.isfile(args.memdump)):
        print "error: File '{}' does not exist".format(args.memdump)
	exit(0)
    if(not os.path.isfile(args.registers)):
        print "error: File '{}' does not exist".format(args.registers)
	exit(0)

    if(args.systemmap == None):
        print "error: System.map (-s) is required (use -h for help)"
	exit(0)

    if(args.ioctlname == None):
        print "error: ioctl handler name is required (-i) is required (use -h for help)"
	exit(0)

    if(args.systemmap != None):
        if(not os.path.isfile(args.systemmap)):
            print "error: File '{}' does not exist".format(args.systemmap)
	    exit(0)
    #print "{} - {}".format(hex(istart), hex(iend))
    #exit(0)

    #print "symbex.py: systemmap={}".format(args.systemmap)
    m1 = Manticore.barebones(args.memdump, systemmap=args.systemmap, policy='uncovered')
    m1.verbosity(args.verbose)


    # Now let's read the registers
    print "[+] Reading registers"
    initialize_registers(m1.initial_state, args.registers)

    (istart, iend) = get_func_boundaries(args.systemmap, args.ioctlname)
    print "istart = {}, iend = {}".format(hex(istart),hex(iend))
    if istart==-1 or iend==-1:
        print "error: could not find ioctl handler"
	exit(0)
    if(m1.initial_state.cpu.PC != istart):
        print "error: ioctl handler address mismatch (did you provide the right func name?, pc = {})".format(hex(m1.initial_state.cpu.PC))
	exit(0)
    m1.initial_state.context['ioctl_start_addr'] = istart
    m1.initial_state.context['ioctl_end_addr'] = iend


    # NOTE: ./manticore/core/plugin.py:        state.cpu.RFLAGS = state.new_symbolic_value(state.cpu.address_bit_size)
    # NOTE: ./tests/test_state.py:138:         expr = self.state.new_symbolic_value(length)
    # NOTE: ./tests/test_unicorn.py:103:       self.mem.write(start, assemble(asm))

    # Trigger an event when PC reaches a certain value
    # Emulate code in infinite time & unlimited instructions until 'ret_fast_syscall()' which is at 0x8000df00.
    # See the following for why we chose this stop function :https://stackoverflow.com/questions/24176570/how-does-a-system-call-travels-from-user-space-to-kernel-space-and-back-to-user 
    end_address = get_symbol_address(args.systemmap, " t ret_fast_syscall\n") #we used 0x8000df00 constant before which is only valid for kernel 3.4 
    #print "end_address={}".format(hex(end_address))
    @m1.hook(end_address)
    def reached_goal(state):
        cpu = state.cpu
        assert cpu.PC == end_address
        #instruction = cpu.read_int(cpu.PC)
        #print "Execution goal reached (pc={}). Terminating state".format(hex(end_address))
	#m1.terminate()
	state.generate_testcase("abc")
	state.abandon()
        #print "Instruction bytes: {:08x}".format(instruction)
        #print "0x{:016x}: {:08x}".format(cpu.PC,instruction)

    kmem_cache_alloc_trace_addr = get_symbol_address(args.systemmap, " T kmem_cache_alloc_trace\n")
    @m1.hook(kmem_cache_alloc_trace_addr)
    def code_hook_kmem_cache_alloc_trace(state):
        cpu = state.cpu
	#print "cpu.PC = {}". format(hex(cpu.PC))
        assert cpu.PC == kmem_cache_alloc_trace_addr
	size = state.cpu.R2
	ret_addr = candy_memalloc(state, size)
	print "We reached kmem_cache_alloc_trace(), size(r2)={}; using candy allocator and returning addr={} ".format(size,hex(ret_addr));
	state.cpu.regfile.write("R0", ret_addr)

    __kmalloc_addr = get_symbol_address(args.systemmap, " T __kmalloc\n")
    @m1.hook(__kmalloc_addr)
    def code_hook_kmem_cache_alloc_trace(state):
        cpu = state.cpu
        assert cpu.PC == __kmalloc_addr
	size = state.cpu.R0
	ret_addr = candy_memalloc(state, size)
	print "We reached __kmalloc(), size(r0)={}; using candy allocator and returning addr={} ".format(size,hex(ret_addr));
	state.cpu.regfile.write("R0", ret_addr)

    kmalloc_order_trace_addr = get_symbol_address(args.systemmap, " T kmalloc_order_trace\n")
    @m1.hook(kmalloc_order_trace_addr)
    def code_hook_kmem_cache_alloc_trace(state):
        cpu = state.cpu
        assert cpu.PC == kmalloc_order_trace_addr
	size = state.cpu.R0
	ret_addr = candy_memalloc(state, size)
	print "We reached __kmalloc(), size(r0)={}; using candy allocator and returning addr={} ".format(size,hex(ret_addr));
	state.cpu.regfile.write("R0", ret_addr)

    # here is the function prorotye: void *krealloc(const void *p, size_t new_size, gfp_t flags) */
    krealloc_addr = get_symbol_address(args.systemmap, " T krealloc\n")
    @m1.hook(krealloc_addr)
    def code_hook_krealloc(state):
        cpu = state.cpu
        assert cpu.PC == krealloc_addr
	p = cpu.R0
	new_size = cpu.R1
	flags = cpu.R2
        contents = cpu.memory.read(p, new_size)
	new_addr = candy_memalloc(state, new_size)
	cpu.memory.write(new_addr, contents)
	print "We reached krealloc(p={}, new_size={}, flags={}), new addr={} ".format(hex(p), new_size, hex(flags), hex(ret_addr))
	state.cpu.regfile.write("R0", new_addr)

    generic_stub_0_addr = get_symbol_address(args.systemmap, " T generic_stub_0\n")
    @m1.hook(generic_stub_0_addr)
    def code_hook_generic_stub_0(state):
        cpu = state.cpu
        assert cpu.PC == generic_stub_0_addr
	#print "We reached generic_stub_0()";
	state.cpu.regfile.write("R0", 0)

    taint_id = 'taint_A'

    f = InstructionFollower()
    m1.register_plugin(f)

    init_candy_allocator(m1.initial_state)
    m1.initial_state.cpu.R1 = m1.initial_state.new_symbolic_value(32,taint=(taint_id,))
    m1.initial_state.context['symbolic_r1'] = m1.initial_state.cpu.R1
    m1.initial_state.cpu.memory.mmap(0x10000000, 0x1000, 'rwx', name='argp') # To have some memory allocated for argp in case the driver copy from user before ioctl cmd switch statement
    m1.initial_state.cpu.R2 = 0x10000000
    print "R1=",m1.initial_state.cpu.R1
    m1.initial_state.context['candy_brk'] = 0x11000000

    with m1.locked_context() as mc:
        mc["sols"] = list() # We'll store solutions here (i.e. ioctl cmd's)
        #mc['symbolic_r1'] = m1.initial_state.cpu.R1 # So that we can solve in r1

    m1.run(procs=4)
    
    # Save solutions to file
    outf =open('./ioctlcmds.txt', 'w')
    with m1.locked_context() as mc:
        #print "Solutions = ", sorted(set(mc["sols"]))
	i = 0
	for sol in sorted(set(mc["sols"])):
	    #print sol
            outf.write("{}\n".format(sol))
	    i = i + 1
        print "=== {} solutions saved to ioctlcmds.txt".format(i)
    outf.close()

if __name__=='__main__':
    main()

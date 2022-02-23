# Evasion-framework (EASIER)

Testing IOCTL's in Android device drivers without devices.

This is an early research prototype and work in progress. Contributions are welcome. 

See IEEE S&P paper ["Ex-vivo dynamic analysis framework for android device drivers"](https://ieeexplore.ieee.org/document/9152767). This framework was used to discover zero-day bugs in Xiaomi Redmi6 smartphones.

Project includes:
 * Evasion kernel
 * DTB rewriter
 * Binary patcher
 * Emulator
 * Symoblic executor

The core of the evasion framework are evasion kernels.

# Dependencies

You'll need the following:
 * ARM cross compilers to compile kernel and modules
 * Qemu 3.1.1 to run the evasion kernel
 * GDB with ARM support
 * Unicorn emulation library with afl patches
 * AFL fuzzer

Run/refer to `setup.sh` script to install the dependencies.

# Example/Tutorial

Evasion framework is a complex project that includes many parts. One way to understand what each part does is to demostrate how they are used with an example. We will rediscover a vulnerability in Xiaomi REDMI6 kernel. The first step is to checkout the xioami kernel and the commit with the vulnerability.

```
$ cd examples
$ git clone https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git 
$ git checkout cactus-p-oss
$ git checkout ee99fdb82cdafe8cd16dd516b9944e222f6db7e2
```

## Vulnerability description
Here is the description of the vulnrability:
ZERO_SIZE_PTR dereference in ./drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.c (https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git.

A local application can issue ISP_WRITE_REGISTER ioctl and cause a ZERO_SIZE_PTR (equals 0x10) dereference due to that the
return value of kmalloc(0) is checked against NULL but not against ZERO_SIZE_PTR.

Vulnerable code is in ISP_WriteReg() (around line 4383):

```
// Around line 4383
static signed int ISP_WriteReg(struct ISP_REG_IO_STRUCT *pRegIo)
{
        ...
    pData = kmalloc((pRegIo->Count) * sizeof(struct ISP_REG_STRUCT), // <--- pRegIo->Count is user-provided and can be zero, and kmalloc(0) returns ZERO_SIZE_PTR = 0x10
            GFP_ATOMIC);
    if (pData == NULL) {            // <--- pData is 0x10, so this check passes
            ...
        goto EXIT;
    }
    ...

    Ret = ISP_WriteRegToHw(         // Now we go inside ISP_WriteRegToHw() with pData set to ZERO_SIZE_PTR = 0x10
              pData,
              pRegIo->Count);
...
...

// Around line 4287
static signed int ISP_WriteRegToHw(
    struct ISP_REG_STRUCT *pReg,    // pReg is ZERO_SIZE_PTR = 0x10
    unsigned int         Count)
{
        ...
    module = pReg->module;          // finally, pReg=0x10 is dereferenced

...
```
In more detail, when a userspace program calls ISP_WRITE_REGISTER ioctl, it can set pRegIo->Count to 0. kmalloc() is thus called with zero size which returns ZERO_SIZE_PTR = 0x10 (https://lwn.net/Articles/236809/). The driver however only checks if the return value is NULL (i.e. the case the kernel is out of memory), but does not check for ZERO_SIZE_PTR. The driver continues execution and calls ISP_WriteRegToHw(pData,...). Inside function ISP_WriteRegToHw(), pReg=ZERO_SIZE_PTR is dereferences (line module = pReg->module;).


## Building Xiaomi kernel

If you see the following error during the complication:
`/usr/bin/ld: scripts/dtc/dtc-parser.tab.o:(.bss+0x50): multiple definition of ``yylloc'; scripts/dtc/dtc-lexer.lex.o:(.bss+0x0): first defined here`,
replace definition of `YYLTYPE yylloc;` with `extern YYLTYPE yylloc;`

Also some of the pythong scripts might expect python2, if you use python3 by default, fix this by replacing `#! /usr/bin/python` with `#! /usr/bin/python2` in failing scripts.

```
export PATH="$PATH:$(realpath ../../compilers/arm-linux-androideabi-4.9/bin)"
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- cactus_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- -j3
```

You probably will see missing header files during compilation. This should probably be reported to the xiaomi developers. However we are not interested in compiling the xiaomi kernel actually, we just need to generated autogenerated files to be able to compile the vulnerable module. So you can safely move to the next section.

*But* if you really want to compile the xioami kernel, you can fix the errors by:
Replace drivers/devfreq/helio-dvfsrc-opp.c:14:26 
 `#include <helio-dvfsrc.h>` with `#include "helio-dvfsrc.h"`

In
 drivers/devfreq/helio-dvfsrc.h replace
 `#include <helio-dvfsrc-mt6765.h>` with `#include "helio-dvfsrc-mt6765.h"`

and so on.

## Compiling vulnerable driver
We need to compile the driver as a kernel module (.ko file).

We assume you are in xioami folder.
```
cd drivers/misc/mediatek/cameraisp/src/mt6765
```

Modify the Makefile:

Add the following lines:
```
ccflags-y += -I$(srctree)/drivers/misc/mediatek/cmdq/v3/mt6765/
obj-m += camera_isp.o

all:
                make -C ../../../../../../ M=$(PWD) ARCH=arm CROSS_COMPILE=arm-linux-androideabi- modules

		clean:
		                rm -f *.ko *.o
```

and comment out this line:
```
obj-y += camera_isp.o
```

Then run `make`. You should get `camera_isp.ko`.


## Patching vulnerable driver

The driver we just compiled relies on some Xioami-specific functions. These function are not present in the evasion kernel. We need to tell the evasion kernel what to do with them. More specifically, we need to tell the kernel function prototypes for those functions, so that the evasion kernel can choose the right stub.


First run this inside the xiaomi kernel tree:
```
$ cd examples/Xiaomi_Kernel_OpenSource/
$ ctags -R --fields=+KmnSpt --c-kinds=f .
$ cd ../../ # Should be at the root of the evasion framework now
```

Next go to `tools/patcher` and run the script to extract function prototypes.


```
$ cd tools/patcher
$ make
$ ./funcsigs.pl ../../examples/Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.ko ../../examples/Xiaomi_Kernel_OpenSource/tags
```

Function prototypes will be extracted to inject/inject.c. Now we need to compile it and link with out module.

```
$ cd inject/
$ export PATH="$PATH:$(realpath ../../../compilers/arm-eabi-4.8/bin/)"
$ make
$ arm-eabi-ld -r inject.o ../../../examples/Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.ko -o camera_isp-injected.ko
```
You should get file `camera_isp-injected.ko` which now contains an additional ELF section `protos` that has the function signatures.


## Building the evasion kernel


Now we have the driver. In order to execute it, we need to load it into a kernel. The original xiaomi kernel won't run inside Qemu due to hardware dependencies that Qemu does not have (see our paper for details). Vanilla Linux kernel is not going to work either because the driver depends on xiaomi kernel. Also the driver expects the peripheral it controls to be present (and Qemu does not have it). This is where our evasion kernel comes into play. It resolves all the dependencies in a generic way.

Now we have the driver, in order to emuluate it, we need to load it to the evasion kernel.  In order to increase the probability of successfully loading the driver, the evasion kernel needs to be as close to the driver's host kernel as much as possible. By running `make kernelversion` inside xiaomi kernel tree, we can see that it's version is `v4.9.117`. Thus we will use the evasion kernel based on vanilla kernel 4.9.117.

The evasion kernel is a modification of the Linux vanilla kernel. In order save space, we distribute patches that will make evasion kernel from the vanilla kernel. The patches for 4.9.117 are in `evasion-kernels/patches/4.9.117/`. First download the vanilla kernel, and apply the patch and copy missing files.

```
$ cd evasion-kernels
$ wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.9.117.tar.xz 
$ tar -xf linux-4.9.117.tar.xz
$ mv linux-4.9.117 linux-4.9.117-evasion
$ rm linux-4.9.117.tar.xz
$ patch -d linux-4.9.117-evasion -p1 <patches/4.9.117/linux-4.9.117-evasion.patch
$ cp -r patches/4.9.117/* linux-4.9.117-evasion
```

Now you can build the evasion kernel:
```
$ cd linux-4.9.117-evasion
$ ./configure.sh
$ ./menuconfig # <---- IMPORTANT: go to kernel hacking->tracers and enable "Support for tracing block IO actions"
$ ./make.sh
```

As a sanity check you can try to emulate the kernel by running `run-arm-kernel-4.9.sh`.
Use name is `root`, password is `1`.


## Adjusting evasion kernel configuration

Our driver was compiled against a specific xiaomi kernel configuration. In particluar, this kernel configuration defines: (a) kernel subsystems, (b) layout of various kernel structures that are used by the driver. Drivers that implement IOCTL interface use at least the following kernel structures: `struct device` and `struct file`. It is *critical* for the evasion kernel to have the same layouts for these structures (i.e. the same fields at the same offsets). Because of this it is critical that the configuration options that appear in definitions of `struct device` and `struct file` are the same in the xiaomi and evasion kernel.

In order to verify that layouts are the same, we use a special kernel module that lists all the fields in the aforementioned structures. We compile this module against the evasion and xioami kernels and look if the layouts of these structures are different.

### Copy testkoofset module and build it

The module we are going to use is called `testoffsets.ko`, and it located in `evasion-kernels/mymodules/testoffsets`. You need to copy to and compile against both the evasion kernel and the xioami kernels.

```
$ cp -r evasion-kernels/mymodules examples/Xiaomi_Kernel_OpenSource
$ cp -r evasion-kernels/mymodules evasion-kernels/linux-4.9.117-evasion
$ cd examples/Xiaomi_Kernel_OpenSource/mymodules/testoffsets && make && cd -
$ cd evasion-kernels/linux-4.9.117-evasion/mymodules/testoffsets && make && cd -
```

### Compare `struct dev` and `struct file` layouts
Now we need to compare the modules.

First check offsets of `struct file`.

```
./tools/compare-offsets/compare-offsets.py -v evasion-kernels/linux-4.9.117-evasion/mymodules/testoffsets/testoffsets.ko -x examples/Xiaomi_Kernel_OpenSource/mymodules/testoffsets/testoffsets.ko --file
```

It should tell you that you CONFIG_SECURITY is not set in the evasion kernel. Set it, recompile the kernel and *recompile the testoffsets module*. Ater this step, the layouts of `struct device` and `struct file` should be the same.


```
./tools/compare-offsets/compare-offsets.py -v evasion-kernels/linux-4.9.117-evasion/mymodules/testoffsets/testoffsets.ko -x examples/Xiaomi_Kernel_OpenSource/mymodules/testoffsets/testoffsets.ko --dev
```

It should say that offsets match. Go to the next section.

*Note*.
Sometime It might say that there is a offset mismatch between tokens 83 87. This is bit cryptic becuase the script is not finished (contributions are welcome).  You need to look at testoffsets.c to see what configuration options are responsbile for these tokens. This is the part between these tokens:

```
261   quasi_print((uint32_t)&dev_local->pm_domain,INIT_TOKEN+83);
262   #ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
263   quasi_print((uint32_t)&dev_local->msi_domain,INIT_TOKEN+84);
264   #endif
265   #ifdef PINCTRL
266   quasi_print((uint32_t)&dev_local->pins,TOKEN_RANGE1+6);
267   #endif
268   #ifdef CONFIG_GENERIC_MSI_IRQ
269   quasi_print((uint32_t)&dev_local->msi_list,INIT_TOKEN+85);
270   #endif
271   #ifdef CONFIG_NUMA
272   quasi_print((uint32_t)&dev_local->numa_node,INIT_TOKEN+86);
273   #endif
274   quasi_print((uint32_t)&dev_local->dma_mask,INIT_TOKEN+87);
```

Thus you need to check if the following config options are present/missing in both the evasion and xioami kernels. As you will find out `PINCTRL` option is set in Xiaomi kernel and is missing in the evasion kernel. Thus you need to enable this option in the evasion kernel. Relunch menuconfig, set the option and recompile the kernel and the testoffsets.ko module. This should fix the offset descripancy.


## Patching device tree file
The driver expects a specific peripheral to be present. We don't emulate the device. Instead we make the kernel and the driver believe that the peripheral is persent. In order to do that we add a device tree entry to the devce tree file. The first step is to identify the device tree entry name. In order to find the name of the device tree nodes expected by the driver you can grep `compatible` property.

```
grep "compatible = " evasion-framework/examples/Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/cameraisp/src/mt6765/*
```

This shoud give you the following list:

```
 { .compatible = "mediatek,imgsys", },
 { .compatible = "mediatek,dip1", },
 { .compatible = "mediatek,camsys", },
 { .compatible = "mediatek,cam1", },
 { .compatible = "mediatek,cam2", },
 { .compatible = "mediatek,cam3", },
 { .compatible = "mediatek,camsv0", },
 { .compatible = "mediatek,camsv1", },
 { .compatible = "mediatek,camsv2", },
 { .compatible = "mediatek,camsv3", },
 { .compatible = "mediatek,camsv4", },
 { .compatible = "mediatek,camsv5", },
```

The necessary device tree file entries should come with the xiaomi kernel. They can be found in `arch/arm/boot/dts/`. One of them is arch/arm/boot/dts/mt6765.dtb. Let's see if it contains our entries:
```
$ grep mediatek,imgsys  arch/arm/boot/dts/mt6756.dtb
Binary file arch/arm/boot/dts/mt6765 matches
```
It contains the first device tree node. We need to copy it to the evasion kernel's device tree file. You can use `evasion-framework/tools/fdt-extract/fdtextract` program to do this:

```
$ ./fdtextract -f ../../examples/Xiaomi_Kernel_OpenSource/arch/arm/boot/dts/mt6765.dtb -t ../../evasion-kernels/linux-4.9.117-evasion/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb "mediatek,imgsys"
```

Now repeat the same for nodes. (Usualyy you will need just one device tree entry, but his specific example requires many).

```
mediatek,dip1 
mediatek,camsys
mediatek,cam1,
mediatek,cam2,
mediatek,cam3,
mediatek,camsv1
mediatek,camsv2
mediatek,camsv3
mediatek,camsv4
mediatek,smi_larb0
mediatek,smi_larb1
mediatek,smi_larb2
mediatek,smi_larb3
mediatek,seninf1
mediatek,seninf2
mediatek,seninf3
mediatek,seninf4
mediatek,apmixed
mediatek,mmsys_config
```

There are no entries in xioami dtb for nodes
```
mediatek,camsv0
mediatek,camsv5
mediatek,smi_larb4
mediatek,smi_larb5
mediatek,smi_larb6
mediatek,smi_larb7
```

In this case we will create generic nodes using the same program (`fdtextract`):
```
$ ./fdtextract -f none -t ../../evasion-kernels/linux-4.9.117-evasion/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb "mediatek,camsv0"
```
(repeat for other nodes).


## Loading the driver inside the evasion kernel
Now we should be ready to load our driver inside the evasion kernel.

```
$ cd evasion-kernels/linux-4.9.117-evasion
$ ./run-arm-kernel-4.9.sh
# Go to the inject folder with the patched module
$ scp camera_isp-injected.ko root@192.168.99.36:
```

In the evasion kernel in Qemu:
```
# insmod camera_isp-injected.ko
# lsmod
Module                  Size  Used by    Tainted: G
camera_isp            395594  0 [permanent]
```

and you should also have a new entry in `/dev/` : `/dev/camera-isp`.

`At this point we verfied that we can load the driver and it creates a dev entry for which we can issue ioctl's. You can poweroff the evastion kernel VM:

```
# poweroff
```


# Part 2: fuzzing

## Collect memory dump
Now we have the configured evasion kernel and the driver. We need to load the driver to the kernel, execute an ioctl system call and this moment collect the memory/registers state from Qemu for further analysis. You can use `prepare-emulation-arm.pl` sript to do this.

```
$ cd fuzzer
$ cp ../tools/patcher/inject/camera_isp-injected.ko ./binary/   #  the scirpt expect the vulnerable module to be present in 'fuzzer/binary' folder
```

We need to collect the memory dump once the execution enters the driver's ioctl handerl. In order to find out the ioclt hander name, we can run
```
$ readelf -s binary/camera_isp-injected.ko | grep -i ioctl
621: 00011bbc 20448 FUNC    LOCAL  DEFAULT    3 ISP_ioctl
...
```

And we found the dev file when we loaded the driver into the evasion kernel manulaly dring the previous steps : `/dev/camera-isp`.


The first step is to run the evasion kernel inside Qemu, load the driver, issue ioctl and collect kernel state snapshot. In order to do this we will use 
```
$ sudo ./prepare-tap.sh   # Creates tep interface so that we can speak with the kernel over the network
$ ./prepare-emulation-arm.pl -m camera_isp-injected.ko -p '/dev/camera-isp' -i ISP_ioctl -k 4.9
```

Here is the expected output:


```
$ ./prepare-emulation-arm.pl -m camera_isp-injected.ko -p '/dev/camera-isp' -i ISP_ioctl -k 4.9                                                                                               
    inet 192.168.99.37/24 scope global tap0                                                                                                                                                                     
[+] Restoring fresh virtual hard drives. Ignore audio errors messages (if any).audio: Could not init `oss' audio driver
[+] Qemu started wth PID 104728       
[+] Copying and loading modules
    -- camera_isp-injected.ko
Module                  Size  Used by    Tainted: G   
camera_isp            395082  0 [permanent]

[+] Copying test program: ./testprogram/sample-ioctl 
[+] Getting kernel memory map/kallsyms
[+] Extracting the address of the ioctl handler you want to fuzz
    ISP_ioctl was loaded to at address 0x7f011bbc
[+] Getting userspace memory maps
[+] Generating gdb scripts...
     warning: NOT skipping unused large range
              0x83180000 - 0x87180000 (64 M)
     warning: NOT skipping unused large range
              0x87200000 - 0x8b200000 (64 M)
     warning: NOT skipping unused large range
              0x8b280000 - 0x8d280000 (32 M)
    file './emulation/memdumppart.gdb' generated
[+] gdb'ing to Qemu and taking the memdump (gdb output follows)
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default 
arm settings.                                       
The target architecture is set to "arm".
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default 
arm settings.                                       
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0x80118528 in ?? ()                                 
Breakpoint 1 at 0x80240a90
Temporary breakpoint 2 at 0x7f011bbc
[INFO] Running test program: ./sample-ioctl /dev/camera-isp
[+] Dumping memory regions and registers: 45/45
[+] Memory and registers dumped                    
[+] Qemu stopped                                    
[+] Postprocessing emulation/gdb.txt for coprocessor registers
[+] Generating coprocessor registers setup code
    setup_cpregs.bin generated
[+] All done.                                       
    Dumps are in 'emulation/memdumps' and 'emulation/registers'
    Memory maps (user space, kernel space, and kallsysm (or System.map) are in ./emulation/memmappings/
    Use 'emulation/dumps2elf/dumps2elf.pl' if you want to convert memdumps to an elf image (for symbex)
```

After this command, the memory will be saved into `emulation /memdumps`, and registers are saved in `emulation/registers`. Arm corprocessor registers will be set using code in `emulation/set_cpregs.bin`. 


## Emulating memory dump

Now we can emulate the driver code using cpu only emualation tool. There are two key feautures of our emulator:

 * If driver code accesses invalid memory, the emulation segfaults. This allows us to capture memory violiation erros 
 * It recovers IOCTL structure format automatically, 
 * I aligns fuzzer's input automatically directly in the memory
 * We can re-execute emualation very fast. This allows us to use the fuzzer eficiently

We collected memory/registers at the time when the execution entered the IOCTL handerl (ISP_ioctl). Our emulation tools will continue the execution from this point. You can run this as follows:

```
$ cd fuzzer/emulation
$ make
$ ./emulate-arm -s memmappings/System.map
[DEBUG]: "[+] Initializing registers from registers/qmp-registers txt"                                                                                                                   [DEBUG]: "[+] Dumping registers\n" 
...
    0x80240ad0:         mov     r0, r4
    0x80240ad4:         pop     {r3, r4, r5, r6, r7, r8, sb, pc}
[DEBUG]: ">>> PC = 0x801076c0"
Emulation only took 0.001544 seconds
```

## Recovering IOCTL command numbers with symbolic execution

IOCTL hander's use commands. Each command has a magic number. Fuzzers are bad at recovering magic numbers. This is why we need to recover this numbers first. There two way to do this: 1) manually from the source code; 2) with our symbolic executio tool.  Let's try the second approach. The symbolic execution tools accepts dumps combined as an elf file. You can use `emulation/dumps2elf/dumps2elf.pl` script to do the conversion.

```
$ cd dumps2elf
$ ./dumps2elf.sh  # It will read files from ../memdumps
```

Now we are ready to run symbolic execution.

```
./symbex.py -m dumps2elf/img.elf -s memmappings/System.map -r registers/qmp-registers.txt -i ISP_ioctl
```

(Expect ~4GB of RAM to be used for symbolic execution)
This will produce a list of numbers that are ioctl commands and will save them into `ioctlcmds.txt`. Usually you want to fuzz all of them. But for this tutorial we focus on ISP_WRITE_REGISTER ioctl which is 3221777154. You can verify that `ioctlcmds.txt` has this number.


## Fuzzing

The core of the fuzzing process is program called `emualte-arm`. It reads the memory snapshot/registers and emulates it from the point where we took the memory dump. It's a quite complex program that does many things, but the key features is that it segfaults when the correspodning drive would segfault in the kenrel. This allows the fuzzer to catch those crashes.


### Finding crashes
```
$ mkdir output-3221777154
$ export cmd=3221777154
$ sudo sh -c "echo core >/proc/sys/kernel/core_pattern"
$ sudo echo performance | sudo tee cpu*/cpufreq/scaling_governor
$ AFL_NO_AFFINITY=1 ../../afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o $outputdir -- ./emulate-arm -s ./memmappings/System.map -c $cmd -f @@
```


```
                     american fuzzy lop 2.52b (emulate-arm)

┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐
│        run time : 0 days, 0 hrs, 15 min, 15 sec      │  cycles done : 5      │
│   last new path : 0 days, 0 hrs, 0 min, 52 sec       │  total paths : 29     │
│ last uniq crash : 0 days, 0 hrs, 0 min, 35 sec       │ uniq crashes : 16     │
│  last uniq hang : 0 days, 0 hrs, 1 min, 5 sec        │   uniq hangs : 6      │
├─ cycle progress ────────────────────┬─ map coverage ─┴───────────────────────┤
│  now processing : 5 (17.24%)        │    map density : 0.13% / 0.26%         │
│ paths timed out : 0 (0.00%)         │ count coverage : 1.12 bits/tuple       │
├─ stage progress ────────────────────┼─ findings in depth ────────────────────┤
│  now trying : havoc                 │ favored paths : 19 (65.52%)            │
│ stage execs : 26.6k/32.8k (81.12%)  │  new edges on : 27 (93.10%)            │
│ total execs : 100k                  │ total crashes : 3374 (16 unique)       │
│  exec speed : 114.4/sec             │  total tmouts : 22 (6 unique)          │
├─ fuzzing strategy yields ───────────┴───────────────┬─ path geometry ────────┤
│   bit flips : 4/960, 3/954, 1/942                   │    levels : 4          │
│  byte flips : 1/120, 0/114, 0/102                   │   pending : 24         │
│ arithmetics : 6/6714, 0/6676, 0/4415                │  pend fav : 16         │
│  known ints : 0/341, 0/1331, 1/2420                 │ own finds : 28         │
│  dictionary : 0/0, 0/0, 0/87                        │  imported : n/a        │
│       havoc : 13/41.2k, 3/6864                      │ stability : 100.00%    │
│        trim : 81.16%/48, 0.00%                      ├────────────────────────┘
^C────────────────────────────────────────────────────┘             [cpu: 58%]

+++ Testing aborted by user +++
[+] We're done here. Have a nice day!
```

Now we found a number of crashes and the fuzzer output is in `output-3221777154/`. 

### Generating programs

When it comes to local privelege escalation vulnerabilities via IOCTL's, such vulnerabilities are triggered by a local unpriveleged program. Such program issues an ioctl system call, with two arguments: cmd, and an a pointer to arbitrary structure. Recovering such structure is a difficult problem but `emulate-arm` is able to do automatically. First you need to run emulation again with the crashing input:

```
./emulate-arm -s ./memmappings/System.map -c $cmd -f output-3221777154/crashes/id\:000000\,sig\:11\,src\:000000\,op\:int32\,pos\:4\,val\:+0 
```
This will generate file `recovered-ioctlscheme-cmd-3221777154` with xml representation of the recovered ioctl structure. Then you can use to use script `./xml2c.pl` to generate a program that triggers the vulnerability.


```
$ ./xml2c.pl recovered-ioctlscheme-cmd-3221777154 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

struct sp_0x10000000 {
  uint8_t farray_0x10000008[0];
};

struct toplevel_0x10000000 {
  struct sp_0x10000000 *fp_0x10000000;
  uint8_t farray_0x10000004[4];
};

int main()
{

  struct sp_0x10000000 var_sp_0x10000000;
  memcpy(&var_sp_0x10000000.farray_0x10000008, "", 0);
  
  struct toplevel_0x10000000 var_toplevel_0x10000000;
  var_toplevel_0x10000000.fp_0x10000000 = &var_sp_0x10000000;
  memcpy(&var_toplevel_0x10000000.farray_0x10000004, "\x00\x00\x00\x00", 4);
  
  int fd = open('/dev/xxx', O_RDWR);
  ioctl(fd, 3221777154, &var_toplevel_0x10000000);
}
```





# evasion-framework

Testing IOCTL's in Android device drivers without devices.

Project description
 * Evasion kernel
 * DTB rewriter
 * Binary patcher
 * Emulator
 * Symoblic executor

The core of the evasion framework are evasion kernels.

## Dependencies
### Download cross compilers and Qemu 3.1.1

You will need ARM cross compilers to compile the evasion kernels. You will aslo need to have Qemu 3.10 to emulate the kernels. You can use script `setup.sh` to fetch compilers from codeaurora into 'compilers' folder and Qemu into 'qemu-3.1.1' folder

```
$ ./setup.sh
```

## Example/Tutorial

Evasion framework is a complex project that includes many parts. One way to understand what each part does is to demostrate how they are used with an example. In our first example we will use the evasion framework to rediscover CVE-2014-9782 (https://www.cvedetails.com/cve/CVE-2014-9782/):

```
drivers/media/platform/msm/camera_v2/sensor/actuator/msm_actuator.c in the
Qualcomm components in Android before 2016-07-05 on Nexus 5 and 7 (2013)
devices does not validate direction and step parameters, which allows attackers
to gain privileges via a crafted application, aka Android internal bug 28431531
and Qualcomm internal bug CR511349.
```

### Get (download) the driver
The bug resides in an IOCTL handler of the corresponding driver. Our goal is to fuzz this driver on our desktop computer and find a crash. Let's download the correspdonding Android kernel that has the vulnerable driver.  CVE-2014-9782 was fixed in the current version, so we need to checkout the commit where this bug was still present (in order find out the commit, got to  and check the parent commit).

```
$ mkdir examples
$ git clone https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git
$ git checkout ee99fdb82cdafe8cd16dd516b9944e222f6db7e2
```

### Compile the driver
Now we have the right kernel tree. 

With Android kernel, there are two ways to compile a driver: a)
built-in (i.e. a part of vmlinux binary) or b) a loadable kernel module.
We will need to compile the driver as a kernel loadable module. The first step is to compile the kernel. 

```
$ export PATH="$PATH:$(realpath ../../compilers/arm-eabi-4.6/bin)"
$ make O=msm-kernel-build ARCH=arm msm8610_defconfig
$ make O=msm-kernel-build ARCH=arm CROSS_COMPILE=arm-eabi- -j3

```

If you see the following error during the complication:
`/usr/bin/ld: scripts/dtc/dtc-parser.tab.o:(.bss+0x50): multiple definition of ``yylloc'; scripts/dtc/dtc-lexer.lex.o:(.bss+0x0): first defined here`,
replace definition of `YYLTYPE yylloc;` with `extern YYLTYPE yylloc;`


The second step is to compile the driver. 

The driver consists of two parts: msm subsystem and the actuator sensor driver:
`msm.ko` and `msm_actuator.ko`.  You can compile the driver anyway you want
(for example you can find the corresponding config options).  I prefer to
modify the corresponding Makefiles.

The source code for the driver is located in 
`drivers/media/platform/msm/camera_v2` and `drivers/media/platform/msm/camera_v2/sensor/actuator`.

You'll need to make the following modifications to the corresponding Makefiles (the diff looks a bit big, but its due to the context, only a few lines were modified/added):

```
diff --git a/drivers/media/platform/msm/camera_v2/Makefile b/drivers/media/platform/msm/camera_v2/Makefile
index 02eb3dd0584c..09559fef6420 100644
--- a/drivers/media/platform/msm/camera_v2/Makefile
+++ b/drivers/media/platform/msm/camera_v2/Makefile
@@ -7,13 +7,20 @@ ccflags-y += -Idrivers/media/platform/msm/camera_v2/msm_vb2
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/camera
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/jpeg_10

-obj-$(CONFIG_MSMB_CAMERA) += msm.o
+obj-m += msm.o
 obj-$(CONFIG_MSMB_CAMERA) += camera/
 obj-$(CONFIG_MSMB_CAMERA) += msm_vb2/
-obj-$(CONFIG_MSMB_CAMERA) += sensor/
+obj-m += sensor/
 obj-$(CONFIG_MSMB_CAMERA) += isp/
 obj-$(CONFIG_MSMB_CAMERA) += ispif/
 obj-$(CONFIG_MSMB_JPEG) += jpeg_10/
 obj-$(CONFIG_MSMB_CAMERA) += msm_buf_mgr/
 obj-$(CONFIG_MSMB_CAMERA) += pproc/
 obj-$(CONFIG_MSMB_CAMERA) += gemini/
+
+
+all:
+               make -C ../../../../../ O=msm-kernel-build M=$(PWD) ARCH=arm CROSS_COMPILE=arm-eabi- modules
+
+clean:
+               rm -f *.ko *.o
diff --git a/drivers/media/platform/msm/camera_v2/sensor/Makefile b/drivers/media/platform/msm/camera_v2/sensor/Makefile
index bd1b10ba2af7..829caec5a6d8 100644
--- a/drivers/media/platform/msm/camera_v2/sensor/Makefile
+++ b/drivers/media/platform/msm/camera_v2/sensor/Makefile
@@ -3,7 +3,8 @@ ccflags-y += -Idrivers/media/platform/msm/camera_v2/msm_vb2
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/camera
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/io
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/cci
-obj-$(CONFIG_MSMB_CAMERA) += cci/ io/ csiphy/ csid/ actuator/ flash/ eeprom/
+#obj-$(CONFIG_MSMB_CAMERA) += cci/ io/ csiphy/ csid/ actuator/ flash/ eeprom/
+obj-m += actuator/
 obj-$(CONFIG_MSM_CAMERA_SENSOR) += msm_sensor.o
 obj-$(CONFIG_S5K3L1YX) += s5k3l1yx.o
 obj-$(CONFIG_IMX135) += imx135.o
diff --git a/drivers/media/platform/msm/camera_v2/sensor/actuator/Makefile b/drivers/media/platform/msm/camera_v2/sensor/actuator/Makefile
index c0d607f731ba..c2b02d7a44b6 100644
--- a/drivers/media/platform/msm/camera_v2/sensor/actuator/Makefile
+++ b/drivers/media/platform/msm/camera_v2/sensor/actuator/Makefile
@@ -1,4 +1,5 @@
 ccflags-y += -Idrivers/media/platform/msm/camera_v2
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/io
 ccflags-y += -Idrivers/media/platform/msm/camera_v2/sensor/cci
-obj-$(CONFIG_MSMB_CAMERA) += msm_actuator.o
+#obj-$(CONFIG_MSMB_CAMERA) += msm_actuator.o
+obj-m += msm_actuator.o
```

I also had some problems compiling the driver, maybe it's due to compiler version. So I had to fix the errors emmitted by the compiler. Here are my modifications:

```
diff --git a/drivers/media/platform/msm/camera_v2/msm.c b/drivers/media/platform/msm/camera_v2/msm.c
index da2f9005208c..7d5c20335a2a 100644
--- a/drivers/media/platform/msm/camera_v2/msm.c
+++ b/drivers/media/platform/msm/camera_v2/msm.c
@@ -1026,8 +1026,8 @@ probe_end:
 }

 static const struct of_device_id msm_dt_match[] = {
-       {.compatible = "qcom,msm-cam"},
-}
+       {.compatible = "qcom,msm-cam"}, {}
+};

 MODULE_DEVICE_TABLE(of, msm_dt_match);
diff --git a/drivers/media/platform/msm/camera_v2/sensor/actuator/msm_actuator.c b/drivers/media/platform/msm/camera_v2/sensor/actuator/msm_actuator.c
index 87178b720c4c..75cd0a818a02 100644
--- a/drivers/media/platform/msm/camera_v2/sensor/actuator/msm_actuator.c
+++ b/drivers/media/platform/msm/camera_v2/sensor/actuator/msm_actuator.c
@@ -849,7 +849,8 @@ MODULE_DEVICE_TABLE(of, msm_actuator_i2c_dt_match);
 static struct i2c_driver msm_actuator_i2c_driver = {
        .id_table = msm_actuator_i2c_id,
        .probe  = msm_actuator_i2c_probe,
-       .remove = __exit_p(msm_actuator_i2c_remove),
+       //.remove = __exit_p(msm_actuator_i2c_remove),
+       .remove = NULL,
        .driver = {
                .name = "qcom,actuator",
                .owner = THIS_MODULE,
diff --git a/scripts/dtc/dtc-parser.tab.c_shipped b/scripts/dtc/dtc-parser.tab.c_shipped
index ee1d8c3042fb..c8c8ca8b744f 100644
--- a/scripts/dtc/dtc-parser.tab.c_shipped
+++ b/scripts/dtc/dtc-parser.tab.c_shipped
@@ -73,7 +73,7 @@
 #include "dtc.h"
 #include "srcpos.h"

-YYLTYPE yylloc;
+extern YYLTYPE yylloc;

 extern int yylex(void);
 extern void print_error(char const *fmt, ...);
```

After these modifications and running `make` inside `drivers/media/platform/msm/camera_v2` folder., I have `msm.ko` and `msm_actuaotr.ko` in the corresponding folders.


Now we have the driver. In order to execute it, we need to load it into a kernel. The original msm kernel won't run inside Qemu due to hardware dependencies that Qemu does not have (see our paper for details). Vanilla Linux kernel is not going to work either because the driver depends on msm kernel. Also the driver expects the peripheral it controls to be present (and Qemu does not have it). 

This is where our evasion kernel comes into play. It resolves all the dependencies in a generic way.

### Choose evasion kernel version

In order to increase the probability of successfully loading the driver, the evasion kernel needs to be as close to the driver's host kernel (in our case the MSM kernel) as much as possible. By running `make kernelvercion` inside msm kernel tree, we can see that it's version is `v3.10`. Thus we choose to use `evasion-kernels/linux-3.10-alien`.


### Configure evasion kernel 

Our driver was compiled against a specific kernel configuration. In particluar, kernel configuration defines: (a) kernel subsystems, (b) layout of various kernel structures that are used by the driver. Drivers that implement IOCTL interface use at least the following kernel structures: `struct device` and `struct file`. It is critical for the evasion kernel to have the same layout for these structures. In order to help with this, 


Because of this it is critical that the evasion kernel has some of the configuraiton options identical to the driver's host kernel.

It is very important that the evasion kernel has the same configuration option for 

to configure the evasion kernel the same way.

```
$ cd evasion-kernels/linux-3.10-alien
$ ./configure.sh
$ ./make.sh
```


### Building Xiaomi kernel


1. Build
export PATH="$PATH:$(realpath ../../compilers/arm-linux-androideabi-4.9/bin)"
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- cactus_defconfig
(fix extern yylloc and python2)

Replace drivers/devfreq/helio-dvfsrc-opp.c:14:26 
 #include <helio-dvfsrc.h> with #include "helio-dvfsrc.h"

In
 drivers/devfreq/helio-dvfsrc.h replace
 #include <helio-dvfsrc-mt6765.h> with #include "helio-dvfsrc-mt6765.h"

2. Copy checkoofset module and build it
inside xiomi kernel:
mkdir mymudules
cp -r evasion-kernels/linux-4.9.117-alien/mymodules/checkoffsets mymodules/

./compare-offsets.py -v testoffsets.ko -x /home/ivan/prj/evasion-framework/examples/Xiaomi_Kernel_OpenSource/mymodules/checkoffsets/testoffsets.ko --dev
It should say that there is a offset mismatch between tokens 83 87. You need to look at testoffsets.c to see what configuration options are responsbile for these tokens. This is the part between these tokens:

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

Thus you need to check if the following config options are present/missing in both the evasion and xioami kernels. As you will find out PINCTRL option is set in Xiaomi kernel and is missing in the evasion kernel. Thus you need to enable this option in the evasion kernel. The future version of the script will tell you the name of config options (contributions are welcome).

You cannot enable this option using menuconfig. In order to enable it modify it entry in drivers/pinctrl/Kconfig:

```
  5 config PINCTRL
  6         bool "PINCTRL support"
  7         default y
  8         ---help---
  9                 Pin ctrl.
```

and relunch menuconfig, set the option and recompile the kernel and the testoffsets.ko module. This should fix the offset descripancy.
Now let's check offsets of `struct file`.

```
./compare-offsets.py -v testoffsets.ko -x /home/ivan/prj/evasion-framework/examples/Xiaomi_Kernel_OpenSource/mymodules/checkoffsets/testoffsets.ko --file
```

It should tell you that you CONFIG_SECURITY is not set in the evasion kernl. Set it, recompile. Ater this step, the layouts of `struct device` and `struct file` should be the same.

IMPORTANT: also enable BLK_DEV_IO_TRACE in the evasion kernel.


### Vulnerability
Here is the description of the vulnrability:
ZERO_SIZE_PTR dereference in ./drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.c (https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git, branch "cactus-p-oss")

A local application can issue ISP_WRITE_REGISTER ioctl and cause a ZERO_SIZE_PTR (equals 0x10) dereference due to that the
return value of kmalloc(0) is checked against NULL but not against ZERO_SIZE_PTR.

Vulnerabl code in ISP_WriteReg() (around line 4383):

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


### Compiling vulnerable driver
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


### Patching vulnerable driver

The driver we just compiled relies on some Xioami-specific functions. These function are not present in the evasion kernel. We need to tell the evasion kernel what to do with them. More specifically, we need to tell the kernel function prototypes for those functions, so that the evasion kernel can choose the right stub.

First ru this inside the xiaomi kernel tree:
```
ctags -R --fields=+KmnSpt --c-kinds=f .
```

Next go to `evasion-framework/fuzzer/patcher`.
and run the following command
1. Install necessary perl modules.
```
sudo cpan Binutils::Objdump
sudo cpan Parse::ExuberantCTags
```
2. Run the script to extract function prototypes.
```
./funcsigs.pl ../../examples/Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.ko ../../examples/Xiaomi_Kernel_OpenSource/tags
```

Function prototypes will be extracted to inject/inject.c. Now we need to compile it and link with out module.

```
cd inject/
export PATH="$PATH:$(realpath ../../../compilers/arm-eabi-4.8/bin/)"
make
arm-eabi-ld -r inject.o ../../../examples/Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/cameraisp/src/mt6765/camera_isp.ko -o camera_isp-injected.ko
```
You should get file `camera_isp-injected.ko` which now contains an additional ELF section `protos` that has the function signatures.

### Patching device tree file
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
 /*{ .compatible = "mediatek,camsv6", },
```

When we compiled the xiaomi kernel, it also compiled some of the device tree files. They can be found in `arch/arm/boot/dts/`. One of them is arch/arm/boot/dts/mt6765.dtb. Let's see if it contains our entries:
```
$ grep mediatek,imgsys  arch/arm/boot/dts/mt6756.dtb
Binary file arch/arm/boot/dts/mt6765 matches
```
It contains the first device tree node. We need to copy it to the evasion kernel's device tree file. You can use `evasion-framework/fuzzer/fdt-extract/fdtextract` program to do this:

```
$ ./fdtextract -f /home/ivan/prj/evasion-framework/examples/Xiaomi_Kernel_OpenSource/arch/arm/boot/dts/mt6765.dtb -t /home/ivan/prj/evasion-framework/evasion-kernels/linux-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb "mediatek,imgsys"
Going to extract node 'mediatek,imgsys'
from file: '/home/ivan/prj/evasion-framework/examples/Xiaomi_Kernel_OpenSource/arch/arm/boot/dts/mt6765.dtb' and inject it
into file: '/home/ivan/prj/evasion-framework/evasion-kernels/linux-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb'

[+] Loading dtb's: '/home/ivan/prj/evasion-framework/examples/Xiaomi_Kernel_OpenSource/arch/arm/boot/dts/mt6765.dtb', '/home/ivan/prj/evasion-framework/evasion-kernels/linux-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb'
[+] Found node 'imgsys@15020000' (compatible = 'mediatek,imgsys') in the host dtb
[+] Analyzing node
    Found #interrupt-cells in node intpol-controller@10200a80
    interrupt cells = 3
    Looking for node's parent in host dtb
    After checking the parent: the node is NOT an i2c device.
[+] Preparing new empty node under root in evasion dtb
[+] Copying host node's properties into the prepared empty node
    + copying property compatible, len = 23
    + copying property reg, len = 16
    + copying property #clock-cells, len = 4
    + copying property clocks, len = 80
    + copying property clock-names, len = 154
    - skipping 'linux,phandle' property
    = replacing 'phandle' property with a newly generated value
[+] Backing up evasion dtb into 'backup.dtb'
[+] Rewriting the original evasion dtb file
```

Now repeat the same for nodes 

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
$ ./fdtextract -f none -t /home/ivan/prj/evasion-framework/evasion-kernels/linux
-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb "mediatek,camsv0"
[+] Going to create a new node 'mediatek,camsv0' in file '/home/ivan/prj/evasion-framework/evasion-kernels/linux-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb'
[+] Loading dtb: '/home/ivan/prj/evasion-framework/evasion-kernels/linux-4.9.117-alien/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb'
[+] Preparing new empty node 'generic_node_94068169@4ba00000' under root in evasion dtb
[+] Adding new fields
[+] Adding dummy subnode 'generic_subnode_1137472617'
[+] Backing up evasion dtb into 'backup.dtb'
[+] Rewriting the original evasion dtb file
```
(repeat for other nodes).


### Loading the driver inside the evasion kernel
Now we should be ready to load our driver inside the evasion kernel.

```
cd evasion-kernels/linux-4.9.117-alien
run-arm-kernel-4.9.sh
# Go to the inject folder with the patched module
scp camera_isp-injected.ko root@192.168.99.36:
```

In the evasion kernel in Qemu:
```
# insmod camera_isp-injected.ko
# lsmod
Module                  Size  Used by    Tainted: G
camera_isp            395594  0 [permanent]
```

and you should also have a new entry in `/dev/` : `/dev/camera-isp`.

At this point we verfied that we can load the driver and it creates  a dev entry for which we can issue ioctl's

# Part 2: fuzzing

Now we have the configured evasion kernel and the driver.


This folder contains 'patcher' to (in place) patch module's relocation entry

Given a function name and the offset from the start of the function,
patcher tries to find the relocation entry that targets that location.
If found it replaces the relocation's symbol to 'generic_stub' symbol.
Note that 'generic_stub' symbol should be present in the module. You can inject
a symbol by compiling and linking the following code with the module:

 int generic_stub();

 int randomfunction()
 {
   generic_stub();
 }

 And then compile with:
$ arm-eabi-gcc -fno-short-enums -c inject.c
$ arm-eabi-ld -r inject.o ../vidc.ko -o vidc-injected.ko

Example:
$ patcher vidc-injected.ko res_trk_check_for_sec_session 0x1

Note. Use the same gcc versin as you used to compiled you kernel and module.
Pay special attentaion of you used hard fp or softfp.
For example if you use 'arm-linux-gnueabihf-gcc', it will use
hard float point calling convention. Most probably it is not what you
want, use arm-eabi-gcc.

You can check if you use hard fp using the following command:
$ arm-eabi-readelf -A inject.o
Attribute Section: aeabi
File Attributes
  Tag_CPU_name: "7-A"
  Tag_CPU_arch: v7
  Tag_CPU_arch_profile: Application
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-2
  Tag_FP_arch: VFPv3-D16
  Tag_ABI_PCS_wchar_t: 4
  Tag_ABI_FP_denormal: Needed
  Tag_ABI_FP_exceptions: Needed
  Tag_ABI_FP_number_model: IEEE 754
  Tag_ABI_align_needed: 8-byte
  Tag_ABI_align_preserved: 8-byte, except leaf SP
  Tag_ABI_enum_size: int
  Tag_ABI_HardFP_use: SP and DP
  Tag_ABI_VFP_args: VFP registers                  <-- Look for this field, if you have it, you use hardfp, which is not good.
  Tag_ABI_optimization_goals: Aggressive Debug
  Tag_CPU_unaligned_access: v6

Here are a couple of link that might help you to uderstand the problem:

https://stackoverflow.com/questions/9753749/arm-compilation-error-vfp-registered-used-by-executable-not-object-file
https://stackoverflow.com/questions/20555594/how-can-i-know-if-an-arm-library-is-using-hardfp
https://stackoverflow.com/questions/43890117/enforce-32-bit-enums-with-gcc-linker

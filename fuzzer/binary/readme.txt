* Files in this folder are necessary for 'prepre-emulation*' scripts to run.
* This folder contains:
  1. zImage's of modified kernels that allow loading aline modules
     (Usually you compile them at heaven1 and scp them here)
  2. Modules we want to fuzz (you compile them at heaven1)
  3. Sample programs that trigger the module functionality
     (you can find them in ../../fuzzer/driverprograms/)

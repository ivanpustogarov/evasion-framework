#! /bin/bash

# Original version can be found here: ./prj/LKM-fuzz/my-modules/ebbchar/emulation/build-elf-from-memdumps/

# This script coverts each memory dump from "../memdumps" to an relocatable
# object ELF file (.o) using objcopy. It then links those object file into the
# final "executable" ELF binary. This script generates linker script files which
# are removed at the end. You can comment the following line `rm $LINKERSCRIPT $LINKERSCRIPT_S $LINKERSCRIPT_P`
# in order to debug those scripts

export PATH="$PATH:/home/ivan/prj/LKM-fuzz/linux-kernels/compilers/arm-eabi-4.6/bin"

LINKERSCRIPT_S="link-s.ld"
LINKERSCRIPT_P="link-p.ld"
LINKERSCRIPT="link.ld"
OUTPUT="img.elf"
DUMPSFOLDER="../memdumps"

rm -f $LINKERSCRIPT $LINKERSCRIPT_S $LINKERSCRIPT_P
rm -f *.o
rm -f $OUTPUT
echo "SECTIONS" > $LINKERSCRIPT_S
echo '{' >> $LINKERSCRIPT_S

echo "PHDRS" > $LINKERSCRIPT_P
echo '{' >> $LINKERSCRIPT_P

dump_list=$(ls  $DUMPSFOLDER/*.dump)

i=0
while read -r filename
do
    i=$((i+1))
    echo "[+] Converting \"$filename\" to relocatable elf"
    fbname=$(basename "$filename" .dump) # <fbname> stands for _f_ile _b_ase _name_
    #sectionname=".dump$fbname"
    vm_start=$(echo $fbname | cut -f1 -d'-')
    #objcopy -I binary -O elf64-x86-64 -B i386 --set-section-flags .data=CONTENTS,ALLOC,LOAD,CODE --rename-section .data=$sectionname $fbname.dump $fbname.o
    arm-eabi-objcopy -I binary -O elf32-littlearm -B arm --set-section-flags .data=CONTENTS,ALLOC,LOAD,CODE "$DUMPSFOLDER/$fbname.dump" $fbname.o
    #echo "    Updating linker script, vm_start=$vm_start"
    #echo "$sectionname 0x$vm_start: AT ( 0x$vm_start ) { 
    echo ". = 0x$vm_start;" >> $LINKERSCRIPT_S
    echo ".dump$i : { $fbname.o (.data); } : pdump$i" >> $LINKERSCRIPT_S

    echo "pdump$i PT_LOAD AT ( 0x$vm_start ) ;" >> $LINKERSCRIPT_P
    #echo $vm_start
done < <(printf '%s\n' "$dump_list")

echo '}' >> $LINKERSCRIPT_S
echo '}' >> $LINKERSCRIPT_P

cat $LINKERSCRIPT_P $LINKERSCRIPT_S > $LINKERSCRIPT

echo "[+] Linking into \"img.elf\""
#ld -Map system.map -N -T $LINKERSCRIPT *.o -o $OUTPUT
#ld -Map system.map --split-by-file -N -T link.ld *.o -o img.elf
arm-eabi-ld -N -T $LINKERSCRIPT *.o -o $OUTPUT

echo "[+] Deleting temporary files (*.o and linker scripts)"
rm *.o
rm $LINKERSCRIPT $LINKERSCRIPT_S $LINKERSCRIPT_P

echo "[+] All done. Final elf is \"img.elf\""

#objcopy -I binary -O elf64-x86-64 -B i386 --set-section-flags .data=CONTENTS,ALLOC,LOAD,CODE --rename-section .data=.dump0000000000601000  0000000000601000-0000000000602000.dump 0000000000601000-0000000000602000.o
#objcopy -I binary -O elf64-x86-64 -B i386 --set-section-flags .data=CONTENTS,ALLOC,LOAD,CODE --rename-section .data=.dumpffff880000000000 ffff880000000000-ffff880000200000.dump ffff880000000000-ffff880000200000.o

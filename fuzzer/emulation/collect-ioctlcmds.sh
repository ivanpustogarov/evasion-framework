#! /bin/bash

IOCTLCMDS="ioctlcmds.txt"
cat mcore*/*.input > $IOCTLCMDS
echo "[+] Collected ioctl cmds from manticore (mcore*) output into file $IOCTLCMDS"
rm -rf ./mcore*
echo "[+] Deleting mcore* folder"

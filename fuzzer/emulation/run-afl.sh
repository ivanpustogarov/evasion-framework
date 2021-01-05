#! /bin/bash

#AFL_SKIP_CPUFREQ=1 ~/Workspaces/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate -s System.map -a iosubmit -f @@
#AFL_SKIP_CPUFREQ=1 ~/Workspaces/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate-arm -s System.map -a write -f @@
#AFL_SKIP_CPUFREQ=1 ~/Workspaces/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate-arm -s System.map -a ioctl -f @@
#AFL_SKIP_CPUFREQ=1 ~/Workspaces/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate-arm -c 3221513216 -x ioctlschemas/testmodule-cmd-3221513216-setmsg.xml -f @@

# On how to check that a session exisits and create a new session within tmux: https://stackoverflow.com/questions/16398850/create-new-tmux-session-from-inside-a-tmux-session 
IOCTLCMDS_PATH="ioctlcmds.txt"
#export AFL_NO_AFFINITY=1

SESSION_NAME=$1
if [ -z $SESSION_NAME ]; then
  echo "usage: run-afl.sh SESSION_NAME"
  echo " use module name that you fuzz as SESSION_NAME"
  exit 0
fi

if [ ! -e $IOCTLCMDS_PATH ]; then
  echo "error: file $IOCTLCMDS_PATH does not exist, use ./symbex.py and then ./collect-ioctlcmds.sh to create it"
  exit 0
fi

tmux has-session -t $SESSION_NAME
if [ $? -eq 0 ]
then
  echo "error: session $SESSION_NAME aleady exist"
  exit 0
fi

echo "[+] Deleting \"output-*\" folders and \"recovered-*\" files"
rm -rf ./output-*
rm recovered-ioctlscheme-cmd-*
echo "[+] Creating new session "$SESSION_NAME""
tmux new-session -s $SESSION_NAME -d
tmux rename-window -t $SESSION_NAME:0 "base"

i=0
while read p; do
  #cmd=$(echo $p | cut -d: -f2 | tr -d " ") 
  cmd=$(echo $p | sed 's/\n//g') 
  #if [[ $cmd -ge 0xffff ]]; then  
    i=$((i+1))
    #echo "going to run the following command : ~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate-arm -c $cmd -f @@"
    outputdir="output-$cmd"
    #echo "[+] Creating output dir $outputdir"
    mkdir $outputdir
    echo "[+] [$i] Creating new window for cmd $cmd"
    #echo " Command: AFL_NO_AFFINITY=1 ~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o $outputdir -- ./emulate-arm -c $cmd -f @@"
    tmux rename-window -t "$SESSION_NAME:" $cmd

    #tmux new-window -t "$SESSION_NAME:" "AFL_NO_AFFINITY=1 ~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o $outputdir -- ./emulate-arm -c $cmd -f @@;read"
    #tmux new-window -t $SESSION_NAME:$i "AFL_NO_AFFINITY=1 ~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o $outputdir -- ./emulate-arm -c $cmd -f @@"
    #tmux new-window -t $SESSION_NAME: -d "echo $cmd;read"
    tmux new-window -t $SESSION_NAME:$i -d
    tmux send-keys -t $SESSION_NAME:$i "AFL_NO_AFFINITY=1 ~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o $outputdir -- ./emulate-arm -s ./memmappings/System.map -c $cmd -f @@" Enter
    tmux rename-window -t $SESSION_NAME:$i "$cmd"
    #sleep 2
  #~/LKM-fuzz/afl-unicorn/afl-fuzz -U -m none -i ./sample_inputs -o ./output -- ./emulate-arm -c $cmd -f @@
  #fi
done <$IOCTLCMDS_PATH

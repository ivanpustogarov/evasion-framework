#! /usr/bin/perl

use Net::OpenSSH;
use Time::HiRes qw( usleep );
use integer;
use Devel::GDB;
use File::Basename;
use Getopt::Std;
use Data::Dumper;
use IO::Select;
use IO::Socket::INET;

# We need these variables to login into the VM. We redirect
# the VM's serial port to tcp:localhost:VMPORT
# We need this additional communication interface because gdb
# crashes on condition breakpoins if ssh is used.
my $VMHOST=localhost;
my $VMPORT=6034;
my $NETCAT="./nc.traditional"; # obtained from here: https://packages.ubuntu.com/bionic/netcat-traditional
                            # reason: some nc implementation don't have '-q' flag
my $GDBMULTYARCH="../gdb-10.1/build/bin/gdb";
my $ARM_AS = "../compilers/arm-linux-androideabi-4.9/bin/arm-linux-androideabi-as";
my $ARM_OBJCOPY = "../compilers/arm-linux-androideabi-4.9/bin/arm-linux-androideabi-objcopy";

# Kernels
my $KERNEL_v3_4="../evasion-kernels/linux-3.4-evasion/arch/arm/boot/zImage"; # this one is a patched kernel that allows loading alien modules
my $KERNEL_v4_9="../evasion-kernels/linux-4.9.117-evasion/arch/arm/boot/zImage"; # this one is a patched kernel that allows loading alien modules
my $KERNEL_v4_9_ARM64="../evasion-kernels/linux-4.9.117-evasion-arm64/arch/arm64/boot/Image";

# Device trees
my $DEVICETREE_v3_4="../evasion-kernels/linux-3.4-evasion/arch/arm/boot/dts/vexpress-v2p-ca9.dtb";
my $DEVICETREE_v4_9="../evasion-kernels/linux-4.9.117-evasion/arch/arm/boot/dts/vexpress-v2p-ca15-tc1.dtb";
my $DEVICETREE_v4_9_ARM64="../evasion-kernels/precompiled/virt-gicv3.dtb";

# Root file systems
my $ROOTFS_FRESH="binary/arm-linux-3.4-buildroot.ext2.qcow2.fresh";
my $ROOTFS="binary/arm-linux-3.4-buildroot.ext2.qcow2";
my $ROOTFS_ARM64_FRESH="binary/rootfs-arm64.ext2.fresh";
my $ROOTFS_ARM64="binary/rootfs-arm64.ext2";
#my $KERNEL_APPEND = "\"console=ttyAMA0 root=/dev/mmcblk0 init=/sbin/init\"";
# These are not file paths, but just names of modules. You should put them inside './binary' folder
#my $DRV_NAME1="ebbchar.ko";

my $HOST_IP="192.168.99.37";
my $GUEST_IP="192.168.99.36";
my @spchars = qw(| / - \ );
my $QEMUPIDFILE = "qemu.pid";
my $QEMUPID = 0;
my $QEMU="../qemu-3.1.1/arm-softmmu/qemu-system-arm";
my $QEMU_ARM64="qemu-system-aarch64";

my $QEMUMEM = 16; # in MB
my $QEMUMEM32 = 32; # in MB
my $QEMUMEM128 = 128; # in MB
#my $QEMUCMD="$QEMU -M vexpress-a9 -dtb $DEVICETREE -smp 1 -m $QEMUMEM -kernel $KERNEL -append \"console=ttyAMA0 root=/dev/mmcblk0 init=/sbin/init\" -s -sd $ROOTFS -net nic,model=lan9118,netdev=net0 -netdev tap,id=net0,script=no,downscript=no,ifname=tap0 -pidfile $QEMUPIDFILE -daemonize -display none -qmp tcp:localhost:4444,server,nowait -serial tcp:$VMHOST:$VMPORT,server,nowait";

# Qemu launch commands
# arm32, kernel version 3.4
my $QEMUCMD_v3_4="$QEMU -M vexpress-a9  -dtb $DEVICETREE_v3_4 -smp 1 -m $QEMUMEM -kernel $KERNEL_v3_4 -append \"console=ttyAMA0 root=/dev/mmcblk0 init=/sbin/init\" -s -sd $ROOTFS -net nic,model=lan9118,netdev=net0 -netdev tap,id=net0,script=no,downscript=no,ifname=tap0 -pidfile $QEMUPIDFILE -daemonize -display none -qmp tcp:localhost:4444,server,nowait -serial tcp:$VMHOST:$VMPORT,server,nowait";
# arm32, kernel version 4.9
my $QEMUCMD_v4_9="$QEMU -M vexpress-a15 -dtb $DEVICETREE_v4_9 -smp 1 -m $QEMUMEM32 -kernel $KERNEL_v4_9 -append \"console=ttyAMA0 root=/dev/mmcblk0 init=/sbin/init\" -s -sd $ROOTFS -net nic,model=lan9118,netdev=net0 -netdev tap,id=net0,script=no,downscript=no,ifname=tap0 -pidfile $QEMUPIDFILE -daemonize -display none -qmp tcp:localhost:4444,server,nowait -serial tcp:$VMHOST:$VMPORT,server,nowait";
# arm64, kernel version 4.9, arm64
my $QEMUCMD_v4_9_ARM64="$QEMU_ARM64 -M virt,gic_version=3 -cpu cortex-a57 -machine type=virt -dtb $DEVICETREE_v4_9_ARM64 -smp 1 -m $QEMUMEM128 -hda $ROOTFS_ARM64 -kernel $KERNEL_v4_9_ARM64 -s -netdev tap,ifname=tap0,script=no,downscript=no,id=unet -device virtio-net,netdev=unet -append \"console=ttyAMA0 root=/dev/vda\"  -pidfile $QEMUPIDFILE -daemonize -display none -qmp tcp:localhost:4444,server,nowait -serial tcp:$VMHOST:$VMPORT,server,nowait";

# This command does not have -kernel and -dtb options, we'll add them after parsing command line args
#my $QEMUCMD_v3_4="$QEMU -M vexpress-a9 -smp 1 -m $QEMUMEM -s -sd $ROOTFS -net nic,model=lan9118,netdev=net0 -netdev tap,id=net0,script=no,downscript=no,ifname=tap0 -pidfile $QEMUPIDFILE -daemonize -display none -qmp tcp:localhost:4444,server,nowait -serial tcp:$VMHOST:$VMPORT,server,nowait -append $KERNEL_APPEND";


my $TEST_PROGRAM="./testprogram/sample-ioctl";
my $TEST_PROGRAM_ARM64="./testprogram-arm64/sample-ioctl";
#my $MY_UNIQUE_IOCTL_CMD=12345;
#my $MY_UNIQUE_IOCTL_CMD=3221513217;
my $MY_UNIQUE_IOCTL_CMD=0x12345678;
my $BP_CONDITION = "if \$r1==$MY_UNIQUE_IOCTL_CMD";
my $BP_CONDITION_ARM64 = "if \$x1==$MY_UNIQUE_IOCTL_CMD";
#my $BP_CONDITION = "";

# emulat-arm will use these files
my $KERNELMAPPING_PATH   = "./emulation/memmappings/kernel_page_tables.txt";
my $USRSPACE_MEMMAP_PATH = "./emulation/memmappings/usrspace_memmap.txt";
my $SYSTEMMAP_PATH       = "./emulation/memmappings/System.map";
my $QMP_REGISTERS_PATH   = "./emulation/registers/qmp-registers.txt"; # used for arm32. TODO: move to gdb registers
my $GDB_REGISTERS_PATH   = "./emulation/registers/gdb-registers.txt"; # used for arm64
my $GDB_LOGFILE          = "./emulation/gdb.txt";

sub check_tap
{
  system("ip addr list dev tap0 | grep \"$HOST_IP\"");
  #print "$?\n";
  if ($? != 0) {
    print "error: tap0 either does not exist or has not been assigned an address\n";
    #print "Try: 'sudo ip address add $HOST_IP/24 dev tap0'\n";
    print "Try: 'sudo ./prepare-tap.sh'\n";
    exit 0;
  }
}

sub spinner
{
  $timeout = shift;
  $msg_progress = shift;
  $msg_done = shift;
  $oldbuffering = $|;
  $|++; # turn off output buffering;
  
  my @chars = qw(| / - \ );
  
  my $i = 0;
  
  print $chars[$i];
  
  print "[|] $msg_progress\r";
  while ($timeout) 
  {
    print "[", $chars[++$i % @chars], "] $msg_progress\r";
    $timeout--;
    sleep 1;
  }
  print "[+] $msg_done\n";
  $| = $oldbuffering;
}


# Sources: https://www.perlmonks.org/bare/?displaytype=displaycode;abspart=1;node_id=95351;part=1
#          https://www.perlmonks.org/bare/?node_id=427056
sub netcat
{

  my $req = shift;
  my $output = "";

  my $old_buffering = $|;
  $| = 1;

  my $sel = IO::Select->new();
  my $socket = new IO::Socket::INET (
      PeerHost => $VMHOST,
      PeerPort => $VMPORT,
      Proto => 'tcp'
  );
  unless($socket) {
      print "couldn't connect to the server\n";
  }
  
  $sel->add($socket);
  my $buf;
  
  # data to send to a server
  my $message = $req. "\n";
  #print "[+] Sending $message";
  my $size = $socket->send($message);
  my $timeout = 0.1;
  my $sock;
  
  #print "[+] Output follows\n";
  while (1) {
    if (my @socks = $sel->can_read($timeout)) {
      $sock = shift(@socks);
      my $return=$sock->sysread($buf,512); 
      if (!defined($return)) {
           # undef from sysread means an error
           print "error: $!\n";
           $sel->remove($sock);
           $sock->close;
      } elsif ($return == 0) {
           # 0 from sysread means the connection was closed
           print "socket was closed\n";
           $sel->remove($sock);
           $sock->close;
      } else {
           # a positive int from sysread means
           # we got some data
           #print "read $return bytes from a socket [$buf]\n";
           #print "$buf";
	   $output = $output . $buf;

      }
    } else {
       #printf("Timed out, socket connection status (all data received?): %d\n",
       #                 defined($sock->connected()));
       last;
    }
  }
  $| = $old_buffering;
  return $output;
}


sub copy_and_load_module
{
  my $ssh = shift;
  my $module_name = shift;
  if (not -e "binary/$module_name")
  {
      stop_qemu($ssh);
      die "error: file binary/$module_name does not exist";
  }
  # Copy modules
  $ssh->scp_put("binary/$module_name");
  # Try to load the module
  my $out = $ssh->capture("insmod $module_name");
  if ($ssh->error) {
    print "[-] There was an error loading the module (was it loaded already?). Continuing anyways.\n";
  }
  $out = $ssh->capture("lsmod");
   
    #{die "problem with SSH connection: ". $ssh->error;}
  print "$out\n";
}

sub copy_and_run_sample_program
{
  my $ssh = shift;
  my $program_name = shift;
  if (not -e "binary/$program_name")
    {die "error: file binary/$program_name does not exist";}
  $ssh->scp_put("binary/$program_name");
  my $out = $ssh->capture("./$program_name");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}
  return "$out";
}

# Create a characater device file and issue 'cat vidc' command
sub parse_stack_trace
{
  my $funcname = undef;
  my $offset = undef;
  #   # Get the kernel logs before we load the modules
  #   $ssh->scp_get("/var/log/messages", "dmesgold");

  #   $ssh->system("mknod vidc c 252 0");
  #   $ssh->system("cat vidc");

  #   # Get the kernel logs after we loaded the modules
  #   $ssh->scp_get("/var/log/messages", "dmesgnew");

  my $diff = `diff -u dmesgold dmesgnew`;
  print $diff;
  foreach (split(/\n/, $diff)) 
  {
    $line = $_;
    #print "$line\n";
    # +Nov 30 05:59:42 buildroot kern.warn kernel: [<803a7be4>] (mutex_lock+0x1c/0x34) from [<7f01c8dc>] (res_trk_check_for_sec_session+0x14/0x2c [vidc]) 
    if ($line =~ m/\[vidc\]/)
    {
      print ">>> $line\n";
      # regex for something like this: 'from [<7f01c8dc>] (res_trk_check_for_sec_session+0x14'
      $line =~ /from \[<[a-f0-9]+>\] \(([a-z0-9_]+)\+(0x[a-f0-9]+)/;
      ($funcname,$offset) = ($1,$2);
      #print "$funcname $offset\n";
      last;
    }
    #if (/START/../END/) 
    #{
    #  next if /START/ || /END/;
    #  print;
    #}
   }
   return ($funcname, $offset);
}

sub start_qemu
{
  #print "$QEMUCMD\n";
  #exit(0);

  # Run Qemu
  print "[+] Restoring fresh virtual hard drives. Ignore audio errors messages (if any).";
  system("cp $ROOTFS_FRESH $ROOTFS");
  system("cp $ROOTFS_ARM64_FRESH $ROOTFS_ARM64");
  #print "$QEMUCMD\n";
  system($QEMUCMD);
  open my $stderr_fh, '>', '/tmp/lkmhost.err' or die "Cannot ssh stderr file";
  open my $stdout_fh, '>', '/tmp/lkmhost.log' or die "Cannot ssh stdout file";

  # Spin until we establish an ssh connection to Qemu
  my $i = 0;
  my $ssh;
  $oldbuffering = $|;
  #$|++; # turn off output buffering;
  do {
    print "[", $spchars[++$i % @spchars], "] Starting Qemu\r";
    $ssh = Net::OpenSSH->new("root:1\@$GUEST_IP", default_stderr_fh => $stderr_fh, default_stdout_fh => $stdout_fh, master_opts => [-o => "UserKnownHostsFile=/dev/null", -o => "StrictHostKeyChecking=no"]);
    sleep 1;
    #usleep(500);
  } while ($ssh->error);
  #$| = $oldbuffering;

  # Save PID, so that we can kill Qemu later
  open my $file, '<', $QEMUPIDFILE; 
  chomp($QEMUPID = <$file>); 
  close $file;

  print "[+] Qemu started wth PID $QEMUPID       \n";
  # Login over serial before starting gdb. Otherwise gdb will crash :(
  system("echo root | $NETCAT -q1 $VMHOST $VMPORT");
  sleep 1;
  system("echo 1 | $NETCAT -q1 $VMHOST $VMPORT");
  sleep 1;
  # Disable ASLR
  $ssh->system("echo 0 > /proc/sys/kernel/randomize_va_space");

  return $ssh;
}

sub stop_qemu
{
  $ssh = shift;
  #$ssh->system("poweroff");
  netcat("poweroff");
  my $i = 0;
  sleep 5;
  kill 'SIGKILL', $QEMUPID;
  
  #my $exists = kill 0, $QEMUPID;
  #while($exists) {
  #  print "[", $spchars[++$i % @spchars], "] Stopping Qemu\r";
  #  usleep(500); 
  #  $exists = kill 0, $QEMUPID;
  #  #print("Stil exissts $QEMUPID\n");
  #}
 
  print "[+] Qemu stopped    \n";

  #do {
  #  sleep 0.5;
  #spinner(2, "shutting down Qemu...", "Qemu stoped                  ");
}


#sub get_kallsyms
#{
#  $ssh = shift;
#  $ssh->scp_get("/proc/kallsyms", "System.map");
#  if ($ssh->error)
#    {die "problem with SSH connection: ". $ssh->error;}
#}

sub get_kernel_memory_map
{
  $ssh = shift;
  (my $sysmap_filename_at_host, my $kernmap_filename_at_host) = ($SYSTEMMAP_PATH, $KERNELMAPPING_PATH);
  (my $sysmap_filename_at_guest, my $kernmap_filename_at_guest) = ("System.map", "kernel_page_tables.txt");

  # Delete old files both locally and on the remote machine
  unlink $sysmap_filename_at_host, $kernmap_filename_at_host;
  $ssh->system("rm -rf $sysmap_filename_at_guest");
  $ssh->system("rm -rf $kernmap_filename_at_guest");

  # Copy kernel memory map from guest's debugfs
  ## Create a folder on guest if it does not exist yet. This will the mount point for debugfs
  $ssh->system("mkdir -p ./debug");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}
  ## Mount debugfs (unmount in case it was mounted already. This can happen if we reuse already running guest)
  $ssh->system("umount ./debug/");
  $ssh->system("mount -t debugfs none ./debug/");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}

  ## Copy debugfs file to a local file at guest. We need this additional copy
  ## operation becuase using scp on debugs directly returns an empty file
  $ssh->system("cp ./debug/kernel_page_tables $kernmap_filename_at_guest");
  if ($ssh->error)
    {die "problem with SSH connection when trying to copy ./debug/kernel_page_tables: ". $ssh->error;}
  ## Copy kernel map file from guest to host
  $ssh->scp_get("./$kernmap_filename_at_guest", "$kernmap_filename_at_host");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}

  # Copy kernel symbol table (kallsyms or sysmap)
  ## Copy proc file to a local guest file. We need this additional copy
  ## operation becuase using scp on procfs directly returns an empty file
  $ssh->system("cp /proc/kallsyms $sysmap_filename_at_guest");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}
  ## Copy symbol table file from guest to host
  $ssh->scp_get("./$sysmap_filename_at_guest", "$sysmap_filename_at_host");
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}

  #return ("System.map", "kernel_page_tables.txt");
  return ("$sysmap_filename_at_host", "$kernmap_filename_at_host");

}

sub get_userspace_memory_map
{
  my $ssh = shift; 
  my $testprogram = shift; 
  $testprogram= basename($testprogram); 
  #my $out_filename = "usrspace_memmap.txt";
  my $out_filename = $USRSPACE_MEMMAP_PATH;

  # Delete old file both locally and on the remote machine
  unlink $out_filename;


  #system("echo ./$testprogram | nc -q1 $VMHOST $VMPORT >  $out_filename");
  my $output = netcat("./$testprogram");
  open(my $fh, '>', "$out_filename") or die "Could not open file '$out_filename'";
  print $fh $output;
  close $fh;

  return $out_filename;
}

# @return Address of the corresponding function in System.map (hex number without '0x' prefix)
# @type string
sub extract_address
{
  $filename = shift;
  $func_name = shift;
  #print "[DEBUG] extract_address(): searching for \"$func_name\" in file \"$filename\"\n";
  open my $fh, '<', $filename or die;
  while (my $line = <$fh>) {
    if ($line =~ /([a-f0-9]*) [tdbrBtTW] $func_name[ \t\n]/) {
      #print "$line";
      close $fh;
      return $1;
    }
  }
  close $fh;
  return undef;
}

# Create a gdb script based on kernel memory map that would dump guest memory
# once it reaches the breakpoint
#
# @param kernmap_filename File with guest memory map (from debugfs)
# @type string
# @param bp_address1 Address of sys_ioctl. Gdb will set the breakpoin at this address (a hex string without '0x' prefix)
# @type string
# @param bp_address2 Address of module's ioctl handler. Can be undefined. If defined, Gdb will set the breakpoin at this address (a hex string without '0x' prefix)
# @type string
# @param bp_condition Gdb will trigger the breakpoint only if this condition is met
#                     This is used to distinguish entrance to sys_ioctl/sys_write from
#                     other entrances e.g. by the terminal. (you don't need the condition
#                     if the breakpoint is set inside the module, as cannnot be triggered
#                     by anything but your program)
# @type string
# @type string
# @return $output_filename Path to the generated gdb script
# @type string
sub create_gdb_memdump_script
{
  #my $output_filename = "/tmp/memdumppart.gdb";
  my $output_filename = "./emulation/memdumppart.gdb";
  my $kernmap_filename = shift; 
  my $usrspacemap_filename = shift;
  my $sys_ioctl_address = shift; # sys_ioctl
  my $ioctl_address = shift; # module's ioctl. Can be undef
  my $bp_condition = shift; 
  my $bits = shift; # type: integer, either <32> for arm32, or <64> for arm64, we use it to set arch for gdb
  my $sysmap_filename = shift;

  open(my $fh_out, '>', $output_filename);
  open(my $fh_in_kernel, '<', $kernmap_filename);
  open(my $fh_in_userspace, '<', $usrspacemap_filename);

  # First, put static stuff
  if($bits==32) {
    printf($fh_out "set architecture arm\n");
  } elsif ($bits==64) {
    printf($fh_out "set architecture aarch64\n");
  } else {
    die("BUG: bits should be either 32 or 64\n");
  }
  printf($fh_out "target remote localhost:1234\n");
  printf($fh_out "set height 0\n");
  printf($fh_out "set logging overwrite on\n");
  printf($fh_out "set logging file $GDB_LOGFILE\n");
  printf($fh_out "set logging on\n");
  #printf($fh_out "echo \"gdb says hi\"\n");
  #printf($fh_out "set logging redirect\n");
  #printf($fh_out "set logging off\n");
  #printf($fh_out "set logging on\n");
  #printf($fh_out "set logging debugredirect on\n\n");
  #printf($fh_out "set logging off\n");
  #printf($fh_out "set logging on\n");

  # If module's ioctl handler was specified, we need to add an additional transient breakpoint for sys_ioctl
  my $command_n = 1;
  if(defined($ioctl_address))
  {
    # By some reason without setting another breakpont in the kernel space (not
    # inside the module), the actual module breakpoint does not work
    printf($fh_out "b *0x$sys_ioctl_address $bp_condition\n");
    printf($fh_out "commands 1\n");
    printf($fh_out " echo \"kernel space breakpoint reached\"\n");
    printf($fh_out " continue\n");
    printf($fh_out "end\n");
    printf($fh_out "\n");
    $command_n = $command_n+1;
  }

  # Now goes the breakpoint inside the module
  # and let's add 'dump binary memory' gdb commands based on the guest's memory map
  #printf($fh_out "b *0x$bp_address $bp_condition\n");
  #printf($fh_out "b *0x$ioctl_address\n");
  if(defined($ioctl_address)) { # If ioctl hander was defined then put the second, real,  breakpoint
    printf($fh_out "tb *0x$ioctl_address\n");
  } else {
    printf($fh_out "b *0x$sys_ioctl_address $bp_condition\n"); # if iotclt handler was not specified, then we will have one breakpoint at sys_ioctl
  }
  printf($fh_out "commands $command_n\n");
  printf($fh_out "  echo \"module breakpoint reached\"\n");
  printf($fh_out "  info registers\n"); # to collect coprocessor registers into gdb.txt
  $command_n = $command_n+1;

  # Dump kernel memory
  while (<$fh_in_kernel>)
  {
     chomp;
     # We look for lines like this: "0x7f000000-0x7f001000           4K     RW x  SHD MEM/CACHED/WBWA"
     #           ($1= _start_)  ($2 = _end_)    ($3 _size_)  ($4 _units_)
     next if (!m/0x([a-f0-9]*)-0x([a-f0-9]*)[ \t]*([0-9]*)([KMBG])/);
     my $start = $1;
     my $end = $2;
     my $size = $3;
     my $units = $4;
     #if("$units" eq "G") {
     #  #$end = hex($start) + 15*(2**20);
     #  #$end = sprintf("%x", $end);
     #  $start = hex($end) - 50*(2**20);
     #  $start = sprintf("%x", $start);
     #  print "     warning: create_gdb_memdump_script: line <$_>\n";
     #  print "                                    size is too big, truncating start boundary to 0x$start (30MB)\n";
     #}
     
     # This is an ad-hoc hack to fight Qemu's bug (and prevent it from segfaulting)
     # Hope they'll fix this bug in future versions of Qemu
     if("$start" eq "f8200000")
     {
       print "     warning: create_gdb_memdump_script: applying a fix for address\n";
       print "              0x$start due to Qemu bug when accessing MMIO\n";
       next;
     }
     # The following ranges seem to be very large (>= physical memory), seems they are not
     # used, but this requires further investigation
     if( (hex($start) >= 0x83000000) && (hex($end)-hex($start) >= 0x2000000)) # 0x2000000 = 32Mb
     {
       print "     warning: NOT skipping unused large range\n";
       print "              0x$start - 0x$end ($size $units)\n";
       #next;
     }
      
     printf($fh_out "  dump binary memory emulation/memdumps/%x-%x.dump 0x%x 0x%x\n", 
                                 hex($start), hex($end), hex($start), hex($end));
  }


  # Dump userspace memory (ASLR was disabled in start_qemu())
  # We don't dump user space for arm64. TODO: disable it for arm32 too
  my $usr_exists = 0;
  my $dump_userspace = 0;
  while (<$fh_in_userspace>)
  {
     next if ($bits==64);
     next if ($dump_userspace==0); # TODO: it is a temporary way to disable dumpting userspace memory, we don't need it. Just remove this code block in the future.
     chomp;
     # Skip vectors, they point to kernel space and we dumped them already
     next if (m/vectors/);
     # Skip the heap, and vsdo-related mappings, all we need is in the data section 
     next if (m/heap/);
     next if (m/sigpage/);
     next if (m/vvar/);
     next if (m/vdso/);
     # We look for lines like this: "00010000-00011000 r-xp 00000000 b3:00 9613       /root/cci-cve-2014-9783"
     #           ($1= _start_)  ($2 = _end_)    ($3 _permissions_)
     next if (!m/([a-f0-9]*)-([a-f0-9]*) ([rwxp-]*)/);
     my $start = $1;
     my $end = $2;
     $usr_exists = 1;
     # The stack memory will not be mapped wholy yet by the kernel (due to
     # on-demand memory allocation), so let's extract only the bottom-most page
     if (m/stack/)
     {
       $start = hex($end)-0x1000;
       $start = sprintf("%x", $start);
       #print "$start\n";
       #print "$end\n";
     }
     printf($fh_out "  dump binary memory emulation/memdumps/%x-%x.dump 0x%x 0x%x\n", 
                                 hex($start), hex($end), hex($start), hex($end));
  }

  # if we need to dump userspace memory && we don't have userspace mapping && we are working with ar32
  if( ($dump_userspace==1) && ($usr_exists==0) && ($bits==32) )
    {die "your test program does not print its memory map";}

  printf($fh_out "  shell sleep 3\n");

  if($bits==32) {
    printf($fh_out "  shell echo -e '{ \"execute\": \"qmp_capabilities\" }\\n{\"execute\": \"human-monitor-command\", \"arguments\": { \"command-line\": \"info registers\" } }' | $NETCAT 127.0.0.1 4444 > emulation/registers/qmp-registers.txt\n");
    printf($fh_out "  shell sleep 2\n");
    ## Dump (coprocessor) registers with gdb
    #printf($fh_out "  info registers\n"); # to collect coprocessor registers into gdb.txt
    printf($fh_out "  shell sleep 3\n");
    printf($fh_out "end\n");
  }
  if($bits==64) {
    # In the case of arm64, gdb can't dump coprocessor registers, so we need to use evasion kernel's custom code
    # the code is like this:
    #   dump_cpregs_addr:
    #     mrs     x0, sp_el0
    #     mrs     x0, tpidr_el0
    #     nop
    printf($fh_out "  info registers\n");
    my $dump_cpregs_addr = extract_address($sysmap_filename, "dump_cpregs");
    my $dump_cpregs_endaddr = hex($dump_cpregs_addr)+8; # pint to 'nop'
    #printf($fh_out "  set \$pc=0x$dump_cpregs_addr\n");
    #printf($fh_out "  printf \"sp_el0=0x%%lx\\n\", \$x0\n");
    #printf($fh_out "  printf \"pc=0x%%lx\\n\", \$pc\n");
    printf($fh_out "  jump *0x$dump_cpregs_addr\n");
    printf($fh_out "  continue\n");
    printf($fh_out "end\n");
    printf($fh_out "\n");

    # breakpoint at the end of dump_cpregs
    my $hex = sprintf("0x%x", $dump_cpregs_endaddr);
    printf($fh_out "b *$hex\n");
    printf($fh_out "commands $command_n\n");
    $command_n = $command_n+1;
    printf($fh_out "  printf \"sp_el0=0x%%lx\", \$x17\n");
    printf($fh_out "  printf \"tpidr_el0=0x%%lx\", \$x18\n");
    printf($fh_out "  set \$pc=0x$ioctl_address\n");
    #printf($fh_out "  jump *0x$ioctl_address\n");
    #printf($fh_out "  quit\n");
    printf($fh_out "end\n");
  }
  #printf($fh_out "  shell sleep 3\n");
  #printf($fh_out "end\n");
  printf($fh_out "\n");
  #printf($fh_out "echo \"we continue now\"\n");
  printf($fh_out "continue\n");

  close $fh_in_kernel;
  close $fh_in_userspace;
  close $fh_out;

  return $output_filename;
}

# Dump memory using the corresponding gdb script and test program
# Then dump registers and continue running the guest
# 
# @param gdbscript GDB scirpt that contains 'dump memory binary' commands
# @type string
# @param testprogram Test program that would trigger the breakpoint in the gdb script
# @type string
# @param ssh SSH connection to the guest
# @type Net::OpenSSH
sub dump_guest_memory
{
  my $gdbscript = shift;
  my $testprogram = shift;
  my $dev_fname = shift;
  my $ssh = shift;

  #my $n_dumps = `grep -c "dump binary memory" /tmp/memdumppart.gdb`;
  my $n_dumps = `grep -c "dump binary memory" $gdbscript`;
  chomp($n_dumps);
  
  # Delete all dumps
  #print "[INFO] Deleting old memdumps\n";
  mkdir("emulation/memdumps")
           or $!{EEXIST}   # Don't die if folder already exists.
           or die("Can't create directory \"emulation/memdumps\": $!\n");
  mkdir("emulation/registers")
           or $!{EEXIST}   # Don't die if the folder already exists.
           or die("Can't create directory \"emulation/registers\": $!\n");
  unlink glob "'emulation/registers/*'";
  unlink glob "'emulation/memdumps/*'";
  unlink "emulation/gdb.txt";

  #print "[INFO] Creating gdb session\n";
  #my $gdb = new Devel::GDB('-execfile' => 'gdb-multiarch', '-params' => '-q');
  #my $gdb = new Devel::GDB('-execfile' => $GDBMULTYARCH);
  my $gdb = new Devel::GDB('-execfile' => $GDBMULTYARCH, '-params' => '-q');

  # Register the script that sets breakpoints/dumps memory
  #print $gdb->send_cmd("source $gdbscript");
  #exit(1);
  $gdb->send_cmd("source $gdbscript");
  #print "\n";
  
  # Run the program to trigger the previously set breakpoints

  # After this command triggers the breakpoint, the gdb script should do all the work
  $testprogram = basename($testprogram); # In case the testprogram name contains full path
  print "[INFO] Running test program: ./$testprogram $dev_fname\n";
  system("echo \"./$testprogram $dev_fname\" | $NETCAT -q1 $VMHOST $VMPORT");
  #$ssh->system({async => 1}, "./$testprogram");
  #my $out = $ssh->capture($testprogram);
  #print " -- hi, $out\n";
  #print "-- hi\n";

  # Wait until 'emulation/registers/qmp-registers.txt' is created, which is an indication that gdb script finished
  my $i = 0;
  my $num_entries = 0;
  #$registersdumpfile = "emulation/registers/qmp-registers.txt"; <<< getting QMP registers with gdb does not work for some reason
  #while(! -f $registersdumpfile) {
  while($num_entries != $n_dumps) {
    print "[", $spchars[++$i % @spchars], "] Dumping memory regions and registers: $num_entries/$n_dumps\r";
    $num_entries = `ls -1 emulation/memdumps/ | wc -l`;
    chomp($num_entries);
    #usleep(500); 
    sleep 1; 
  }
  $num_entries = `ls -1 emulation/memdumps/ | wc -l`;
  chomp($num_entries);
  print "[+] Dumping memory regions and registers: $num_entries/$n_dumps\n";
  print "[+] Memory and registers dumped                    \n";
  # Detach gdb 
  #$gdb->send_cmd("continue");
  sleep 3;  # wait until we execute assembly code that reads coprocessor registers. TODO: check 'tpidr_el0' in gdb.txt instead
  $gdb->end;
}

sub usage
{
  print("$0 [OPTIONS] -m module.ko[,module2.ko,...] -i ioctlhandler -p testprogram\n");
  print "\n";
  print "OPTIONS:\n";
  print "  -m List of module names to analyze, separated by ',' (should be in ./binary folder)\n\n";
  #print "  -p Test program to trigger IOCTL (should be in ./binary folder)\n\n";
  print "  -p 'dev' file created by the module (e.g. '/dev/xxx')\n\n";
  print "  -i Name of the IOCTL handler in the driver\n";
  print "     If specified, the memory dump will be collected at the\n";
  print "     entry of this function. If you want to collect the dump at the start\n";
  print "     of 'sys_ioctl' ommit this argument\n\n"; 
  print "  -k Alient kernel version ('3.4', '4.9',  or '4.9_arm64', default is '3.4')\n\n";
  #print "You can also change some defaults (NOT IMPLEMENTED!):\n";
  #print "  -k Path to Linux kernel (default is '$DEFAULT_KERNEL_v3_4')\n\n";
  #print "  -r Path to rootfs (default is '$ROOTFS')\n\n";
  #print "  -d Path to device tree file (default is '$DEFAULT_DEVICETREE_v3_4')\n\n";
  print "EXAMPLES:\n\n";
  print "./prepare-emulation-arm.pl -m \"msm-injected.ko,msm_isp_module-injected.ko\" -p \"/dev/v4l-subdev0\" -i msm_isp_ioctl\n";
  print "./prepare-emulation-arm.pl -m \"msm-injected.ko,msm_isp_module-injected.ko\" -p \"/dev/v4l-subdev0\"\n";

}


# Split comma-separated list of modules into an array
#
# @param concatenated Modules separated by comman (e.g. path1/module1.ko,path2/module2,ko)
# @type String
# @return Array of module names
sub get_modules_names_from_arg
{
  my $concatenated = shift;
  my @modules = split(/,/, $concatenated);
  return @modules;
}


# Generated assembly code that will restore coprocessor
# registers for arm64:
#        msr     sp_el0, x1
#        msr     tpidr_el0, x1
sub generate_cpregs_code_arm64
{
  my $setup_cpregs_S="./emulation/setup_cpregs.S";
  open(my $fh, '>', "$setup_cpregs_S") or die "Could not open file '$setup_cpregs_S' for writing";
  
  my $header= ".section .text\n.global _start\n\n_start:\n";
  print $fh $header;

  my $code;
  my $sp_el0_val = `cat $GDB_REGISTERS_PATH | grep sp_el0 | cut -f2 -d' '`;
  chomp($sp_el0_val);
  my $tpidr_el0_val = `cat $GDB_REGISTERS_PATH | grep tpidr_el0 | cut -f2 -d' '`;
  chomp($tpidr_el0_val);

  # We use x1 and x2 registers here since they will be written again in 'prepare_fuzz_ioctl()' in emulate-arm64
  # https://thinkingeek.com/2016/11/13/exploring-aarch64-assembler-chapter-5/ , section 'Load a literal address'
  $code =         "ldr x1, sp_el0_val_addr\n";
  $code = $code . "msr sp_el0, x1\n";
  $code = $code . "ldr x1, tpidr_el0_val_addr\n";
  $code = $code . "msr tpidr_el0, x1\n";
  $code = $code . "nop\n"; # just for debug purposes in emulate-arm-64
  $code = $code . "sp_el0_val_addr : .dword $sp_el0_val\n";
  $code = $code . "tpidr_el0_val_addr : .dword $tpidr_el0_val\n";
  print $fh $code;

  close $fh;

}

# Generated assembly code that will restore coprocessor for arm32
# ldr r1, =#0x162d000
# mcr p15, 0, r1, cr13, cr0, 4
sub generate_cpregs_code_arm32
{
  system("cd emulation && ./generate-cpregs-read-code.pl > setup_cpregs.S");
}

sub main
{
  # ** Check if tap0 interface is up, we attach Qemu to it, and use it for ssh'ing into Qemu
  check_tap();

  #my $alien_kernel = "";
  #my $alien_dtb = "";
  my $alien_kernel_version = "";
  my $testprogram = $TEST_PROGRAM;
  my $bits = 32; # arm32 or arm64

  # ** Parse command line args
  my $ret = getopts('m:p:i:k:r:d:h', \%opts);
  if (not $ret)
  {
    usage();
    exit(0);
  }
  if(exists($opts{"h"}))
  {
    usage();
    exit(0);
  }
  if(not exists($opts{"m"}))
  {
    print "error: module name is required ('-h' for usage)\n";
    exit(0);
  }
  if(not exists($opts{"p"}))
  {
    print "error: 'dev' file is required to generate a program that triggers the IOCTL ('-h' for usage)\n";
    exit(0);
  }

  my @modules = get_modules_names_from_arg($opts{"m"});

  my $ioctlhandler = "";
  if(exists($opts{"i"})) {
    $ioctlhandler = $opts{"i"};
  } else {
    undef $ioctlhandler;
  }


  if(exists($opts{"k"})) {
    $alien_kernel_version = $opts{"k"};
  } else {
    undef $alien_kernel_version;
  }
  if( (not defined($alien_kernel_version)) or ($alien_kernel_version eq "3.4")) { 
    $QEMUCMD = $QEMUCMD_v3_4;
  } elsif ($alien_kernel_version eq "4.9") { 
    $QEMUCMD = $QEMUCMD_v4_9;
  } elsif ($alien_kernel_version eq "4.9_arm64") { 
    $QEMUCMD = $QEMUCMD_v4_9_ARM64;
    $testprogram = $TEST_PROGRAM_ARM64;
    $bits=64;
  } else {
    print "error: alien version is not supported ('-h' for usage)\n";
    exit(0);
  }

  my $dev_fname = $opts{"p"};

  # ** Check if modules and test program exist in the './binary' folder
  foreach (@modules)
  {
    if(not -e "./binary/$_"){
       print("error: module '$_' was not found in './binary' folder\n");
       exit(0);
    }
  }

  #foreach (@modules) {
  #  print " -- $_\n";
  #}
  #print Dumper(\%opts);
  #exit(0);

  $ssh = start_qemu();

  foreach (@modules) {
    print "[+] Copying and loading modules\n";
    print "    -- $_\n";
    copy_and_load_module($ssh, $_); # The module should be in ./binary folder. No segfaults are expected in this function yet
    sleep 3;
  }

  print "[+] Copying test program: $testprogram\n";
  $ssh->scp_put("$testprogram") or die "$ssh->error";
  if ($ssh->error)
    {die "problem with SSH connection: ". $ssh->error;}

  print "[+] Getting kernel memory map/kallsyms\n";
  ($sysmap_filename, $kernmap_filename) = get_kernel_memory_map($ssh);
  print "[+] Extracting the address of the ioctl handler you want to fuzz\n";
  #$bp_address = extract_address($sysmap_filename, "msm_cci_subdev_ioctl");
  my $bp_address1 = extract_address($sysmap_filename, "sys_ioctl");
  my $bp_address2 = 0;
  if(defined($ioctlhandler)) {
    $bp_address2 = extract_address($sysmap_filename, $ioctlhandler);
    if(!defined($bp_address2)) {
      print "error: could not find symbol $ioctlhandler in file '$sysmap_filename'\n";
      stop_qemu($ssh);
      exit(0);
    }
    print "    $ioctlhandler was loaded to at address 0x$bp_address2\n";
  } else {
    undef $bp_address2;
  }

  # At this point ASLR should be disabled (it is done inside start_qemu())
  # Let's get our progrm's memory mapping. The same program that triggers the
  # ioctl should print it's mapping to the stdout for this to work
  print "[+] Getting userspace memory maps\n";
  $usrspacemap_filename = get_userspace_memory_map($ssh, $testprogram);

  print "[+] Generating gdb scripts...\n";
  my $bp_condition;
  if($bits==32) {
    $bp_condition = $BP_CONDITION; # This is to distinguish the sys call issued by our test program from sys calls by other programs (e.g. the terminal)
  } elsif($bits==64) {
    $bp_condition = $BP_CONDITION_ARM64; # This is to distinguish the sys call issued by our test program from sys calls by other programs (e.g. the terminal)
  }
  my $gdbscript_path = create_gdb_memdump_script($kernmap_filename, $usrspacemap_filename,
                                                 $bp_address1, $bp_address2, $bp_condition, $bits, $sysmap_filename);
  print "    file '$gdbscript_path' generated\n";


  print "[+] gdb'ing to Qemu and taking the memdump (gdb output follows)\n";
  dump_guest_memory($gdbscript_path, $testprogram, $dev_fname ,$ssh);

  stop_qemu($ssh);

  #Generate binary code to set coprocessors in emulate-arm
  if ($bits==32) { 
    print "[+] Postprocessing emulation/gdb.txt for coprocessor registers\n"; 
    unlink "emulation/cpregs-from-gdb.txt";
    #system("sed -n '/\~\"[A-Za-z0-9_]* *0x[0-9a-f]*\"/p' $GDB_LOGFILE  | tr -d '~\"' > emulation/cpregs-from-gdb.txt");
    system("sed -n '/\~\"[A-Za-z0-9_]* *0x[0-9a-f]*/p' $GDB_LOGFILE  | tr -d '~\"' | tr -s ' ' | cut -f1,2 -d' ' > emulation/cpregs-from-gdb.txt");
    print "[+] Generating coprocessor registers setup code\n";
    unlink "emulation/setup_cpregs.S";
    unlink "emulation/setup_cpregs.o";
    unlink "emulation/setup_cpregs.bin";
    generate_cpregs_code_arm32();
    system("cd emulation && ../$ARM_AS setup_cpregs.S -o setup_cpregs.o");
    system("cd emulation && ../$ARM_OBJCOPY -O binary setup_cpregs.o setup_cpregs.bin");
    print "    setup_cpregs.bin generated\n";
  }

  #Generate binary code to set coprocessors in emulate-arm64
  if ($bits==64) { 
    print "[+] Postprocessing emulation/gdb.txt for registers\n"; 
    my $regs_regex = q("~\"(x[0-9]{1,2}|sp|pc)"); # like this: ~"x5             0x4000"
    my $cpregs_regex = q("~\"(sp_el0|tpidr_el0)"); # like this: ~"sp_el0=0xffff800004858000"
    system("grep -E -e $regs_regex -e $cpregs_regex $GDB_LOGFILE | tr -d '\"~' | tr '=' ' ' | tr -s ' ' > $GDB_REGISTERS_PATH");
    print "    '$GDB_REGISTERS_PATH' generated\n";
    print "[+] Generating coprocessor registers setup code\n";
    unlink "emulation/setup_cpregs.S";
    unlink "emulation/setup_cpregs.o";
    unlink "emulation/setup_cpregs.bin";
    generate_cpregs_code_arm64();
    system("cd emulation &&  aarch64-linux-gnu-as setup_cpregs.S -o setup_cpregs.o");
    system("cd emulation &&  aarch64-linux-gnu-objcopy -O binary setup_cpregs.o setup_cpregs.bin");
    print "    setup_cpregs.bin generated\n";
  }
  
  print("[+] All done.\n");
  print("    Dumps are in 'emulation/memdumps' and 'emulation/registers'\n");
  print("    Memory maps (user space, kernel space, and kallsysm (or System.map) are in ./emulation/memmappings/\n");
  print("    Use 'emulation/dumps2elf/dumps2elf.pl' if you want to convert memdumps to an elf image (for symbex)\n");

}

main();

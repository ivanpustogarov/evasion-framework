#! /usr/bin/perl

use strict;
use warnings;
use feature qw(say);
use File::Slurp;

my $QEMUREGS_PATH="cpregs-from-qemu.txt";
my $GDBREGS_PATH="cpregs-from-gdb.txt";

# IMPORTANT NOTE: we set the scirpt to only generate code to set TPIDRPRW_S (see line 52)
sub main {

  my %mcr_tail; # "p15, 0, 13, 0, 0" part of mcr instruction
  my %reg_parsed;
  
  # Read Qemu values that contains lines as
  #  FCSEIDR, p15, 0, 13, 0, 0
  my $fh;
  open $fh, $QEMUREGS_PATH or die "Could not open $QEMUREGS_PATH: $!";
  while( my $line = <$fh>)  {   
      chomp $line;
      next if (substr($line,0,1) eq '#');
      # Remove spaces, we'll split by comma
      $line =~  tr/ //ds;
      #print $line,"\n";    
      my ( $name, $cp, $opc1, $rn, $rm, $opc2 ) = split /,/, $line;
      #print "Adding $name -> \"$cp, $opc1, $rn, $rm, $opc2\"\n";
      # TODO: names can repeat, but seems only for non-important registers
      if(!($opc2 eq "-1")) {
        $mcr_tail{$name} = "$cp, $opc1, r1, cr$rn, cr$rm, $opc2"; # note that we added r1
      }
      #last if $. == 3; 
  }
  close $fh;

  # Read Gdb regs values line by line
  open $fh, $GDBREGS_PATH or die "Could not open $GDBREGS_PATH: $!";

  print ".section .text\n";
  print ".global _start\n\n";
  print "_start:\n";
  while( my $line = <$fh>)  {   
      chomp $line;
      #print $line,"\n";    
      my ( $name, $value ) = split /\s+/, $line;
      #if (!defined($value)) {
      #  print "value is undefined in line $line\n"; 
      #}
      next if !defined($value);
      next if $value eq "0x0";
      next if !($name eq "TPIDRPRW_S"); # Some other mcr instructions generate Invalid instruction error in unicorn
      # Give preference to registers that end with _S
      if ( (substr($name, -2) eq "_S") && exists $mcr_tail{substr($name, 0,-2)}) {
        print "/* $name v=$value */\n";
	#print "mov r1, #$value\n";
	print "ldr r1, =#$value\n";
        my $t = $mcr_tail{substr($name, 0,-2)};
        print "mcr $t\n";
	$reg_parsed{substr($name, 0,-2)}=1;
	next;
      }

      if (!(exists $reg_parsed{$name}) && exists $mcr_tail{$name}) {
        #print "Have inst for $name, v=$value\n";
        print "/* $name v=$value */\n";
	#print "mov r1, #$value\n";
	print "ldr r1, =#$value\n";
        my $t = $mcr_tail{$name};
        print "mcr $t\n";
      } 

      #print $name, " ", $value, "\n";
      #last if $. == 2; 
  }
  close $fh;
}

main();


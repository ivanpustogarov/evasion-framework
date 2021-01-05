#! /usr/bin/perl

# This script converts an xml scheme produced by emuatlin-arm
# into a C code

use strict;
use warnings;
use XML::LibXML;

my $cprog_header = <<'END_CCHUNK';
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

END_CCHUNK

my $cprog_p1 = <<'END_CCHUNK';
int main()
{

END_CCHUNK

my $cprog_p2 = <<'END_CCHUNK';
  int fd = open('/dev/xxx', O_RDWR);
  ioctl(fd, <CMD>, &var_toplevel_0x10000000);
}
END_CCHUNK


# Structs get names sp_{vaddr} (stand from struct pointer)
# Fileds of corresponding structs get names vp (stands for variable pointer)
# Naming conventions are critical when we set values for fields
sub pointer2cstruct
{
  my $cur = shift;
  my $cstruct_def = "";
  my $cstruct_init = "";
  #print "Parsing pointer, vaddr = ". $cur->getAttribute("vaddr") . "\n";

  my $cur_vaddr = $cur->getAttribute("vaddr");
  my $cur_name = $cur->nodeName;
  my $struct_name_prefix = "";
  if($cur_name eq "pointer") {
   $struct_name_prefix = "sp_";
  }
  if($cur_name eq "struct") {
   $struct_name_prefix = "toplevel_";
  }
  my $struct_name = "$struct_name_prefix" . "$cur_vaddr";
  $cstruct_def = "struct $struct_name {\n";
  $cstruct_init = "struct $struct_name var_$struct_name;\n";

  my @children = $cur->findnodes('./child::*');
  # Children can be either pointers or arrays
  for my $child (@children) {
    my $child_name = $child->nodeName;
    my $vaddr = $child->getAttribute("vaddr");
    my $size = $child->getAttribute("size");
    my $value = $child->getAttribute("value");
    $value =~ s/([0-9a-f]{2})/\\x$1/g;
    if($child_name eq "array") {
      my $field_name = "farray_$vaddr";
      $cstruct_def .= "  uint8_t ${field_name}[$size];\n";
      $cstruct_init .= "memcpy(&var_$struct_name.$field_name, \"$value\", $size);\n"
    }
    if($child_name eq "pointer") {
      $cstruct_def = $cstruct_def .  "  struct sp_$vaddr *fp_$vaddr;\n";
      #my $ .= "var_$struct_name.$field_name = &var_$struct_name.$field_name;\n"
      my $field_name = "fp_$vaddr";
      $cstruct_init .= "var_$struct_name.$field_name = &var_sp_$vaddr;\n"
    }
  }
  $cstruct_def .= "};\n\n";
  $cstruct_init .= "\n";
  return ($cstruct_def, $cstruct_init);
}

my $inputfilename = shift;
#my $outputfilename = shift;

#if(!$inputfilename || !$outputfilename) { print "error: please provide input and output filenames\nusage: $0 INFILE OUTFILE\n"; exit -1; }
if(!$inputfilename) { print "error: please provide input filename\nusage: $0 INXMLFILE\n"; exit -1; }
if (! -e $inputfilename) {print "error: input file $inputfilename does not exist\n"; exit -1} 

my $doc = eval{XML::LibXML->load_xml(location => $inputfilename);};
if($@) {
    print "Error parsing '$inputfilename':\n$@";
    exit 0;
}

# Prepare struct definitions
my $ioctl_cmd = $doc->findnodes('/struct/@cmd');
my $definitions = "";
my $init_code = "";
my @pointer_nodes = $doc->findnodes('//pointer|//struct');
for my $pointer (reverse(@pointer_nodes)) {
  my ($cstruct_def, $cstruct_init) = pointer2cstruct($pointer);
  $definitions = $definitions . "$cstruct_def";
  $init_code = $init_code . "$cstruct_init";
}

#print "cmd=$ioctl_cmd\n";
print $cprog_header;
print $definitions;
print $cprog_p1;
$cprog_p2 =~ s/<CMD>/$ioctl_cmd/g;
# This is to add two space in front of each line
$init_code =~ s/^/  /g;
$init_code =~ s/\n/\n  /g;
$init_code =~ s/  $//g;
print $init_code;
print $cprog_p2;

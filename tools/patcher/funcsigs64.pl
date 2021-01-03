#! /usr/bin/perl

#use feature qw(say);
#use strict;
#use warnings;
use Binutils::Objdump (); # Seems like this module is missing Exporter interface!??
use Parse::ExuberantCTags;
use Data::Dumper;
use Digest::MD5 qw(md5 md5_hex md5_base64);


#sub ugly_hash
#{
#  my $string = shift;
#  my $hash = 0;
#  #for my $c (split //, $string) {
#  #   $hash = ( ($hash + (324723947 + ord($c))) % 2**32) ^ 0xc1bd59f1;
#  #}
#  for my $c (split //, $string) {
#     $hash = ($hash * 33 + ord($c))  % 2**32;
#  }
#  #return $hash % 2**32;
#  return $hash;
#}


# encoded size: 1 byte; 
# Encoding is done as follows: 
# > two highest bits are set: 
# 00 -- not a pointer; 0x00 in hex
# 01 -- pointer (single '*');  0x40 in hex
# 11 -- pointer to pointer; 0xc0
# 10 -- reserved; 0x80
# > third most significant bit 
# 0 -- not const
# 1 -- const
# > Lowest 4 bits encode the type as follows:
# 0 - int/uint32_t/u32/unsigned int
# 1 - long/long int/unsigned long int
# 2 - short/unsigned short
# 3 - char/u8/uint8_t/unsigned char
# 4 - struct 
# 5 - void
# 15 - everything else (i.e. custom type,e.g. wait_queue_t)
sub encode_arg_type
{
  my $arg = shift; # a string; something like 'int *deadbeef'
  my $type = 0;

  #print "encode_arg_type(): arg = <$arg>, ";
  
  # First check if pointer
  my $idx = index($arg, "*");
  if ($idx != -1)  {
    $type |= (1 << 6);
  }
  $idx = index($arg, "*", $idx+1);
  if ($idx != -1)  {
    $type |= (1 << 7);
  }

  # Check for name
  if ($arg =~ m/(int|unsigned|uint32_t|u32|unsigned int)/) {
    $type |= 0;
  } elsif($arg =~ m/(long|long int|unsigned long int|size_t)/) {
    $type |= 1;
  } elsif ($arg =~ m/(short|unsigned short)/) {
    $type |= 2;
  } elsif ($arg =~ m/(char|u8|uint8_t|unsigned char)/) {
    $type |= 3;
  } elsif ($arg =~ m/struct/) {
    $type |= 4;
  } elsif ($arg =~ m/void/) {
    $type |= 5;
  } 
  else {
    $type |= 15;
  };

  # check for const
  if($arg =~ m/const/) {
    $type |= 0b00100000;
  };

  #print "type = ",sprintf("0x%02x", $type), "\n";
  return $type;
}


sub serialize {
  my $func_name = shift;
  my $parser = shift;

  my $out = "";
  my $tag = $parser->findTag($func_name, ignore_case => 0, partial => 0);
  if (defined $tag) {
    my $ext =  $tag->{extension};
    my $func_sig =  $ext->{signature};
    #print $tag->{name}, ">$ext->{signature}" , "\n";
    #print $tag->{addressPattern}, "\n";
    
    my $ret_type = 0;
    # Note that tag's signature extension does not provide function return type,
    # so we need to get this information from the address patter fieldi which looks something
    # like this: '/^static int qseecom_probe(struct platform_device *pdev)$/;"'
    if($tag->{addressPattern} =~ m/\/\^(.*\*)$func_name/)
    {
      #print "return type is a pointer: $1\n";
      $ret_type = 1; # is a pointer
    } else {
      $ret_type = 0; # not a pointer
      #print "return type not is a pointer\n";
    }

    #my $funcname_hash= ugly_hash($func_name); 
    #my $md5_hex = md5_hex($reloc_target);
    my $md5 = md5($func_name);
    my $funcname_hash  = substr $md5, 0, 4; # 4 bytes => 8 hex digits

    #print $func_name . " -> " . sprintf("0x%x\n", $funcname_hash);
    
    my $len = length($func_name);
    #print "func name len = $len\n";
    #print "serialazing...\n";

    # Let's assemble the serialized string
    my $s = "";

    # 1. func name len
    #my $f1 = pack("C", $len);
    #print $f1;
    #$s = $s . $f1;

    # 2. func name
    #print $func_name, "\n";
    #my $f2 = $func_name;
    #$s = $s . $f2;

    # 3. func name hash (4 bytes)
    #my $f3 = pack("V", $funcname_hash);
    my $f3 = $funcname_hash;
    #print $f3,"\n";
    $s = $s . $f3;

    # 4. func ret type
    my $f4 = pack("C", $ret_type);
    #print $f4,"\n";
    $s = $s . $f4;

    # 5. func args number
    my @args = split /,/, $func_sig; 
    my $f5 = pack("C", scalar @args);
    #print $f5,"\n";
    $s = $s . $f5;
    
    # 6. func args types
    # size: 1 byte; encoding is the following: two highest bits are set: 00 --
    # not a pointer; 01 -- pointer; 11 -- pointer to pointer;
    # lowest bits encode the type as follows:
    # 0 - int/uint32_t/u32/unsigned int/long/long int/unsigned long int
    # 1 - short/unsigned short
    # 2 - char/u8/uint8_t/unsigned char
    # 3 - struct 
    my $arg_type; 
    for my $arg (@args) {
      my $arg_type = encode_arg_type($arg);
      $f6 = pack("C",$arg_type);
      #if (index($arg, "*") != -1) {
      #    $f6 = pack("C",0);
      #} else {
      #    $f6 = pack("C",1);
      #}
      #print $f6,"\n"; 
      $s = $s . $f6;
    }
    
    #print $s;
    

    # Convert it to C-style hex string
    $h = unpack("H*", $s), "\n";
    #print $h;
    my $i = 0;
    for my $c (split //, $h) {
      if ( ($i % 2) == 0) {
        $out = $out . "\\x";
      }
      $out = $out . $c;
      $i = $i + 1;
      #print "$i\n";
    }
    #print "\n";
  }
  return $out;
}

# about objdump: https://stackoverflow.com/questions/52658101/reading-data-from-elf-file-in-perl
#                https://metacpan.org/pod/Binutils::Objdump
#my $search_string = 'ion_map_iommu';
#my $search_string = '*UND*';
sub mysymtab {
    my ($tags_filename, @lines) = @_;
    
    # Search for undefined symbol names
    my $parser = Parse::ExuberantCTags->new($tags_filename);
    my $tmp = "";

    # PROTOTYPES #
    # Collect, encode, and concatenate function prototypes
    my $count = 0;
    for my $line (@lines) {
        if ($line =~ m/0{8,16}[ ]*(\*UND\*)[ \t]*0{8,16} ([\w]*)/) # 8 is for ELF32, and 16 is for ELF64
	{
	   $count = $count + 1;
	   my $func_name = $2;
	   my $ser = serialize($func_name, $parser);
	   $tmp = $tmp . $ser;
	}
    }
    
    my $protos = "char funcprotos[] __attribute__((section(\"protos\"))) = \"";
    $protos = $protos . sprintf("\\x%02x", $count) . $tmp . "\";";

    # Now let's print it the C file
    my $filename = 'inject/inject.c';
    open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";

    (my $header = 
    qq{int generic_stub_0();
        int generic_stub_1();
        int generic_stub_p();
        int randomfunction()
        {
          generic_stub_0();
          generic_stub_1();
          generic_stub_p();
        }

        }) =~ s/^ {8}//mg;

    print $fh $header;
    print $fh $protos;
    print $fh "\n\n";

    (my $footer = 
    qq{char *get_func_protos()
        {
          return &funcprotos[0];
        };
        }) =~ s/^ {8}//mg;

    print $fh $footer;

    close $fh;

    print "Enocoded $count function prototypes\n";
    #print $protos;
}

sub add_relocations {
  my $module_filename = shift;
  # RELOCATIONS #
  
  my @lines = `./patcher -p $module_filename`;
  my $count = 0;
  my $h = "";


  #my $func_text = "\n\nint get_relocs_deadbeef() {\n char deadbeef[] =\""; # full hex string
  my $func_text = "\n\nchar *deadbeef =\""; # full hex string
  my $hex_str = ""; # part that contain serialized relocs
  my $hex_portion = ""; # hex substrigs for each reloc
  for my $line (@lines) {
      
      chomp($line);
      $hex_portion = "";
      my ($reloc_target,$orig_func_name) = split(/ -> /, $line);
      my $discard;
      ($reloc_target,$discard) = split(/\//, $reloc_target);

      #print "$line\n";
      my $md5_hex = md5_hex($reloc_target);
      my $md5 = md5($reloc_target);
      my $md5_left4  = substr $md5, 0, 4; # 4 bytes => 8 hex digits

      # DEBUG PRINT
      # print "md5($reloc_target) = $md5_hex\n";
      # print substr($md5_hex, 0, 8), "\n";
      ##

      #my $f1 = pack("V", $md5_left4);
      my $f1 = $md5_left4;
      my $f2 = pack("C", length($orig_func_name));
      my $f3 = $orig_func_name;

      my $s = $f1 . $f2 . $f3;

      # Convert it to C-style hex string
      $h = unpack("H*", $s), "\n";
      my $i = 0;
      for my $c (split //, $h) {
        if ( ($i % 2) == 0) {
          $hex_portion = $hex_portion . "\\x";
        }
        $hex_portion = $hex_portion . $c;
        $i = $i + 1;
      }
      
      #print "$hex_portion\n";
      $hex_str = $hex_str . $hex_portion;
      $count = $count + 1;

  }

  #print scalar(@lines), "\n";
  #print $count, "\n";
  #exit(0);
  my $f0 = pack("v", scalar(@lines));
  my $h = unpack("H*", $f0), "\n";
  my $i = 0;
  for my $c (split //, $h) {
    if ( ($i % 2) == 0) {
      $func_text = $func_text . "\\x";
    }
    $func_text = $func_text . $c;
    $i = $i + 1;
  }
  #print $func_text;

  $func_text = $func_text . $hex_str . "\";";
  $func_text = $func_text . "\n\nchar *get_relocs_deadbeef()\n{\n  return deadbeef;\n};";
  #print $func_text;

  my $filename = 'inject/inject.c';
  open(my $fh, '>>', $filename) or die "Could not open file '$filename' $!";

  print $fh $func_text;

  print "Encoded $count relocations\n";

  close $fh;

}

sub main {
  # Need two args
  if ($#_ != 1 ) {
        #print $#ARGV . "\n";
  	print "usage: funcsigs.pl module.ko tags\n\n";
  	print "       Generate inject.c based on tags and module\n";
	print "       Check readme.funcsigs.pl for details\n";
  	exit 0;
  }
 
  my $module_filename = shift;
  my $tags_filename = shift;

  Binutils::Objdump::objdumpopt('-t');
  Binutils::Objdump::objdumpwrap("SYMBOL TABLE" => sub { mysymtab( $tags_filename, @_ ) });

  # This will call 'mysymtab()' function which will read 'tags', extract 
  # prototypes for function imported by the module, encode it, and add to inject.c
  Binutils::Objdump::objdump($module_filename);
  
  add_relocations($module_filename);
  print "File inject/inject.c was generated, now compile it and link with your module\n";

}

main(@ARGV);


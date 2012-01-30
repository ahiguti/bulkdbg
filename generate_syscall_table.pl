#!/usr/bin/perl

use strict;
use warnings;
use IO::File;

print "/* THIS IS A GENERATED FILE. DON'T EDIT. */\n";
print "#include \"syscall_table.hpp\"\n";
generate_one('/usr/include/asm/unistd_32.h', 32);
generate_one('/usr/include/asm/unistd_64.h', 64);

sub generate_one {
  my ($fn, $s) = @_;
  print "const syscall_table_type syscall_table_$s [] = {\n";
  my $fp = new IO::File($fn, 'r');
  while (my $line = <$fp>) {
    chomp($line);
    next if ($line !~ /^#define\s+__NR_(\w+)\s+(\d+)/);
    print "  { $2, \"$1\" },\n";
  }
  print "  { -1, 0 },\n";
  print "};\n";
}


#!/usr/bin/perl -w
# ETVPN Authenticator for OpenVPN servers
# Copyright (C) 2023 Eurotux Informática S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);
use Crypt::OpenSSL::RSA;
use Fcntl;
use Cwd qw/ realpath /;
my $path = realpath($0);

use ETVPN::Cli;


#################################
### Globals
#################################
$|=1;

#### command line arguments
my $priv_file;
my $pub_file;
my $need_help = 0;


#######
# Subs and helpers
#######
sub help {
	print "Usage:\n";
	print "\t$0 private_key_file public_key_file\n";
	print "\n";
	exit 1;
}


###############
# Command Line
###############
GetOptions (
	'h|help' => \$need_help,
) or do {
	print "Invalid parameters.\n\n";
	$need_help = 1;
};
unless ( defined($priv_file = shift @ARGV) && defined($pub_file = shift @ARGV) ) {
	print "Missing file names\n\n";
	$need_help = 1;
}
help if $need_help;

ETVPN::Cli::die_error("File $priv_file already exists") if -e $priv_file;
ETVPN::Cli::die_error("File $pub_file already exists") if -e $pub_file;
ETVPN::Cli::die_error("Need /dev/random") unless -e '/dev/random';

###############
# Perform actions
###############
my $rsa = Crypt::OpenSSL::RSA->generate_key(4096);

sysopen (my $priv_fh, $priv_file, O_WRONLY|O_EXCL|O_CREAT, 0600) or ETVPN::Cli::die_error("Can't open $priv_file: $!");
print $priv_fh $rsa->get_private_key_string();
close $priv_fh;
print "Wrote private key to ".realpath($priv_file)."\n";

sysopen (my $pub_fh, $pub_file, O_WRONLY|O_EXCL|O_CREAT, 0600) or ETVPN::Cli::die_error("Can't open $pub_file: $!");
print $pub_fh $rsa->get_public_key_x509_string();
close $pub_fh;
print "Wrote public key to ".realpath($pub_file)."\n";

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

package ETVPN::Cli 0.7.1;
use strict;
use warnings;
use Term::ReadKey;
use List::Util qw(max);


my $issued_warning = 0;


sub had_warning() {
	return $issued_warning;
}


sub die_error($;$) {
	my ($error, $code) = @_;

	# put extra line if warnings were issued, for better readability
	my $message = $issued_warning ? "\n" : '';
	$message .= $error ? "ERROR: $error" : "An unspecified error has ocurred (this should not happen, please contact support)";
	if ($code) {
		print STDERR "$message\n";
		exit $code;
	}
	die "$message\n";
}


sub issue_warn($) {
	my $message = shift;
	chomp $message;
	warn "$message\n";
	$issued_warning = 1;
}


sub read_prompt($;$) {
	my ($prompt, $is_password) = @_;
	my $value = '';
	do {
		print $prompt;
		if ($is_password) {
			ReadMode('noecho');
			$value = ReadLine(0);
			ReadMode('restore');
			print "\n";
		}
		else {
			$value = ReadLine(0);
		}
		die_error("Aborted") unless defined($value);
		chomp $value;
	} while ($value eq '');
	return $value;
}


sub output_table($;$) {
	my ($list, $extraspace) = @_;
	$extraspace = 1 unless defined($extraspace);
	my @sizes;
	my @vsizes;
	# calculate optimal size for each line element
	my $l = 0;
	foreach my $line (@$list) {
		$vsizes[$l] = 0;
		for (my $c = 0; $c < @$line; $c++) {
			my $col = $line->[$c];
			if (ref($col) eq 'ARRAY') {
				# column is multiline
				foreach my $subline (@$col) {
					$sizes[$c] = max(exists($sizes[$c]) ? $sizes[$c] : 0, length($subline));
				}
				$vsizes[$l] = max(exists($vsizes[$l]) ? $vsizes[$l] : 1, scalar(@$col));
			}
			else {
				$sizes[$c] = max(exists($sizes[$c]) ? $sizes[$c] : 0, length($col));
			}
		}
		$l++;
	}
	# generate printf format string accordingly
	my $list_format = join(" ", (map { '%-'.($_+$extraspace).'s' } @sizes[0..$#sizes-1]), '%s')."\n";
	# output each line using that format
	$l = 0;
	foreach my $line (@$list) {
		if ( (my $vsize = $vsizes[$l]) ) {
			for (my $i = 0; $i < $vsize; $i++) {
				my @multiline;
				foreach my $col (@$line) {
					my $colval;
					if (ref($col) eq 'ARRAY') {
						if (exists($col->[$i])) {
							$colval = $col->[$i];
						}
						else {
							$colval = '';
						}
					}
					else {
						$colval = $i ? '' : $col;
					}
					push @multiline, $colval;
				}
				printf $list_format, @multiline;
			}
		}
		else {
			printf $list_format, @$line;
		}
		$l++;
	}
}


1;

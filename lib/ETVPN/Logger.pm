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

package ETVPN::Logger v0.7.1;
use strict;
use warnings;
use List::Util qw(max);


my $prefix = '';
my @prefixes;
my $is_dynamic = 0;


sub refresh() {
	$is_dynamic = 0;
	$prefix = join(q{}, map { if (ref($_) eq 'CODE') { $is_dynamic = 1; &$_() } else { $_ } } @prefixes);
}


sub _prefix() {
	if ($is_dynamic) {
		refresh();
	}
	return $prefix;
}


sub push_prefix(@) {
	push @prefixes, @_;
	refresh();
}


sub pop_prefix {
	my $opt = shift;
	my $level;

	if (!defined($opt)) {
		$level = -1;
	}
	elsif (ref($opt) eq 'HASH' &&
	    defined($opt->{'level'})) {
		$level = $opt->{'level'};
	}
	else {
		# simulate pop
		$level = @prefixes - $opt;
		$level = 0 if $level < 0;
	}

	my @removed = splice @prefixes, $level;
	refresh();
	if (wantarray()) {
		# list context
		return @removed;
	}
	elsif (defined wantarray()) {
		# scalar context, return join of removed prefixes
		return join(q{}, @removed);
	}
	# void context, return nothing
}


sub get_prefix() {
	if (wantarray()) {
		return @prefixes;
	}
	elsif (defined wantarray()) {
		return _prefix();
	}
	# void context, return nothing
}


sub current_level() {
	return scalar(@prefixes);
}


sub log(@) {
	my $log_prefix = _prefix();
	foreach my $m (@_) {
		foreach my $subm (split(/\n/, $m)) {
			print "$log_prefix$m\n";
		}
	}
}


sub fatal_code($@) {
	my $code = shift;
	if (@_) {
		foreach my $m (@_) {
			warn _prefix()."$m\n";
		}
	}
	else {
		my ( $pkg, $filename, $line ) = caller;
		warn _prefix()."Terminated from $pkg on file $filename at line $line\n";
	}
	exit $code;
}


sub fatal(@) {
	fatal_code(1, @_);
}


1;

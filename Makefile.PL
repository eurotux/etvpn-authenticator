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
use ExtUtils::MakeMaker;
use List::Util qw(pairs);


sub MY::postamble {
<<'END'
ETVPN_SYSTEM_CONFDIR=/etc
ETVPN_CONFDIR = $(ETVPN_SYSTEM_CONFDIR)/etvpn
ETVPN_DESTCONFDIR = $(DESTDIR)$(ETVPN_CONFDIR)
$(ETVPN_DESTCONFDIR):
	$(NOECHO) $(MKPATH) $(ETVPN_DESTCONFDIR)
	$(NOECHO) $(CHMOD) 0700 $(ETVPN_DESTCONFDIR)

ETVPN_SYSTEM_LIBEXECDIR = $(PREFIX)/libexec
ETVPN_LIBEXECDIR = $(ETVPN_SYSTEM_LIBEXECDIR)/etvpn
ETVPN_DESTLIBEXECDIR = $(DESTDIR)$(ETVPN_LIBEXECDIR)
$(ETVPN_DESTLIBEXECDIR):
	$(NOECHO) $(MKPATH) $(ETVPN_DESTLIBEXECDIR)
	$(NOECHO) $(CHMOD) 0755 $(ETVPN_DESTLIBEXECDIR)

ETVPN_SYSTEM_SHAREDIR = $(PREFIX)/share
ETVPN_SHAREDIR = $(ETVPN_SYSTEM_SHAREDIR)/etvpn
ETVPN_DESTSHAREDIR = $(DESTDIR)$(ETVPN_SHAREDIR)
$(ETVPN_DESTSHAREDIR):
	$(NOECHO) $(MKPATH) $(ETVPN_DESTSHAREDIR)
	$(NOECHO) $(CHMOD) 0755 $(ETVPN_DESTSHAREDIR)
ETVPN_SQLUSERPORTAL_DESTSHAREDIR = $(ETVPN_DESTSHAREDIR)/www-sqluserportal
$(ETVPN_SQLUSERPORTAL_DESTSHAREDIR):
	$(NOECHO) $(MKPATH) $(ETVPN_SQLUSERPORTAL_DESTSHAREDIR)
	$(NOECHO) $(CHMOD) 0755 $(ETVPN_SQLUSERPORTAL_DESTSHAREDIR)

etvpn_install_conf: $(ETVPN_DESTCONFDIR) etux-vpnserver.ini
	$(CP_NONEMPTY) etux-vpnserver.ini $(ETVPN_DESTCONFDIR)/etux-vpnserver.ini 0600

etvpn_install_daemon: $(ETVPN_DESTLIBEXECDIR) daemon/etux-vpnserver-auth.pl
	$(CP_NONEMPTY) daemon/etux-vpnserver-auth.pl $(ETVPN_DESTLIBEXECDIR)/etux-vpnserver-auth 0755

etvpn_install_tools: $(ETVPN_DESTLIBEXECDIR) tools/* tools/*/*
	$(CP) -R tools $(ETVPN_DESTLIBEXECDIR)

etvpn_install_webauthn: $(ETVPN_DESTSHAREDIR) webauthn/www/*
	$(CP) -R webauthn/www $(ETVPN_DESTSHAREDIR)

etvpn_install_sqluserportal_conf: $(ETVPN_DESTCONFDIR) sqluserportal/daemon/sqluserportal.ini
	$(CP_NONEMPTY) sqluserportal/daemon/sqluserportal.ini $(ETVPN_DESTCONFDIR)/sqluserportal.ini 0600

etvpn_install_sqluserportal_daemon: $(ETVPN_DESTLIBEXECDIR) sqluserportal/daemon/etux-vpnserver-sqluserportal.pl
	$(CP_NONEMPTY) sqluserportal/daemon/etux-vpnserver-sqluserportal.pl $(ETVPN_DESTLIBEXECDIR)/etux-vpnserver-sqluserportal 0755

etvpn_install_sqluserportal_www: $(ETVPN_SQLUSERPORTAL_DESTSHAREDIR) sqluserportal/www/*
	$(CP) -R sqluserportal/www/* $(ETVPN_SQLUSERPORTAL_DESTSHAREDIR)

ETVPN_INSTALL_TARGETS = etvpn_install_conf etvpn_install_daemon etvpn_install_tools etvpn_install_webauthn etvpn_install_sqluserportal_conf etvpn_install_sqluserportal_daemon etvpn_install_sqluserportal_www
.PHONY: $(ETVPN_INSTALL_TARGETS)
install :: $(ETVPN_INSTALL_TARGETS)
END
}


WriteMakefile(
	NAME              => 'ETVPN',
	VERSION_FROM      => 'lib/ETVPN/Actionable.pm',
);

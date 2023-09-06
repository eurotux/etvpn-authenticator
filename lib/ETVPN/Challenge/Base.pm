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

package ETVPN::Challenge::Base v0.7.3;
use strict;
use warnings;
use parent qw(ETVPN::Actionable);

use ETVPN::Login;


sub validate {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->validate($login, $secret, $user_challenge_reply) and return a boolean
	# ($user_challenge_reply may be ommited depending on challenge type)
	ETVPN::Logger::fatal("internal error: challenge base class validate() called");
}


sub validate_pending_auth {
	# not supposed to be executed on base class
	# when overriding, it should accept $obj->validate_pending_auth($login, $user_challenge_reply) and return a boolean
	# ($user_challenge_reply may be ommited depending on challenge type)
	ETVPN::Logger::fatal("internal error: challenge base class validate_pending_auth() called");
}


sub is_crv {
	# can be overrided on classes to indicate if the object is processing a CRV type challenge
	# if the challenge needs a reply using Challenge-Response protocol, the client will be disconnected with a CRV motive
	# and the openvpn client will present prompt given with $obj->get_crv_prompt($login)
	# by default returns the opposite of is_pending but an override is usually necessary to
	# support CRV compatibility mode for pending challenge types
	# when overriding, it should accept: $obj->is_crv($login) and return a boolean
	return !$_[0]->is_pending;
}


sub is_crv_allowed_empty_reply {
	# only called when is_crv returns true
	# when overriding, it should accept $obj->is_crv_allowed_empty_reply($login)
	# must return a boolean
	return 0;
}


sub get_crv_prompt {
	# usually should be overrided when supporting CRV challenges
	# when overriding, it should accept $obj->get_crv_prompt($login)
	# must return a list with a prompt string and a flag indicating if the user reply can be echoed or not
	# the string returned here will be used as the prompt for the CRV challenge when a denied validation ocurred
	# if the string is undef, a denied validation won't trigger a CRV challenge
	# note that retries are handled in the auth daemon itself so for simpler
	# challenges this can always return the same static string
	return (undef, 0);
}


sub set_secret {
	# useful to be overrided on classes that support both pending and CRV challenges, if something on the secret should be
	# previously known (e.g. at the time of generatint the prompt, as is the case on webauthn, where the "credential id" must
	# be sent to the web session)
	# when overriding, it should accept: $obj->set_secret($login, $secret), any return result is unused
	# by default does nothing
}


sub is_pending {
	# should be overrided on classes that make use of pending challenge type, and return a boolean
	# by default returns false
	return 0;
}


sub get_pending_string {
	# should be overrided on classes that make use of pending challenge type
	# when overriding, it should accept $obj->get_pending_string($login) and return the string to pass to client-pending-auth (without any cid or kid)
	ETVPN::Logger::fatal("internal error: challenge base class get_pending_string() called");
}


1;

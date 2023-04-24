#!/bin/bash

# For typical Linux distributions and ip-route
# Based on https://openvpn.net/faq/why-are-route-and-route-ipv6-commands-not-possible-in-a-ccd-file/
# For other flavours (e.g. BSD) please adapt as needed
#

# IMPORTANT:
#
# If running openvpn as the openvpn user (as you should), and needing to use sudo, don't forget to
# add something like the following in your sudoers configuration:
#
# Defaults:openvpn !requiretty
# openvpn  ALL=(root)  NOPASSWD: /sbin/route, /sbin/ip
#
# Also if you are using systemd, you'll most likely need to increase NPROC limit for your OpenVPN service
# or else you'll be getting "sudo: unable to fork: Resource temporarily unavailable" errors
# One way to do that is to create a file such as /etc/systemd/system/openvpn-server@.service.d/limit-override.conf
# (you may need to create /etc/systemd/system/openvpn-server@.service.d directory beforehand, and adapt the service
# name according to your setup), then add the following content (remove the comments):
#
# [Service]
# LimitNPROC=1024
#
# After that, don't forget to:
#
# systemctl daemon-reload
#
# and also restart your OpenVPN instance
#


exec > >( logger -t "`basename $0 .sh`" ) 2>&1

operation="$1"
route="$2"
cname="$3"

[ -z "$operation" -o -z "$route" ] && exit 0

CMD_ARGS=( /sbin/ip )

case "$route" in
	*:*)
		CMD_ARGS+=( -6 )
		;;
esac

case "$operation" in
	add)
		route_op=add
		;;
	delete)
		route_op=del
		;;
	update)
		route_op=replace
		;;
	*)
		echo "Ignored unknown operation: $operation"
		exit 0
esac

CMD_ARGS+=( route "$route_op" "$route" )
if [ -n "$dev" ]; then
	CMD_ARGS+=( dev "$dev" )
fi

echo "Executing: ${CMD_ARGS[@]}"
sudo "${CMD_ARGS[@]}"
exit 0

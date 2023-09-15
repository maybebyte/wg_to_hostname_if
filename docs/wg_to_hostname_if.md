WG\_TO\_HOSTNAME\_IF(1) - General Commands Manual

# NAME

**wg\_to\_hostname\_if** - translate WireGuard configuration file to hostname.if(5)

# SYNOPSIS

**wg\_to\_hostname\_if**
\[**-hr**]
\[**-m**&nbsp;*mtu*]
\[**-t**&nbsp;*rtable*]
\[*file*]

# DESCRIPTION

The
**wg\_to\_hostname\_if**
utility processes a WireGuard configuration
*file*,
validating its contents and printing its
hostname.if(5)
counterpart to standard output.
If
*file*
is a single dash
('-')
or absent,
**wg\_to\_hostname\_if**
reads from the standard input.

The options are as follows:

**-h**

> Print usage information and exit.

**-m** *mtu*

> Add a line to the output that specifies the MTU (Maximum
> Transmission Unit) of the interface. By default, a WireGuard interface
> has an MTU of 1420.

**-r**

> Add
> route(8)
> commands to the output so that the WireGuard interface will hold
> the default routes.

**-t** *rtable*

> Add a wgrtable line to the output so that
> *rtable*
> will be used to exchange traffic between peers rather than the
> default
> rtable(4).

# EXIT STATUS

The
**wg\_to\_hostname\_if**
utility exits 0 on success, and &gt;0 if an error occurs.

# EXAMPLES

Parse the WireGuard file and print the translated contents to standard
output.

	$ wg_to_hostname_if wireguard-file.conf

In the output, add routing commands and a line specifying that
rtable 1 will be the routing table used to exchange traffic between
peers. Redirect the output to
*hostname.wg0*
and bring the interface up with
netstart(8).

	# wg_to_hostname_if -rt 1 wireguard-file.conf > /etc/hostname.wg0
	# sh /etc/netstart wg0

# SEE ALSO

wg(4),
rtable(4),
hostname.if(5),
ifconfig(8),
netstart(8)

# AUTHORS

Written and maintained by
Ashlen &lt;[dev@anthes.is](mailto:dev@anthes.is)&gt;.

# CAVEATS

When using
**-r**,
**wg\_to\_hostname\_if**
will only print default route commands for the first IPv4 and IPv6
addresses it encounters.

Only client WireGuard configuration files are supported.

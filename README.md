# rustables

Safe abstraction for [`libnftnl`]. Provides low-level userspace access to the
in-kernel nf_tables subsystem. See [`rustables-sys`] for the low level FFI
bindings to the C library.

Can be used to create, list and remove tables, chains, sets and rules from the
nftables firewall, the successor to iptables.

This library is directly derived from the [`nftnl-rs`] crate. Let us thank here
the original project team for their great work without which this library would
probably not exist today.

It currently has quite rough edges and does not make adding and removing
netfilter entries super easy and elegant. That is partly because the library
needs more work, but also partly because nftables is super low level and
extremely customizable, making it hard, and probably wrong, to try and create a
too simple/limited wrapper.  See examples for inspiration.  One can also look
at how the original project this crate was developed to support uses it :
[Mullvad VPN app].

Understanding how to use [`libnftnl`] and implementing this crate has mostly
been done by reading the source code for the [`nftables`] program and attaching
debuggers to the `nft` binary. Since the implementation is mostly based on
trial and error, there might of course be a number of places where the
underlying library is used in an invalid or not intended way.  Large portions
of [`libnftnl`] are also not covered yet. Contributions are welcome!

## Supported versions of `libnftnl`

This crate will automatically link to the currently installed version of
libnftnl upon build.  It requires libnftnl version 1.0.6 or higher. See how the
low level FFI bindings to the C library are generated in [`build.rs`].

## Licensing

License: GNU GPLv3

Original work licensed by Amagicom AB under MIT/Apache-2.0.

[`nftnl-rs`]: https://github.com/mullvad/nftnl-rs
[Mullvad VPN app]: https://github.com/mullvad/mullvadvpn-app
[`libnftnl`]: https://netfilter.org/projects/libnftnl/
[`nftables`]: https://netfilter.org/projects/nftables/
[`build.rs`]: https://gitlab.com/rustwall/rustables/-/blob/master/build.rs


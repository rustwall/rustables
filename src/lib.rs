// Copyryght (c) 2021 GPL lafleur@boum.org and Simon Thoby
//
// This file is free software: you may copy, redistribute and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This file is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see the LICENSE file.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2018 Amagicom AB.
//
//     Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
//     http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
//     <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
//     option. This file may not be copied, modified, or distributed
//     except according to those terms.

//! Safe abstraction for [`libnftnl`]. Provides userspace access to the in-kernel nf_tables
//! subsystem. Can be used to create and remove tables, chains, sets and rules from the nftables
//! firewall, the successor to iptables.
//!
//! This library currently has quite rough edges and does not make adding and removing netfilter
//! entries super easy and elegant. That is partly because the library needs more work, but also
//! partly because nftables is super low level and extremely customizable, making it hard, and
//! probably wrong, to try and create a too simple/limited wrapper. See examples for inspiration.
//! One can also look at how the original project this crate was developed to support uses it:
//! [Mullvad VPN app](https://github.com/mullvad/mullvadvpn-app)
//!
//! Understanding how to use [`libnftnl`] and implementing this crate has mostly been done by
//! reading the source code for the [`nftables`] program and attaching debuggers to the `nft`
//! binary. Since the implementation is mostly based on trial and error, there might of course be
//! a number of places where the underlying library is used in an invalid or not intended way.
//! Large portions of [`libnftnl`] are also not covered yet. Contributions are welcome!
//!
//! # Supported versions of `libnftnl`
//!
//! This crate will automatically link to the currently installed version of libnftnl upon build.
//! It requires libnftnl version 1.0.6 or higher. See how the low level FFI bindings to the C
//! library are generated in [`build.rs`].
//!
//! # Access to raw handles
//!
//! Retrieving raw handles is considered unsafe and should only ever be enabled if you absolutely
//! need it. It is disabled by default and hidden behind the feature gate `unsafe-raw-handles`.
//! The reason for that special treatment is we cannot guarantee the lack of aliasing. For
//! example, a program using a const handle to a object in a thread and writing through a mutable
//! handle in another could reach all kind of undefined (and dangerous!) behaviors.  By enabling
//! that feature flag, you acknowledge that guaranteeing the respect of safety invariants is now
//! your responsibility! Despite these shortcomings, that feature is still available because it
//! may allow you to perform manipulations that this library doesn't currently expose. If that is
//! your case, we would be very happy to hear from you and maybe help you get the necessary
//! functionality upstream.
//!
//! Our current lack of confidence in our availability to provide a safe abstraction over the use
//! of raw handles in the face of concurrency is the reason we decided to settly on `Rc` pointers
//! instead of `Arc` (besides, this should gives us some nice performance boost, not that it
//! matters much of course) and why we do not declare the types exposed by the library as `Send`
//! nor `Sync`.
//!
//! [`libnftnl`]: https://netfilter.org/projects/libnftnl/
//! [`nftables`]: https://netfilter.org/projects/nftables/
//! [`build.rs`]: https://gitlab.com/rustwall/rustables/-/blob/master/build.rs

use parser::DecodeError;
use thiserror::Error;

#[macro_use]
extern crate log;

pub mod sys;
use libc;
use std::convert::TryFrom;

mod batch;
pub use batch::{default_batch_page_size, Batch};

mod table;
pub use table::list_tables;
pub use table::Table;

mod chain;
pub use chain::list_chains_for_table;
pub use chain::{Chain, ChainPolicy, ChainPriority, ChainType, Hook, HookClass};

//mod chain_methods;
//pub use chain_methods::ChainMethods;

pub mod query;

pub mod nlmsg;
pub mod parser;

mod rule;
pub use rule::list_rules_for_chain;
pub use rule::Rule;

pub mod expr;

//mod rule_methods;
//pub use rule_methods::{iface_index, Error as MatchError, Protocol, RuleMethods};

//pub mod set;
//pub use set::Set;

/// The type of the message as it's sent to netfilter. A message consists of an object, such as a
/// [`Table`], [`Chain`] or [`Rule`] for example, and a [`MsgType`] to describe what to do with
/// that object. If a [`Table`] object is sent with `MsgType::Add` then that table will be added
/// to netfilter, if sent with `MsgType::Del` it will be removed.
///
/// [`Table`]: struct.Table.html
/// [`Chain`]: struct.Chain.html
/// [`Rule`]: struct.Rule.html
/// [`MsgType`]: enum.MsgType.html
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MsgType {
    /// Add the object to netfilter.
    Add,
    /// Remove the object from netfilter.
    Del,
}

/// Denotes a protocol. Used to specify which protocol a table or set belongs to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum ProtocolFamily {
    Unspec = libc::NFPROTO_UNSPEC,
    /// Inet - Means both IPv4 and IPv6
    Inet = libc::NFPROTO_INET,
    Ipv4 = libc::NFPROTO_IPV4,
    Arp = libc::NFPROTO_ARP,
    NetDev = libc::NFPROTO_NETDEV,
    Bridge = libc::NFPROTO_BRIDGE,
    Ipv6 = libc::NFPROTO_IPV6,
    DecNet = libc::NFPROTO_DECNET,
}

impl Default for ProtocolFamily {
    fn default() -> Self {
        Self::Unspec
    }
}

impl TryFrom<i32> for ProtocolFamily {
    type Error = DecodeError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            libc::NFPROTO_UNSPEC => Ok(ProtocolFamily::Unspec),
            libc::NFPROTO_INET => Ok(ProtocolFamily::Inet),
            libc::NFPROTO_IPV4 => Ok(ProtocolFamily::Ipv4),
            libc::NFPROTO_ARP => Ok(ProtocolFamily::Arp),
            libc::NFPROTO_NETDEV => Ok(ProtocolFamily::NetDev),
            libc::NFPROTO_BRIDGE => Ok(ProtocolFamily::Bridge),
            libc::NFPROTO_IPV6 => Ok(ProtocolFamily::Ipv6),
            libc::NFPROTO_DECNET => Ok(ProtocolFamily::DecNet),
            _ => Err(DecodeError::InvalidProtocolFamily(value)),
        }
    }
}

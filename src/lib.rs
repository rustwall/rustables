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

use thiserror::Error;

#[macro_use]
extern crate log;

pub mod sys;
use std::{convert::TryFrom, ffi::c_void, ops::Deref};
use sys::libc;

macro_rules! try_alloc {
    ($e:expr) => {{
        let ptr = $e;
        if ptr.is_null() {
            // OOM, and the tried allocation was likely very small,
            // so we are in a very tight situation. We do what libstd does, aborts.
            std::process::abort();
        }
        ptr
    }};
}

mod batch;
#[cfg(feature = "query")]
pub use batch::{batch_is_supported, default_batch_page_size};
pub use batch::{Batch, FinalizedBatch, NetlinkError};

pub mod expr;

pub mod table;
pub use table::Table;
#[cfg(feature = "query")]
pub use table::{get_tables_cb, list_tables};

mod chain;
#[cfg(feature = "query")]
pub use chain::{get_chains_cb, list_chains_for_table};
pub use chain::{Chain, ChainType, Hook, Policy, Priority};

mod chain_methods;
pub use chain_methods::ChainMethods;

pub mod query;

mod rule;
pub use rule::Rule;
#[cfg(feature = "query")]
pub use rule::{get_rules_cb, list_rules_for_chain};

mod rule_methods;
pub use rule_methods::{iface_index, Protocol, RuleMethods, Error as MatchError};

pub mod set;
pub use set::Set;

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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ProtoFamily {
    Unspec = libc::NFPROTO_UNSPEC as u16,
    /// Inet - Means both IPv4 and IPv6
    Inet = libc::NFPROTO_INET as u16,
    Ipv4 = libc::NFPROTO_IPV4 as u16,
    Arp = libc::NFPROTO_ARP as u16,
    NetDev = libc::NFPROTO_NETDEV as u16,
    Bridge = libc::NFPROTO_BRIDGE as u16,
    Ipv6 = libc::NFPROTO_IPV6 as u16,
    DecNet = libc::NFPROTO_DECNET as u16,
}
#[derive(Error, Debug)]
#[error("Couldn't find a matching protocol")]
pub struct InvalidProtocolFamily;

impl TryFrom<i32> for ProtoFamily {
    type Error = InvalidProtocolFamily;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            libc::NFPROTO_UNSPEC => Ok(ProtoFamily::Unspec),
            libc::NFPROTO_INET => Ok(ProtoFamily::Inet),
            libc::NFPROTO_IPV4 => Ok(ProtoFamily::Ipv4),
            libc::NFPROTO_ARP => Ok(ProtoFamily::Arp),
            libc::NFPROTO_NETDEV => Ok(ProtoFamily::NetDev),
            libc::NFPROTO_BRIDGE => Ok(ProtoFamily::Bridge),
            libc::NFPROTO_IPV6 => Ok(ProtoFamily::Ipv6),
            libc::NFPROTO_DECNET => Ok(ProtoFamily::DecNet),
            _ => Err(InvalidProtocolFamily),
        }
    }
}

/// Trait for all types in this crate that can serialize to a Netlink message.
///
/// # Unsafe
///
/// This trait is unsafe to implement because it must never serialize to anything larger than the
/// largest possible netlink message. Internally the `nft_nlmsg_maxsize()` function is used to
/// make sure the `buf` pointer passed to `write` always has room for the largest possible Netlink
/// message.
pub unsafe trait NlMsg {
    /// Serializes the Netlink message to the buffer at `buf`. `buf` must have space for at least
    /// `nft_nlmsg_maxsize()` bytes. This is not checked by the compiler, which is why this method
    /// is unsafe.
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType);
}

unsafe impl<T, R> NlMsg for T
where
    T: Deref<Target = R>,
    R: NlMsg,
{
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        self.deref().write(buf, seq, msg_type);
    }
}

/// The largest nf_tables netlink message is the set element message, which contains the
/// NFTA_SET_ELEM_LIST_ELEMENTS attribute. This attribute is a nest that describes the set
/// elements. Given that the netlink attribute length (nla_len) is 16 bits, the largest message is
/// a bit larger than 64 KBytes.
pub fn nft_nlmsg_maxsize() -> u32 {
    u32::from(::std::u16::MAX) + unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32
}
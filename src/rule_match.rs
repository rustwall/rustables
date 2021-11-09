use crate::{Batch, Rule, nft_expr, sys::libc};
use crate::expr::{LogGroup, LogPrefix};
use ipnetwork::IpNetwork;
use std::ffi::{CString, NulError};
use std::net::IpAddr;
use std::num::ParseIntError;


#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unable to open netlink socket to netfilter")]
    NetlinkOpenError(#[source] std::io::Error),
    #[error("Firewall is already started")]
    AlreadyDone,
    #[error("Error converting from a C string to a string")]
    CStringError(#[from] NulError),
    #[error("no interface found under that name")]
    NoSuchIface,
    #[error("Error converting from a string to an integer")]
    ParseError(#[from] ParseIntError),
    #[error("the interface name is too long")]
    NameTooLong,
}


/// Simple protocol description. Note that it does not implement other layer 4 protocols as
/// IGMP et al. See [`Rule::igmp`] for a workaround.
#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP
}

/// A Match trait over [`rustables::Rule`], to make it match some criteria, and give it a verdict.
/// Mostly adapted from [talpid-core's
/// firewall](https://github.com/mullvad/mullvadvpn-app/blob/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs).
/// All methods return the rule itself, allowing them to be chained. Usage example :
/// ```rust
/// use rustables::{Batch, Chain, Match, Protocol, Rule, ProtoFamily, Table, MsgType, Hook};
/// use std::ffi::CString;
/// use std::rc::Rc;
/// let table = Rc::new(Table::new(&CString::new("main_table").unwrap(), ProtoFamily::Inet));
/// let mut batch = Batch::new();
/// batch.add(&table, MsgType::Add);
/// let mut inbound = Chain::new(&CString::new("inbound").unwrap(), table);
/// inbound.set_hook(Hook::In, 0);
/// let inbound = Rc::new(inbound);
/// batch.add(&inbound, MsgType::Add);
/// let rule = Rule::new(inbound)
///                 .dport("80", &Protocol::TCP).unwrap()
///                 .accept();
/// batch.add(&rule, MsgType::Add);
/// ```
pub trait Match {
    /// Match ICMP packets.
    fn icmp(self) -> Self;
    /// Match IGMP packets.
    fn igmp(self) -> Self;
    /// Match packets to destination `port` and `protocol`.
    fn dport(self, port: &str, protocol: &Protocol) -> Result<Self, Error>
        where Self: std::marker::Sized;
    /// Match packets on `protocol`.
    fn protocol(self, protocol: Protocol) -> Result<Self, Error>
        where Self: std::marker::Sized;
    /// Match packets in an already established connections.
    fn established(self) -> Self where Self: std::marker::Sized;
    /// Match packets going through `iface_index`. Interface indexes can be queried with
    /// `iface_index()`.
    fn iface_id(self, iface_index: libc::c_uint) -> Result<Self, Error>
        where Self: std::marker::Sized;
    /// Match packets going through `iface_name`, an interface name, as in "wlan0" or "lo".
    fn iface(self, iface_name: &str) -> Result<Self, Error>
        where Self: std::marker::Sized;
    /// Add a log instruction to the rule. `group` is the NFLog group, `prefix` is a prefix
    /// appended to each log line.
    fn log(self, group: Option<LogGroup>, prefix: Option<LogPrefix>) -> Self;
    /// Match packets whose source IP address is `saddr`.
    fn saddr(self, ip: IpAddr) -> Self;
    /// Match packets whose source network is `snet`.
    fn snetwork(self, ip: IpNetwork) -> Self;
    /// Add the `Accept` verdict to the rule. The packet will be sent to destination.
    fn accept(self) -> Self;
    /// Add the `Drop` verdict to the rule. The packet will be dropped.
    fn drop(self) -> Self;
    /// Append rule to `batch`.
    fn add_to_batch(self, batch: &mut Batch) -> Self;
}

/// A trait to add helper functions to match some criterium over `rustables::Rule`.
impl Match for Rule {
    fn icmp(mut self) -> Self {
        self.add_expr(&nft_expr!(meta l4proto));
        //self.add_expr(&nft_expr!(cmp == libc::IPPROTO_ICMPV6 as u8));
        self.add_expr(&nft_expr!(cmp == libc::IPPROTO_ICMP as u8));
        self
    }
    fn igmp(mut self) -> Self {
        self.add_expr(&nft_expr!(meta l4proto));
        self.add_expr(&nft_expr!(cmp == libc::IPPROTO_IGMP as u8));
        self
    }
    fn dport(mut self, port: &str, protocol: &Protocol) -> Result<Self, Error> {
        self.add_expr(&nft_expr!(meta l4proto));
        match protocol {
            &Protocol::TCP => {
                self.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));
                self.add_expr(&nft_expr!(payload tcp dport));
            },
            &Protocol::UDP => {
                self.add_expr(&nft_expr!(cmp == libc::IPPROTO_UDP as u8));
                self.add_expr(&nft_expr!(payload udp dport));
            }
        }
        // Convert the port to Big-Endian number spelling.
        // See https://github.com/mullvad/mullvadvpn-app/blob/d92376b4d1df9b547930c68aa9bae9640ff2a022/talpid-core/src/firewall/linux.rs#L969
        self.add_expr(&nft_expr!(cmp == port.parse::<u16>()?.to_be()));
       Ok(self) 
    }
    fn protocol(mut self, protocol: Protocol) -> Result<Self, Error> {
        self.add_expr(&nft_expr!(meta l4proto));
        match protocol {
            Protocol::TCP => {
                self.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));
            },
            Protocol::UDP => {
                self.add_expr(&nft_expr!(cmp == libc::IPPROTO_UDP as u8));
            }
        }
       Ok(self) 
    }
    fn established(mut self) -> Self {
        let allowed_states = crate::expr::ct::States::ESTABLISHED.bits();
        self.add_expr(&nft_expr!(ct state));
        self.add_expr(&nft_expr!(bitwise mask allowed_states, xor 0u32));
        self.add_expr(&nft_expr!(cmp != 0u32));
        self
    }
    fn iface_id(mut self, iface_index: libc::c_uint) -> Result<Self, Error> {
        self.add_expr(&nft_expr!(meta iif));
        self.add_expr(&nft_expr!(cmp == iface_index));
        Ok(self)
    }
    fn iface(mut self, iface_name: &str) -> Result<Self, Error> {
        if iface_name.len() > libc::IFNAMSIZ {
            return Err(Error::NameTooLong);
        }

        self.add_expr(&nft_expr!(meta iifname));
        self.add_expr(&nft_expr!(cmp == CString::new(iface_name)?.as_bytes()));
        Ok(self)
    }
    fn saddr(mut self, ip: IpAddr) -> Self {
        self.add_expr(&nft_expr!(meta nfproto));
        match ip {
            IpAddr::V4(addr) => {
                self.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                self.add_expr(&nft_expr!(payload ipv4 saddr));
                self.add_expr(&nft_expr!(cmp == addr))
            },
            IpAddr::V6(addr) => {
                self.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                self.add_expr(&nft_expr!(payload ipv6 saddr));
                self.add_expr(&nft_expr!(cmp == addr))
            }
        }
        self
    }
    fn snetwork(mut self, net: IpNetwork) -> Self {
        self.add_expr(&nft_expr!(meta nfproto));
        match net {
            IpNetwork::V4(_) => {
                self.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV4 as u8));
                self.add_expr(&nft_expr!(payload ipv4 saddr));
                self.add_expr(&nft_expr!(bitwise mask net.mask(), xor 0u32));
                self.add_expr(&nft_expr!(cmp == net.network()));
            },
            IpNetwork::V6(_) => {
                self.add_expr(&nft_expr!(cmp == libc::NFPROTO_IPV6 as u8));
                self.add_expr(&nft_expr!(payload ipv6 saddr));
                self.add_expr(&nft_expr!(bitwise mask net.mask(), xor &[0u16; 8][..]));
                self.add_expr(&nft_expr!(cmp == net.network()));
            }
        }
        self
    }
    fn log(mut self, group: Option<LogGroup>, prefix: Option<LogPrefix>) -> Self {
        match (group.is_some(), prefix.is_some()) {
            (true, true) => {
                self.add_expr(&nft_expr!(log group group prefix prefix));
            },
            (false, true) => {
                self.add_expr(&nft_expr!(log prefix prefix));
            },
            (true, false) => {
                self.add_expr(&nft_expr!(log group group));
            },
            (false, false) => {
                self.add_expr(&nft_expr!(log));
            }
        }
        self
    }
    fn accept(mut self) -> Self {
        self.add_expr(&nft_expr!(verdict accept));
        self
    }
    fn drop(mut self) -> Self {
        self.add_expr(&nft_expr!(verdict drop));
        self
    }
    fn add_to_batch(self, batch: &mut Batch) -> Self {
        batch.add(&self, crate::MsgType::Add);
        self
    }
}

/// Look up the interface index for a given interface name.
pub fn iface_index(name: &str) -> Result<libc::c_uint, Error> {
    let c_name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    match index {
        0 => Err(Error::NoSuchIface),
        _ => Ok(index)
    }
}



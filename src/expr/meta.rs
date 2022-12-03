use rustables_macros::nfnetlink_struct;

use super::{Expression, Register};
use crate::{
    nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable},
    parser::DecodeError,
    sys,
};

/// A meta expression refers to meta data associated with a packet.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
#[non_exhaustive]
pub enum MetaType {
    /// Packet ethertype protocol (skb->protocol), invalid in OUTPUT.
    Protocol = sys::NFT_META_PROTOCOL,
    /// Packet mark.
    Mark = sys::NFT_META_MARK,
    /// Packet input interface index (dev->ifindex).
    Iif = sys::NFT_META_IIF,
    /// Packet output interface index (dev->ifindex).
    Oif = sys::NFT_META_OIF,
    /// Packet input interface name (dev->name).
    IifName = sys::NFT_META_IIFNAME,
    /// Packet output interface name (dev->name).
    OifName = sys::NFT_META_OIFNAME,
    /// Packet input interface type (dev->type).
    IifType = sys::NFT_META_IFTYPE,
    /// Packet output interface type (dev->type).
    OifType = sys::NFT_META_OIFTYPE,
    /// Originating socket UID (fsuid).
    SkUid = sys::NFT_META_SKUID,
    /// Originating socket GID (fsgid).
    SkGid = sys::NFT_META_SKGID,
    /// Netfilter protocol (Transport layer protocol).
    NfProto = sys::NFT_META_NFPROTO,
    /// Layer 4 protocol number.
    L4Proto = sys::NFT_META_L4PROTO,
    /// Socket control group (skb->sk->sk_classid).
    Cgroup = sys::NFT_META_CGROUP,
    /// A 32bit pseudo-random number.
    PRandom = sys::NFT_META_PRANDOM,
}

impl NfNetlinkAttribute for MetaType {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as u32).write_payload(addr);
    }
}

impl NfNetlinkDeserializable for MetaType {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (v, remaining_data) = u32::deserialize(buf)?;
        Ok((
            match v {
                sys::NFT_META_PROTOCOL => Self::Protocol,
                sys::NFT_META_MARK => Self::Mark,
                sys::NFT_META_IIF => Self::Iif,
                sys::NFT_META_OIF => Self::Oif,
                sys::NFT_META_IIFNAME => Self::IifName,
                sys::NFT_META_OIFNAME => Self::OifName,
                sys::NFT_META_IFTYPE => Self::IifType,
                sys::NFT_META_OIFTYPE => Self::OifType,
                sys::NFT_META_SKUID => Self::SkUid,
                sys::NFT_META_SKGID => Self::SkGid,
                sys::NFT_META_NFPROTO => Self::NfProto,
                sys::NFT_META_L4PROTO => Self::L4Proto,
                sys::NFT_META_CGROUP => Self::Cgroup,
                sys::NFT_META_PRANDOM => Self::PRandom,
                value => return Err(DecodeError::UnknownMetaType(value)),
            },
            remaining_data,
        ))
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct]
pub struct Meta {
    #[field(sys::NFTA_META_DREG)]
    dreg: Register,
    #[field(sys::NFTA_META_KEY)]
    key: MetaType,
    #[field(sys::NFTA_META_SREG)]
    sreg: Register,
}

impl Expression for Meta {
    fn get_name() -> &'static str {
        "meta"
    }
}

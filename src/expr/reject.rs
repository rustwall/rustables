use rustables_macros::nfnetlink_struct;

use crate::{
    nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable},
    parser::DecodeError,
    sys,
};

use super::Expression;

impl Expression for Reject {
    fn get_name() -> &'static str {
        "reject"
    }
}

#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct]
/// A reject expression that defines the type of rejection message sent when discarding a packet.
pub struct Reject {
    #[field(sys::NFTA_REJECT_TYPE, name_in_functions = "type")]
    reject_type: RejectType,
    #[field(sys::NFTA_REJECT_ICMP_CODE)]
    icmp_code: IcmpCode,
}

/// An ICMP reject code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum RejectType {
    IcmpUnreach = sys::NFT_REJECT_ICMP_UNREACH,
    TcpRst = sys::NFT_REJECT_TCP_RST,
    IcmpxUnreach = sys::NFT_REJECT_ICMPX_UNREACH,
}

impl NfNetlinkDeserializable for RejectType {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (v, remaining_code) = u32::deserialize(buf)?;
        Ok((
            match v {
                sys::NFT_REJECT_ICMP_UNREACH => Self::IcmpUnreach,
                sys::NFT_REJECT_TCP_RST => Self::TcpRst,
                sys::NFT_REJECT_ICMPX_UNREACH => Self::IcmpxUnreach,
                _ => return Err(DecodeError::UnknownRejectType(v)),
            },
            remaining_code,
        ))
    }
}

impl NfNetlinkAttribute for RejectType {
    fn get_size(&self) -> usize {
        (*self as u32).get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as u32).write_payload(addr);
    }
}

/// An ICMP reject code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum IcmpCode {
    NoRoute = sys::NFT_REJECT_ICMPX_NO_ROUTE as u8,
    PortUnreach = sys::NFT_REJECT_ICMPX_PORT_UNREACH as u8,
    HostUnreach = sys::NFT_REJECT_ICMPX_HOST_UNREACH as u8,
    AdminProhibited = sys::NFT_REJECT_ICMPX_ADMIN_PROHIBITED as u8,
}

impl NfNetlinkDeserializable for IcmpCode {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (value, remaining_code) = u8::deserialize(buf)?;
        Ok((
            match value as u32 {
                sys::NFT_REJECT_ICMPX_NO_ROUTE => Self::NoRoute,
                sys::NFT_REJECT_ICMPX_PORT_UNREACH => Self::PortUnreach,
                sys::NFT_REJECT_ICMPX_HOST_UNREACH => Self::HostUnreach,
                sys::NFT_REJECT_ICMPX_ADMIN_PROHIBITED => Self::AdminProhibited,
                _ => return Err(DecodeError::UnknownIcmpCode(value)),
            },
            remaining_code,
        ))
    }
}

impl NfNetlinkAttribute for IcmpCode {
    fn get_size(&self) -> usize {
        (*self as u8).get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as u8).write_payload(addr);
    }
}

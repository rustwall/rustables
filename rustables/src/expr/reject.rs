use super::{Expression, Rule};
use crate::ProtoFamily;
use rustables_sys::{
    self as sys,
    libc::{self, c_char},
};

/// A reject expression that defines the type of rejection message sent
/// when discarding a packet.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Reject {
    /// Return an ICMP unreachable packet
    Icmp(IcmpCode),
    /// Reject by sending a TCP RST packet
    TcpRst,
}

impl Reject {
    fn to_raw(&self, family: ProtoFamily) -> u32 {
        use libc::*;
        let value = match *self {
            Self::Icmp(..) => match family {
                ProtoFamily::Bridge | ProtoFamily::Inet => NFT_REJECT_ICMPX_UNREACH,
                _ => NFT_REJECT_ICMP_UNREACH,
            },
            Self::TcpRst => NFT_REJECT_TCP_RST,
        };
        value as u32
    }
}

impl Expression for Reject {
    fn get_raw_name() -> *const libc::c_char {
        b"reject\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self>
    where
        Self: Sized,
    {
        unsafe {
            if sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_REJECT_TYPE as u16)
                == libc::NFT_REJECT_TCP_RST as u32
            {
                Some(Self::TcpRst)
            } else {
                IcmpCode::from_raw(sys::nftnl_expr_get_u8(
                    expr,
                    sys::NFTNL_EXPR_REJECT_CODE as u16,
                ))
                .map(Self::Icmp)
            }
        }
    }

    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr {
        let family = rule.get_chain().get_table().get_family();

        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(Self::get_raw_name()));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_REJECT_TYPE as u16,
                self.to_raw(family),
            );

            let reject_code = match *self {
                Reject::Icmp(code) => code as u8,
                Reject::TcpRst => 0,
            };

            sys::nftnl_expr_set_u8(expr, sys::NFTNL_EXPR_REJECT_CODE as u16, reject_code);

            expr
        }
    }
}

/// An ICMP reject code.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum IcmpCode {
    NoRoute = libc::NFT_REJECT_ICMPX_NO_ROUTE as u8,
    PortUnreach = libc::NFT_REJECT_ICMPX_PORT_UNREACH as u8,
    HostUnreach = libc::NFT_REJECT_ICMPX_HOST_UNREACH as u8,
    AdminProhibited = libc::NFT_REJECT_ICMPX_ADMIN_PROHIBITED as u8,
}

impl IcmpCode {
    fn from_raw(code: u8) -> Option<Self> {
        match code as i32 {
            libc::NFT_REJECT_ICMPX_NO_ROUTE => Some(Self::NoRoute),
            libc::NFT_REJECT_ICMPX_PORT_UNREACH => Some(Self::PortUnreach),
            libc::NFT_REJECT_ICMPX_HOST_UNREACH => Some(Self::HostUnreach),
            libc::NFT_REJECT_ICMPX_ADMIN_PROHIBITED => Some(Self::AdminProhibited),
            _ => None,
        }
    }
}

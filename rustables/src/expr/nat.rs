use super::{Expression, Register, Rule};
use crate::ProtoFamily;
use rustables_sys::{self as sys, libc};
use std::{convert::TryFrom, os::raw::c_char};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum NatType {
    /// Source NAT. Changes the source address of a packet
    SNat = libc::NFT_NAT_SNAT,
    /// Destination NAT. Changeth the destination address of a packet
    DNat = libc::NFT_NAT_DNAT,
}

impl NatType {
    fn from_raw(val: u32) -> Option<Self> {
        match val as i32 {
            libc::NFT_NAT_SNAT => Some(NatType::SNat),
            libc::NFT_NAT_DNAT => Some(NatType::DNat),
            _ => None,
        }
    }
}

/// A source or destination NAT statement. Modifies the source or destination address
/// (and possibly port) of packets.
#[derive(Debug, PartialEq)]
pub struct Nat {
    pub nat_type: NatType,
    pub family: ProtoFamily,
    pub ip_register: Register,
    pub port_register: Option<Register>,
}

impl Expression for Nat {
    fn get_raw_name() -> *const libc::c_char {
        b"nat\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self>
    where
        Self: Sized,
    {
        unsafe {
            let nat_type = NatType::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_TYPE as u16,
            ));
            let nat_type = match nat_type {
                Some(x) => x,
                None => return None,
            };

            let family = ProtoFamily::try_from(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_FAMILY as u16,
            ) as i32);
            let family = match family {
                Ok(x) => x,
                Err(_) => return None,
            };

            let ip_register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_REG_ADDR_MIN as u16,
            ));
            let ip_register = match ip_register {
                Some(x) => x,
                None => return None,
            };

            let mut port_register = None;
            if sys::nftnl_expr_is_set(expr, sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16) {
                port_register = Register::from_raw(sys::nftnl_expr_get_u32(
                    expr,
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16,
                ));
                if port_register.is_none() {
                    trace!("Invalid register in expression 'nat'");
                }
            }

            Some(Nat {
                ip_register,
                nat_type,
                family,
                port_register,
            })
        }
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        let expr = try_alloc!(unsafe { sys::nftnl_expr_alloc(Self::get_raw_name()) });

        unsafe {
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_NAT_TYPE as u16, self.nat_type as u32);
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_NAT_FAMILY as u16, self.family as u32);
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_NAT_REG_ADDR_MIN as u16,
                self.ip_register.to_raw(),
            );
            if let Some(port_register) = self.port_register {
                sys::nftnl_expr_set_u32(
                    expr,
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16,
                    port_register.to_raw(),
                );
            }
        }

        expr
    }
}

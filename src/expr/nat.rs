use rustables_macros::{nfnetlink_enum, nfnetlink_struct};

use super::{Expression, Register};
use crate::{
    sys::{self, NFT_NAT_DNAT, NFT_NAT_SNAT},
    ProtocolFamily,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[nfnetlink_enum(i32)]
pub enum NatType {
    /// Source NAT. Changes the source address of a packet.
    SNat = NFT_NAT_SNAT,
    /// Destination NAT. Changes the destination address of a packet.
    DNat = NFT_NAT_DNAT,
}

/// A source or destination NAT statement. Modifies the source or destination address (and possibly
/// port) of packets.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[nfnetlink_struct(nested = true)]
pub struct Nat {
    #[field(sys::NFTA_NAT_TYPE)]
    pub nat_type: NatType,
    #[field(sys::NFTA_NAT_FAMILY)]
    pub family: ProtocolFamily,
    #[field(sys::NFTA_NAT_REG_ADDR_MIN)]
    pub ip_register: Register,
    #[field(sys::NFTA_NAT_REG_PROTO_MIN)]
    pub port_register: Register,
}

impl Expression for Nat {
    fn get_name() -> &'static str {
        "nat"
    }
}
/*

    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        unsafe {
            let nat_type = NatType::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_TYPE as u16,
            ))?;

            let family = ProtoFamily::try_from(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_FAMILY as u16,
            ) as i32)?;

            let ip_register = Register::from_raw(sys::nftnl_expr_get_u32(
                expr,
                sys::NFTNL_EXPR_NAT_REG_ADDR_MIN as u16,
            ))?;

            let mut port_register = None;
            if sys::nftnl_expr_is_set(expr, sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16) {
                port_register = Some(Register::from_raw(sys::nftnl_expr_get_u32(
                    expr,
                    sys::NFTNL_EXPR_NAT_REG_PROTO_MIN as u16,
                ))?);
            }

            Ok(Nat {
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
*/

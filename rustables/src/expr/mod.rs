//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use std::borrow::Cow;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use super::rule::Rule;
use rustables_sys::{self as sys, libc};
use thiserror::Error;

mod bitwise;
pub use self::bitwise::*;

mod cmp;
pub use self::cmp::*;

mod counter;
pub use self::counter::*;

pub mod ct;
pub use self::ct::*;

mod immediate;
pub use self::immediate::*;

mod log;
pub use self::log::*;

mod lookup;
pub use self::lookup::*;

mod masquerade;
pub use self::masquerade::*;

mod meta;
pub use self::meta::*;

mod nat;
pub use self::nat::*;

mod payload;
pub use self::payload::*;

mod reject;
pub use self::reject::{IcmpCode, Reject};

mod register;
pub use self::register::Register;

mod verdict;
pub use self::verdict::*;

mod wrapper;
pub use self::wrapper::ExpressionWrapper;

#[derive(Debug, Error)]
pub enum DeserializationError {
    #[error("The expected expression type doesn't match the name of the raw expression")]
    /// The expected expression type doesn't match the name of the raw expression
    InvalidExpressionKind,

    #[error("Deserializing the requested type isn't implemented yet")]
    /// Deserializing the requested type isn't implemented yet
    NotImplemented,

    #[error("The expression value cannot be deserialized to the requested type")]
    /// The expression value cannot be deserialized to the requested type
    InvalidValue,

    #[error("A pointer was null while a non-null pointer was expected")]
    /// A pointer was null while a non-null pointer was expected
    NullPointer,

    #[error(
        "The size of a raw value was incoherent with the expected type of the deserialized value"
    )]
    /// The size of a raw value was incoherent with the expected type of the deserialized value
    InvalidDataSize,

    #[error(transparent)]
    /// Couldn't find a matching protocol
    InvalidProtolFamily(#[from] super::InvalidProtocolFamily),
}

/// Trait for every safe wrapper of an nftables expression.
pub trait Expression {
    /// Returns the raw name used by nftables to identify the rule.
    fn get_raw_name() -> *const libc::c_char;

    /// Try to parse the expression from a raw nftables expression,
    /// returning a [DeserializationError] if the attempted parsing failed.
    fn from_expr(_expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        Err(DeserializationError::NotImplemented)
    }

    /// Allocates and returns the low level `nftnl_expr` representation of this expression.
    /// The caller to this method is responsible for freeing the expression.
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr;
}

/// A type that can be converted into a byte buffer.
pub trait ToSlice {
    /// Returns the data this type represents.
    fn to_slice(&self) -> Cow<'_, [u8]>;
}

impl<'a> ToSlice for &'a [u8] {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

impl<'a> ToSlice for &'a [u16] {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let ptr = self.as_ptr() as *const u8;
        let len = self.len() * 2;
        Cow::Borrowed(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

impl ToSlice for IpAddr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        match *self {
            IpAddr::V4(ref addr) => addr.to_slice(),
            IpAddr::V6(ref addr) => addr.to_slice(),
        }
    }
}

impl ToSlice for Ipv4Addr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.octets().to_vec())
    }
}

impl ToSlice for Ipv6Addr {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.octets().to_vec())
    }
}

impl ToSlice for u8 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::Owned(vec![*self])
    }
}

impl ToSlice for u16 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = (*self & 0x00ff) as u8;
        let b1 = (*self >> 8) as u8;
        Cow::Owned(vec![b0, b1])
    }
}

impl ToSlice for u32 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = *self as u8;
        let b1 = (*self >> 8) as u8;
        let b2 = (*self >> 16) as u8;
        let b3 = (*self >> 24) as u8;
        Cow::Owned(vec![b0, b1, b2, b3])
    }
}

impl ToSlice for i32 {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        let b0 = *self as u8;
        let b1 = (*self >> 8) as u8;
        let b2 = (*self >> 16) as u8;
        let b3 = (*self >> 24) as u8;
        Cow::Owned(vec![b0, b1, b2, b3])
    }
}

impl<'a> ToSlice for &'a str {
    fn to_slice(&self) -> Cow<'_, [u8]> {
        Cow::from(self.as_bytes())
    }
}

#[macro_export(local_inner_macros)]
macro_rules! nft_expr {
    (bitwise mask $mask:expr,xor $xor:expr) => {
        nft_expr_bitwise!(mask $mask, xor $xor)
    };
    (cmp $op:tt $data:expr) => {
        nft_expr_cmp!($op $data)
    };
    (counter) => {
        $crate::expr::Counter { nb_bytes: 0, nb_packets: 0}
    };
    (ct $key:ident set) => {
        nft_expr_ct!($key set)
    };
    (ct $key:ident) => {
        nft_expr_ct!($key)
    };
    (immediate $expr:ident $value:expr) => {
        nft_expr_immediate!($expr $value)
    };
    (log group $group:ident prefix $prefix:expr) => {
        nft_expr_log!(group $group prefix $prefix)
    };
    (log group $group:ident) => {
        nft_expr_log!(group $group)
    };
    (log prefix $prefix:expr) => {
        nft_expr_log!(prefix $prefix)
    };
    (log) => {
        nft_expr_log!()
    };
    (lookup $set:expr) => {
        nft_expr_lookup!($set)
    };
    (masquerade) => {
        $crate::expr::Masquerade
    };
    (meta $expr:ident set) => {
        nft_expr_meta!($expr set)
    };
    (meta $expr:ident) => {
        nft_expr_meta!($expr)
    };
    (payload $proto:ident $field:ident) => {
        nft_expr_payload!($proto $field)
    };
    (verdict $verdict:ident) => {
        nft_expr_verdict!($verdict)
    };
    (verdict $verdict:ident $chain:expr) => {
        nft_expr_verdict!($verdict $chain)
    };
}

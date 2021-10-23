//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use super::rule::Rule;
use rustables_sys::{self as sys, libc};

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

/// Trait for every safe wrapper of an nftables expression.
pub trait Expression {
    /// Returns the raw name used by nftables to identify the rule.
    fn get_raw_name() -> *const libc::c_char;

    /// Try to parse the expression from a raw nftables expression,
    /// returning None if the attempted parsing failed.
    fn from_expr(_expr: *const sys::nftnl_expr) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }

    /// Allocates and returns the low level `nftnl_expr` representation of this expression.
    /// The caller to this method is responsible for freeing the expression.
    fn to_expr(&self, rule: &Rule) -> *mut sys::nftnl_expr;
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

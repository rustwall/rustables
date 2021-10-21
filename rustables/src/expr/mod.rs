//! A module with all the nftables expressions that can be added to [`Rule`]s to build up how
//! they match against packets.
//!
//! [`Rule`]: struct.Rule.html

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Debug;
use std::rc::Rc;

use super::rule::Rule;
use rustables_sys::{self as sys, libc};

pub struct ExpressionWrapper {
    pub(crate) expr: *const sys::nftnl_expr,
    // we also need the rule here to ensure that the rule lives as long as the `expr` pointer
    #[allow(dead_code)]
    pub(crate) rule: Rc<Rule>,
}

impl Debug for ExpressionWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.get_str())
    }
}

impl ExpressionWrapper {
    /// Retrieves a textual description of the expression.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_expr_snprintf(
                descr_buf.as_mut_ptr(),
                (descr_buf.len() - 1) as u64,
                self.expr,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr()).to_owned()
        }
    }

    /// Retrieves the type of expression ("log", "counter", ...).
    pub fn get_kind(&self) -> Option<&CStr> {
        unsafe {
            let ptr = sys::nftnl_expr_get_str(self.expr, sys::NFTNL_EXPR_NAME as u16);
            if !ptr.is_null() {
                Some(CStr::from_ptr(ptr))
            } else {
                None
            }
        }
    }

    /// Attempt to decode the expression as the type T, returning None if such
    /// conversion is not possible or failed.
    pub fn decode_expr<T: Expression>(&self) -> Option<T> {
        if let Some(kind) = self.get_kind() {
            let raw_name = unsafe { CStr::from_ptr(T::get_raw_name()) };
            if kind == raw_name {
                return T::from_expr(self.expr);
            }
        }
        None
    }
}

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

/// A netfilter data register. The expressions store and read data to and from these
/// when evaluating rule statements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum Register {
    Reg1 = libc::NFT_REG_1,
    Reg2 = libc::NFT_REG_2,
    Reg3 = libc::NFT_REG_3,
    Reg4 = libc::NFT_REG_4,
}

impl Register {
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

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

mod verdict;
pub use self::verdict::*;

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

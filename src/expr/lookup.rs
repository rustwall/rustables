use super::{DeserializationError, Expression, Rule};
use crate::set::Set;
use crate::sys::{self, libc};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[derive(Debug, PartialEq)]
pub struct Lookup {
    set_name: CString,
    set_id: u32,
}

impl Lookup {
    /// Creates a new lookup entry. May return None if the set has no name.
    pub fn new<K>(set: &Set<K>) -> Option<Self> {
        set.get_name().map(|set_name| Lookup {
            set_name: set_name.to_owned(),
            set_id: set.get_id(),
        })
    }
}

impl Expression for Lookup {
    fn get_raw_name() -> *const libc::c_char {
        b"lookup\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        unsafe {
            let set_name = sys::nftnl_expr_get_str(expr, sys::NFTNL_EXPR_LOOKUP_SET as u16);
            let set_id = sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_LOOKUP_SET_ID as u16);

            if set_name.is_null() {
                return Err(DeserializationError::NullPointer);
            }

            let set_name = CStr::from_ptr(set_name).to_owned();

            Ok(Lookup { set_id, set_name })
        }
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(Self::get_raw_name()));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_LOOKUP_SREG as u16,
                libc::NFT_REG_1 as u32,
            );
            sys::nftnl_expr_set_str(
                expr,
                sys::NFTNL_EXPR_LOOKUP_SET as u16,
                self.set_name.as_ptr() as *const _ as *const c_char,
            );
            sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_LOOKUP_SET_ID as u16, self.set_id);

            // This code is left here since it's quite likely we need it again when we get further
            // if self.reverse {
            //     sys::nftnl_expr_set_u32(expr, sys::NFTNL_EXPR_LOOKUP_FLAGS as u16,
            //         libc::NFT_LOOKUP_F_INV as u32);
            // }

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_lookup {
    ($set:expr) => {
        $crate::expr::Lookup::new($set)
    };
}

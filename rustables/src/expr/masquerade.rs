use super::{DeserializationError, Expression, Rule};
use rustables_sys as sys;
use std::os::raw::c_char;

/// Sets the source IP to that of the output interface.
#[derive(Debug, PartialEq)]
pub struct Masquerade;

impl Expression for Masquerade {
    fn get_raw_name() -> *const sys::libc::c_char {
        b"masq\0" as *const _ as *const c_char
    }

    fn from_expr(_expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        Ok(Masquerade)
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        try_alloc!(unsafe { sys::nftnl_expr_alloc(Self::get_raw_name()) })
    }
}

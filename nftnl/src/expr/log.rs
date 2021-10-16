use super::{Expression, Rule};
use nftnl_sys as sys;
use std::os::raw::c_char;

/// A Log expression will log all packets that match the rule.
pub struct Log;

impl Expression for Log {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        try_alloc!(unsafe { sys::nftnl_expr_alloc(b"log\0" as *const _ as *const c_char) })
    }
}

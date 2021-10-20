use super::{Expression, Rule};
use rustables_sys as sys;
use std::os::raw::c_char;

/// A counter expression adds a counter to the rule that is incremented to count number of packets
/// and number of bytes for all packets that has matched the rule.
pub struct Counter {
    pub nb_bytes: u64,
    pub nb_packets: u64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            nb_bytes: 0,
            nb_packets: 0,
        }
    }
}

impl Expression for Counter {
    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"counter\0" as *const _ as *const c_char
            ));
            sys::nftnl_expr_set_u64(expr, sys::NFTNL_EXPR_CTR_BYTES as u16, self.nb_bytes);
            sys::nftnl_expr_set_u64(expr, sys::NFTNL_EXPR_CTR_PACKETS as u16, self.nb_packets);
            expr
        }
    }
}

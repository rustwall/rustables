use super::{DeserializationError, Expression, Rule};
use rustables_sys as sys;
use std::os::raw::c_char;

/// A counter expression adds a counter to the rule that is incremented to count number of packets
/// and number of bytes for all packets that has matched the rule.
#[derive(Debug, PartialEq)]
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
    fn get_raw_name() -> *const c_char {
        b"counter\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Result<Self, DeserializationError> {
        unsafe {
            let nb_bytes = sys::nftnl_expr_get_u64(expr, sys::NFTNL_EXPR_CTR_BYTES as u16);
            let nb_packets = sys::nftnl_expr_get_u64(expr, sys::NFTNL_EXPR_CTR_PACKETS as u16);
            Ok(Counter {
                nb_bytes,
                nb_packets,
            })
        }
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(Self::get_raw_name()));
            sys::nftnl_expr_set_u64(expr, sys::NFTNL_EXPR_CTR_BYTES as u16, self.nb_bytes);
            sys::nftnl_expr_set_u64(expr, sys::NFTNL_EXPR_CTR_PACKETS as u16, self.nb_packets);
            expr
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Expression;
    use std::ffi::CString;
    use std::rc::Rc;

    #[test]
    fn counter_expr_is_valid() {
        let mut counter = super::Counter::new();
        counter.nb_bytes = 0;
        counter.nb_packets = 0;
        let table = Rc::new(crate::Table::new(
                &CString::new("mocktable").unwrap(),
                crate::ProtoFamily::Inet)
        );
        let chain = Rc::new(crate::Chain::new(
                &CString::new("mockchain").unwrap(),
                Rc::clone(&table))
        );
        let rule = crate::Rule::new(Rc::clone(&chain));
        let view = &counter.to_expr(&rule) as *const _ as *const u8;
        let slice = unsafe {
            std::slice::from_raw_parts(view, std::mem::size_of::<super::Counter>())
        };
        assert_eq!(slice[0], 64);
        assert_eq!(slice[1], 15);
        assert_eq!(slice[2], 0);
        assert_eq!(slice[5], 127);
        assert_eq!(slice[6], 0);
        assert_eq!(slice[7], 0);
        assert_eq!(slice[8], 200);
        assert_eq!(slice[13], 127);
        assert_eq!(slice[14], 0);
        assert_eq!(slice[15], 0);
        //assert_eq!(slice, [64, 15, 0, 1, 1, 127, 0, 0, 200, 1, 1, 1, 1, 127, 0, 0]);
    }
}

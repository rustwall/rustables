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
    use crate::{nft_nlmsg_maxsize, NlMsg};

    use rustables_sys as sys;
    use std::ffi::{c_void, CString};
    use std::mem::size_of;
    use std::rc::Rc;
    use sys::libc::{nlmsghdr, AF_UNIX, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE};

    fn get_subsystem_from_nlmsghdr_type(x: u16) -> u8 {
        ((x & 0xff00) >> 8) as u8
    }
    fn get_operation_from_nlmsghdr_type(x: u16) -> u8 {
        (x & 0x00ff) as u8
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct nfgenmsg {
        family: u8,  /* AF_xxx */
        version: u8, /* nfnetlink version */
        res_id: u16, /* resource id */
    }

    #[test]
    fn counter_expr_is_valid() {
        let mut counter = super::Counter::new();
        counter.nb_bytes = 0;
        counter.nb_packets = 0;
        let table = Rc::new(crate::Table::new(
            &CString::new("mocktable").unwrap(),
            crate::ProtoFamily::Inet,
        ));
        let chain = Rc::new(crate::Chain::new(
            &CString::new("mockchain").unwrap(),
            Rc::clone(&table),
        ));
        let mut rule = crate::Rule::new(Rc::clone(&chain));
        rule.add_expr(&counter);
        let mut buf = vec![0u8; nft_nlmsg_maxsize() as usize];
        let (nlmsghdr, nfgenmsg, raw_expr) = unsafe {
            rule.write(buf.as_mut_ptr() as *mut c_void, 0, crate::MsgType::Add);

            // right now the message is composed of the following parts:
            // - nlmsghdr (contain the message size and type)
            // - nfgenmsg (nftables header that describe the family)
            // - the raw expression that we want to check

            let size_of_hdr = size_of::<nlmsghdr>();
            let size_of_nfgenmsg = size_of::<nfgenmsg>();
            let nlmsghdr = *(buf[0..size_of_hdr].as_ptr() as *const nlmsghdr);
            let nfgenmsg =
                *(buf[size_of_hdr..size_of_hdr + size_of_nfgenmsg].as_ptr() as *const nfgenmsg);
            (
                nlmsghdr,
                nfgenmsg,
                &buf[size_of_hdr + size_of_nfgenmsg..nlmsghdr.nlmsg_len as usize],
            )
        };

        // sanity checks on the global message (this should be very similar/factorisable for the
        // most part in other tests)
        assert_eq!(nlmsghdr.nlmsg_len, 100);
        // TODO: check the messages flags
        assert_eq!(
            get_subsystem_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
            NFNL_SUBSYS_NFTABLES as u8
        );
        assert_eq!(
            get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
            NFT_MSG_NEWRULE as u8
        );
        assert_eq!(nlmsghdr.nlmsg_seq, 0);
        assert_eq!(nlmsghdr.nlmsg_pid, 0);
        assert_eq!(nfgenmsg.family, AF_UNIX as u8);
        assert_eq!(nfgenmsg.version, 0);
        assert_eq!(nfgenmsg.res_id.to_be(), 0);

        // check the expression content itself
        assert_eq!(
            raw_expr,
            &[
                0xe, 0x0, 0x1, 0x0, 0x6d, 0x6f, 0x63, 0x6b, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x0, 0x0,
                0x0, 0xe, 0x0, 0x2, 0x0, 0x6d, 0x6f, 0x63, 0x6b, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x0,
                0x0, 0x0, 0x30, 0x0, 0x4, 0x80, 0x2c, 0x0, 0x1, 0x80, 0xc, 0x0, 0x1, 0x0, 0x63,
                0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x0, 0x1c, 0x0, 0x2, 0x80, 0xc, 0x0, 0x1, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0
            ]
        );
    }
}

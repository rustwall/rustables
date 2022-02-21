#![allow(dead_code)]
use libc::{nlmsghdr, AF_UNIX};
use rustables::query::{parse_nlmsg, Nfgenmsg};
use rustables::set::SetKey;
use rustables::{nft_nlmsg_maxsize, Chain, MsgType, NlMsg, ProtoFamily, Rule, Set, Table};
use std::ffi::{c_void, CStr};
use std::rc::Rc;

pub const TABLE_NAME: &[u8; 10] = b"mocktable\0";
pub const CHAIN_NAME: &[u8; 10] = b"mockchain\0";
pub const SET_NAME: &[u8; 8] = b"mockset\0";

pub const TABLE_USERDATA: &[u8; 14] = b"mocktabledata\0";
pub const CHAIN_USERDATA: &[u8; 14] = b"mockchaindata\0";
pub const RULE_USERDATA: &[u8; 13] = b"mockruledata\0";
pub const SET_USERDATA: &[u8; 12] = b"mocksetdata\0";

pub const SET_ID: u32 = 123456;

type NetLinkType = u16;

#[derive(Debug, thiserror::Error)]
#[error("empty data")]
pub struct EmptyDataError;

#[derive(Debug, PartialEq)]
pub enum NetlinkExpr {
    Nested(NetLinkType, Vec<NetlinkExpr>),
    Final(NetLinkType, Vec<u8>),
    List(Vec<NetlinkExpr>),
}

impl NetlinkExpr {
    pub fn to_raw(self) -> Vec<u8> {
        match self {
            NetlinkExpr::Final(ty, val) => {
                let len = val.len() + 4;
                let mut res = Vec::with_capacity(len);

                res.extend(&(len as u16).to_le_bytes());
                res.extend(&ty.to_le_bytes());
                res.extend(val);
                // alignment
                while res.len() % 4 != 0 {
                    res.push(0);
                }

                res
            }
            NetlinkExpr::Nested(ty, exprs) => {
                // some heuristic to decrease allocations (even though this is
                // only useful for testing so performance is not an objective)
                let mut sub = Vec::with_capacity(exprs.len() * 50);

                for expr in exprs {
                    sub.append(&mut expr.to_raw());
                }

                let len = sub.len() + 4;
                let mut res = Vec::with_capacity(len);

                // set the "NESTED" flag
                res.extend(&(len as u16).to_le_bytes());
                res.extend(&(ty | 0x8000).to_le_bytes());
                res.extend(sub);

                res
            }
            NetlinkExpr::List(exprs) => {
                // some heuristic to decrease allocations (even though this is
                // only useful for testing so performance is not an objective)
                let mut list = Vec::with_capacity(exprs.len() * 50);

                for expr in exprs {
                    list.append(&mut expr.to_raw());
                }

                list
            }
        }
    }
}

pub fn get_test_table() -> Table {
    Table::new(
        &CStr::from_bytes_with_nul(TABLE_NAME).unwrap(),
        ProtoFamily::Inet,
    )
}

pub fn get_test_chain() -> Chain {
    Chain::new(
        &CStr::from_bytes_with_nul(CHAIN_NAME).unwrap(),
        Rc::new(get_test_table()),
    )
}

pub fn get_test_rule() -> Rule {
    Rule::new(Rc::new(get_test_chain()))
}

pub fn get_test_set<T: SetKey>() -> Set<T> {
    Set::new(
        CStr::from_bytes_with_nul(SET_NAME).unwrap(),
        SET_ID,
        Rc::new(get_test_table()),
    )
}

pub fn get_test_nlmsg_with_msg_type(
    obj: &mut dyn NlMsg,
    msg_type: MsgType,
) -> (nlmsghdr, Nfgenmsg, Vec<u8>) {
    let mut buf = vec![0u8; nft_nlmsg_maxsize() as usize];
    unsafe {
        obj.write(buf.as_mut_ptr() as *mut c_void, 0, msg_type);

        let (nlmsghdr, msg) = parse_nlmsg(&buf, 0, 0).expect("Couldn't parse the message");

        let (nfgenmsg, raw_value) = match msg {
            rustables::query::NlMsg::NfGenMsg(nfgenmsg, raw_value) => (nfgenmsg, raw_value),
            _ => panic!("Invalid return value type, expected a valid message"),
        };

        // sanity checks on the global message (this should be very similar/factorisable for the
        // most part in other tests)
        // TODO: check the messages flags
        assert_eq!(nfgenmsg.family, AF_UNIX as u8);
        assert_eq!(nfgenmsg.res_id.to_be(), 0);

        (*nlmsghdr, *nfgenmsg, raw_value.to_owned())
    }
}

pub fn get_test_nlmsg(obj: &mut dyn NlMsg) -> (nlmsghdr, Nfgenmsg, Vec<u8>) {
    get_test_nlmsg_with_msg_type(obj, MsgType::Add)
}

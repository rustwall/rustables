#![allow(dead_code)]
use libc::{nlmsghdr, AF_UNIX};
use rustables::nlmsg::{NfNetlinkObject, NfNetlinkWriter, Nfgenmsg};
use rustables::parser::nft_nlmsg_maxsize;
use rustables::query::parse_nlmsg;
//use rustables::set::SetKey;
use rustables::{MsgType, ProtoFamily, Table};
//use rustables::{nft_nlmsg_maxsize, Chain, MsgType, NlMsg, ProtoFamily, Rule, Set, Table};
use std::ffi::c_void;

pub const TABLE_NAME: &'static str = "mocktable";
pub const CHAIN_NAME: &'static str = "mockchain";
pub const SET_NAME: &'static str = "mockset";

pub const TABLE_USERDATA: &'static str = "mocktabledata";
pub const CHAIN_USERDATA: &'static str = "mockchaindata";
pub const RULE_USERDATA: &'static str = "mockruledata";
pub const SET_USERDATA: &'static str = "mocksetdata";

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
    Table::new(TABLE_NAME, ProtoFamily::Inet)
}

/*
pub fn get_test_chain() -> Chain {
    Chain::new(CHAIN_NAME, Rc::new(get_test_table()))
}

pub fn get_test_rule() -> Rule {
    Rule::new(Rc::new(get_test_chain()))
}

pub fn get_test_set<T: SetKey>() -> Set<T> {
    Set::new(SET_NAME, SET_ID, Rc::new(get_test_table()))
}
*/

pub fn get_test_nlmsg_with_msg_type(
    obj: &mut impl NfNetlinkObject,
    msg_type: MsgType,
) -> (nlmsghdr, Nfgenmsg, Vec<u8>) {
    let mut buf = Vec::with_capacity(nft_nlmsg_maxsize() as usize);
    let mut writer = NfNetlinkWriter::new(&mut buf);
    obj.add_or_remove(&mut writer, msg_type, 0);

    println!("{:?}", &buf);

    let (hdr, msg) = rustables::parser::parse_nlmsg(&buf).expect("Couldn't parse the message");

    let (nfgenmsg, raw_value) = match msg {
        rustables::parser::NlMsg::NfGenMsg(nfgenmsg, raw_value) => (nfgenmsg, raw_value),
        _ => panic!("Invalid return value type, expected a valid message"),
    };

    // sanity checks on the global message (this should be very similar/factorisable for the
    // most part in other tests)
    // TODO: check the messages flags
    assert_eq!(nfgenmsg.family, AF_UNIX as u8);
    assert_eq!(nfgenmsg.res_id.to_be(), 0);

    (hdr, *nfgenmsg, raw_value.to_owned())
}

pub fn get_test_nlmsg(obj: &mut impl NfNetlinkObject) -> (nlmsghdr, Nfgenmsg, Vec<u8>) {
    get_test_nlmsg_with_msg_type(obj, MsgType::Add)
}

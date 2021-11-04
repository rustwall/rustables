use crate::expr::{Bitwise, Counter, Expression, Log, LogGroup, LogPrefix};
use crate::{nft_nlmsg_maxsize, Chain, NlMsg, ProtoFamily, MsgType, Rule, Table};
use rustables_sys::libc::{nlmsghdr, AF_UNIX, NFNETLINK_V0, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWRULE};
use std::ffi::{c_void, CStr};
use std::mem::size_of;
use std::rc::Rc;
use std::net::Ipv4Addr;
//use ipnetwork::IpNetwork;
use thiserror::Error;

mod sys;
use sys::*;

fn get_subsystem_from_nlmsghdr_type(x: u16) -> u8 {
    ((x & 0xff00) >> 8) as u8
}
fn get_operation_from_nlmsghdr_type(x: u16) -> u8 {
    (x & 0x00ff) as u8
}

const TABLE_NAME: &[u8; 10] = b"mocktable\0";
const CHAIN_NAME: &[u8; 10] = b"mockchain\0";

type NetLinkType = u16;

#[derive(Debug, PartialEq)]
enum NetlinkExpr {
    Nested(NetLinkType, Vec<NetlinkExpr>),
    Final(NetLinkType, Vec<u8>),
    List(Vec<NetlinkExpr>),
}

#[derive(Debug, Error)]
#[error("empty data")]
struct EmptyDataError;

impl NetlinkExpr {
    fn to_raw(self) -> Result<Vec<u8>, EmptyDataError> {
        match self {
            NetlinkExpr::Final(ty, val) => {
                if val.len() == 0 {
                    return Err(EmptyDataError);
                }

                let len = val.len() + 4;
                let mut res = Vec::with_capacity(len);

                res.extend(&(len as u16).to_le_bytes());
                res.extend(&ty.to_le_bytes());
                res.extend(val);
                // alignment
                while res.len() % 4 != 0 {
                    res.push(0);
                }

                Ok(res)
            }
            NetlinkExpr::Nested(ty, exprs) => {
                if exprs.len() == 0 {
                    return Err(EmptyDataError);
                }

                // some heuristic to decrease allocations (even though this is
                // only useful for testing so performance is not an objective)
                let mut sub = Vec::with_capacity(exprs.len() * 50);

                for expr in exprs {
                    sub.append(&mut expr.to_raw()?);
                }

                let len = sub.len() + 4;
                let mut res = Vec::with_capacity(len);

                // set the "NESTED" flag
                res.extend(&(len as u16).to_le_bytes());
                res.extend(&(ty | 0x8000).to_le_bytes());
                res.extend(sub);

                Ok(res)
            }
            NetlinkExpr::List(exprs) => {
                if exprs.len() == 0 {
                    return Err(EmptyDataError);
                }

                // some heuristic to decrease allocations (even though this is
                // only useful for testing so performance is not an objective)
                let mut list = Vec::with_capacity(exprs.len() * 50);

                for expr in exprs {
                    list.append(&mut expr.to_raw()?);
                }

                Ok(list)
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Nfgenmsg {
    family: u8,  /* AF_xxx */
    version: u8, /* nfnetlink version */
    res_id: u16, /* resource id */
}

fn get_test_rule() -> Rule {
    let table = Rc::new(Table::new(
        &CStr::from_bytes_with_nul(TABLE_NAME).unwrap(),
        ProtoFamily::Inet,
    ));
    let chain = Rc::new(Chain::new(
        &CStr::from_bytes_with_nul(CHAIN_NAME).unwrap(),
        Rc::clone(&table),
    ));
    let rule = Rule::new(Rc::clone(&chain));
    rule
}

fn get_test_nlmsg_from_expr(rule: &mut Rule, expr: &impl Expression) -> (nlmsghdr, Nfgenmsg, Vec<u8>){
    rule.add_expr(expr);

    let mut buf = vec![0u8; nft_nlmsg_maxsize() as usize];
    unsafe {
        rule.write(buf.as_mut_ptr() as *mut c_void, 0, MsgType::Add);

        // right now the message is composed of the following parts:
        // - nlmsghdr (contain the message size and type)
        // - nfgenmsg (nftables header that describe the family)
        // - the raw expression that we want to check

        let size_of_hdr = size_of::<nlmsghdr>();
        let size_of_nfgenmsg = size_of::<Nfgenmsg>();
        let nlmsghdr = *(buf[0..size_of_hdr].as_ptr() as *const nlmsghdr);
        let nfgenmsg =
            *(buf[size_of_hdr..size_of_hdr + size_of_nfgenmsg].as_ptr() as *const Nfgenmsg);
        let raw_expr = buf[size_of_hdr + size_of_nfgenmsg..nlmsghdr.nlmsg_len as usize]
                          .iter().map(|x| *x).collect();

        // sanity checks on the global message (this should be very similar/factorisable for the
        // most part in other tests)
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
        assert_eq!(nfgenmsg.version, NFNETLINK_V0 as u8);
        assert_eq!(nfgenmsg.res_id.to_be(), 0);

        (
            nlmsghdr,
            nfgenmsg,
            raw_expr,
        )
    }
}

#[test]
fn counter_expr_is_valid() {
    let nb_bytes = 123456u64;
    let nb_packets = 987u64;
    let mut counter = Counter::new();
    counter.nb_bytes = nb_bytes;
    counter.nb_packets = nb_packets;

    let mut rule = get_test_rule();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &counter);
    assert_eq!(nlmsghdr.nlmsg_len, 100);

    // check the expression content itself
    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"counter\0".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_COUNTER_BYTES,
                                    nb_bytes.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_COUNTER_PACKETS,
                                    nb_packets.to_be_bytes().to_vec()
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
        .unwrap()
    );
}

#[test]
fn log_expr_is_valid() {
    let log = Log {
        group: Some(LogGroup(1)),
        prefix: Some(LogPrefix::new("mockprefix").unwrap())
    };
    let mut rule = get_test_rule();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &log);
    assert_eq!(nlmsghdr.nlmsg_len, 96);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"log\0".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_LOG_PREFIX,
                                    b"mockprefix\0".to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_LOG_GROUP,
                                    1u16.to_be_bytes().to_vec()
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
        .unwrap()
    );
}

#[test]
fn bitwise_expr_is_valid() {
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let bitwise = Bitwise::new(netmask, 0);
    let mut rule = get_test_rule();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &bitwise);
    assert_eq!(nlmsghdr.nlmsg_len, 124);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"bitwise\0".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_BITWISE_SREG,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_BITWISE_DREG,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_BITWISE_LEN,
                                    4u32.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Nested(
                                    NFTA_BITWISE_MASK,
                                    vec![
                                        NetlinkExpr::Final(
                                            NFTA_DATA_VALUE,
                                            vec![255, 255, 255, 0]
                                        )
                                    ]
                                ),
                                NetlinkExpr::Nested(
                                    NFTA_BITWISE_XOR,
                                    vec![
                                        NetlinkExpr::Final(
                                            NFTA_DATA_VALUE,
                                            0u32.to_be_bytes().to_vec()
                                        )
                                    ]
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
        .unwrap()
    );
}

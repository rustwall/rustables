use rustables::{
    expr::{
        Bitwise, Cmp, CmpOp, ExpressionList, HeaderField, HighLevelPayload, IcmpCode, Immediate,
        Log, Meta, MetaType, Nat, NatType, Register, Reject, RejectType, TCPHeaderField,
        TransportHeaderField, VerdictKind,
    },
    sys::{
        NFTA_BITWISE_DREG, NFTA_BITWISE_LEN, NFTA_BITWISE_MASK, NFTA_BITWISE_SREG,
        NFTA_BITWISE_XOR, NFTA_CMP_DATA, NFTA_CMP_OP, NFTA_CMP_SREG, NFTA_DATA_VALUE,
        NFTA_DATA_VERDICT, NFTA_EXPR_DATA, NFTA_EXPR_NAME, NFTA_IMMEDIATE_DATA,
        NFTA_IMMEDIATE_DREG, NFTA_LIST_ELEM, NFTA_LOG_GROUP, NFTA_LOG_PREFIX, NFTA_META_DREG,
        NFTA_META_KEY, NFTA_NAT_FAMILY, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_TYPE, NFTA_PAYLOAD_BASE,
        NFTA_PAYLOAD_DREG, NFTA_PAYLOAD_LEN, NFTA_PAYLOAD_OFFSET, NFTA_REJECT_ICMP_CODE,
        NFTA_REJECT_TYPE, NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_TABLE,
        NFTA_VERDICT_CODE, NFT_CMP_EQ, NFT_META_PROTOCOL, NFT_NAT_SNAT,
        NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, NFT_REG_VERDICT, NFT_REJECT_ICMPX_UNREACH,
    },
    ProtocolFamily,
};
//use rustables::expr::{
//    Bitwise, Cmp, CmpOp, Conntrack, Counter, Expression, HeaderField, IcmpCode, Immediate, Log,
//    LogGroup, LogPrefix, Lookup, Meta, Nat, NatType, Payload, Register, Reject, TcpHeaderField,
//    TransportHeaderField, Verdict,
//};
//use rustables::query::{get_operation_from_nlmsghdr_type, Nfgenmsg};
//use rustables::set::Set;
//use rustables::sys::libc::{nlmsghdr, NF_DROP};
//use rustables::{ProtoFamily, Rule};
//use std::ffi::CStr;
use std::net::Ipv4Addr;

use libc::NF_DROP;

mod common;
use common::*;

#[test]
fn bitwise_expr_is_valid() {
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let bitwise = Bitwise::new(netmask.octets(), [0, 0, 0, 0]).unwrap();
    let mut rule =
        get_test_rule().with_expressions(ExpressionList::default().with_expression(bitwise));

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 124);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"bitwise".to_vec()),
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
                                NetlinkExpr::Final(NFTA_BITWISE_LEN, 4u32.to_be_bytes().to_vec()),
                                NetlinkExpr::Nested(
                                    NFTA_BITWISE_MASK,
                                    vec![NetlinkExpr::Final(
                                        NFTA_DATA_VALUE,
                                        vec![255, 255, 255, 0]
                                    )]
                                ),
                                NetlinkExpr::Nested(
                                    NFTA_BITWISE_XOR,
                                    vec![NetlinkExpr::Final(
                                        NFTA_DATA_VALUE,
                                        0u32.to_be_bytes().to_vec()
                                    )]
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn cmp_expr_is_valid() {
    let val = vec![1u8, 2, 3, 4];
    let cmp = Cmp::new(CmpOp::Eq, val.clone());
    let mut rule = get_test_rule().with_expressions(vec![cmp]);

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 100);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"cmp".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(NFTA_CMP_SREG, NFT_REG_1.to_be_bytes().to_vec()),
                                NetlinkExpr::Final(NFTA_CMP_OP, NFT_CMP_EQ.to_be_bytes().to_vec()),
                                NetlinkExpr::Nested(
                                    NFTA_CMP_DATA,
                                    vec![NetlinkExpr::Final(NFTA_DATA_VALUE, val)]
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

//#[test]
//fn counter_expr_is_valid() {
//    let nb_bytes = 123456u64;
//    let nb_packets = 987u64;
//    let mut counter = Counter::new();
//    counter.nb_bytes = nb_bytes;
//    counter.nb_packets = nb_packets;
//
//    let mut rule = get_test_rule();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &counter);
//    assert_eq!(nlmsghdr.nlmsg_len, 100);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Nested(
//                NFTA_RULE_EXPRESSIONS,
//                vec![NetlinkExpr::Nested(
//                    NFTA_LIST_ELEM,
//                    vec![
//                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"counter\0".to_vec()),
//                        NetlinkExpr::Nested(
//                            NFTA_EXPR_DATA,
//                            vec![
//                                NetlinkExpr::Final(
//                                    NFTA_COUNTER_BYTES,
//                                    nb_bytes.to_be_bytes().to_vec()
//                                ),
//                                NetlinkExpr::Final(
//                                    NFTA_COUNTER_PACKETS,
//                                    nb_packets.to_be_bytes().to_vec()
//                                )
//                            ]
//                        )
//                    ]
//                )]
//            )
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn ct_expr_is_valid() {
//    let ct = Conntrack::State;
//    let mut rule = get_test_rule();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &ct);
//    assert_eq!(nlmsghdr.nlmsg_len, 88);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Nested(
//                NFTA_RULE_EXPRESSIONS,
//                vec![NetlinkExpr::Nested(
//                    NFTA_LIST_ELEM,
//                    vec![
//                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"ct\0".to_vec()),
//                        NetlinkExpr::Nested(
//                            NFTA_EXPR_DATA,
//                            vec![
//                                NetlinkExpr::Final(
//                                    NFTA_CT_KEY,
//                                    NFT_CT_STATE.to_be_bytes().to_vec()
//                                ),
//                                NetlinkExpr::Final(NFTA_CT_DREG, NFT_REG_1.to_be_bytes().to_vec())
//                            ]
//                        )
//                    ]
//                )]
//            )
//        ])
//        .to_raw()
//    )
//}
//
#[test]
fn immediate_expr_is_valid() {
    let immediate = Immediate::new_data(vec![42u8], Register::Reg1);
    let mut rule =
        get_test_rule().with_expressions(ExpressionList::default().with_expression(immediate));

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 100);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"immediate".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_IMMEDIATE_DREG,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Nested(
                                    NFTA_IMMEDIATE_DATA,
                                    vec![NetlinkExpr::Final(1u16, 42u8.to_be_bytes().to_vec())]
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn log_expr_is_valid() {
    let log = Log::new(Some(1337), Some("mockprefix")).expect("Could not build a log expression");
    let mut rule = get_test_rule().with_expressions(ExpressionList::default().with_expression(log));

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 96);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"log".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(NFTA_LOG_GROUP, 1337u16.to_be_bytes().to_vec()),
                                NetlinkExpr::Final(NFTA_LOG_PREFIX, b"mockprefix".to_vec()),
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

//#[test]
//fn lookup_expr_is_valid() {
//    let set_name = &CStr::from_bytes_with_nul(b"mockset\0").unwrap();
//    let mut rule = get_test_rule();
//    let table = rule.get_chain().get_table();
//    let mut set = Set::new(set_name, 0, table);
//    let address: Ipv4Addr = [8, 8, 8, 8].into();
//    set.add(&address);
//    let lookup = Lookup::new(&set).unwrap();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &lookup);
//    assert_eq!(nlmsghdr.nlmsg_len, 104);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Nested(
//                NFTA_RULE_EXPRESSIONS,
//                vec![NetlinkExpr::Nested(
//                    NFTA_LIST_ELEM,
//                    vec![
//                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"lookup\0".to_vec()),
//                        NetlinkExpr::Nested(
//                            NFTA_EXPR_DATA,
//                            vec![
//                                NetlinkExpr::Final(
//                                    NFTA_LOOKUP_SREG,
//                                    NFT_REG_1.to_be_bytes().to_vec()
//                                ),
//                                NetlinkExpr::Final(NFTA_LOOKUP_SET, b"mockset\0".to_vec()),
//                                NetlinkExpr::Final(NFTA_LOOKUP_SET_ID, 0u32.to_be_bytes().to_vec()),
//                            ]
//                        )
//                    ]
//                )]
//            )
//        ])
//        .to_raw()
//    );
//}
//
//use rustables::expr::Masquerade;
//#[test]
//fn masquerade_expr_is_valid() {
//    let masquerade = Masquerade;
//    let mut rule = get_test_rule();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_from_expr(&mut rule, &masquerade);
//    assert_eq!(nlmsghdr.nlmsg_len, 76);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Nested(
//                NFTA_RULE_EXPRESSIONS,
//                vec![NetlinkExpr::Nested(
//                    NFTA_LIST_ELEM,
//                    vec![
//                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"masq\0".to_vec()),
//                        NetlinkExpr::Nested(NFTA_EXPR_DATA, vec![]),
//                    ]
//                )]
//            )
//        ])
//        .to_raw()
//    );
//}
//
#[test]
fn meta_expr_is_valid() {
    let meta = Meta::default()
        .with_key(MetaType::Protocol)
        .with_dreg(Register::Reg1);
    let mut rule = get_test_rule().with_expressions(vec![meta]);

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 88);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"meta".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_META_KEY,
                                    NFT_META_PROTOCOL.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_META_DREG,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn nat_expr_is_valid() {
    let nat = Nat::default()
        .with_nat_type(NatType::SNat)
        .with_family(ProtocolFamily::Ipv4)
        .with_ip_register(Register::Reg1);
    let mut rule = get_test_rule().with_expressions(vec![nat]);

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 96);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"nat".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_NAT_TYPE,
                                    NFT_NAT_SNAT.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_NAT_FAMILY,
                                    (ProtocolFamily::Ipv4 as u32).to_be_bytes().to_vec(),
                                ),
                                NetlinkExpr::Final(
                                    NFTA_NAT_REG_ADDR_MIN,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                )
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn payload_expr_is_valid() {
    let tcp_header_field = TCPHeaderField::Sport;
    let transport_header_field = TransportHeaderField::Tcp(tcp_header_field);
    let payload = HighLevelPayload::Transport(transport_header_field);
    let mut rule = get_test_rule().with_expressions(vec![payload.build()]);

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 108);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"payload".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_PAYLOAD_DREG,
                                    NFT_REG_1.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_PAYLOAD_BASE,
                                    NFT_PAYLOAD_TRANSPORT_HEADER.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_PAYLOAD_OFFSET,
                                    tcp_header_field.offset().to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_PAYLOAD_LEN,
                                    tcp_header_field.len().to_be_bytes().to_vec()
                                ),
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn reject_expr_is_valid() {
    let code = IcmpCode::NoRoute;
    let reject = Reject::default()
        .with_type(RejectType::IcmpxUnreach)
        .with_icmp_code(code);
    let mut rule = get_test_rule().with_expressions(vec![reject]);
    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 92);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"reject".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_REJECT_TYPE,
                                    NFT_REJECT_ICMPX_UNREACH.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Final(
                                    NFTA_REJECT_ICMP_CODE,
                                    (code as u8).to_be_bytes().to_vec()
                                ),
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

#[test]
fn verdict_expr_is_valid() {
    let verdict = Immediate::new_verdict(VerdictKind::Drop);
    let mut rule =
        get_test_rule().with_expressions(ExpressionList::default().with_expression(verdict));

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut rule);
    assert_eq!(nlmsghdr.nlmsg_len, 104);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Nested(
                NFTA_RULE_EXPRESSIONS,
                vec![NetlinkExpr::Nested(
                    NFTA_LIST_ELEM,
                    vec![
                        NetlinkExpr::Final(NFTA_EXPR_NAME, b"immediate".to_vec()),
                        NetlinkExpr::Nested(
                            NFTA_EXPR_DATA,
                            vec![
                                NetlinkExpr::Final(
                                    NFTA_IMMEDIATE_DREG,
                                    NFT_REG_VERDICT.to_be_bytes().to_vec()
                                ),
                                NetlinkExpr::Nested(
                                    NFTA_IMMEDIATE_DATA,
                                    vec![NetlinkExpr::Nested(
                                        NFTA_DATA_VERDICT,
                                        vec![NetlinkExpr::Final(
                                            NFTA_VERDICT_CODE,
                                            NF_DROP.to_be_bytes().to_vec()
                                        ),]
                                    )],
                                ),
                            ]
                        )
                    ]
                )]
            )
        ])
        .to_raw()
    );
}

mod sys;
use rustables::{parser::get_operation_from_nlmsghdr_type, MsgType};
use sys::*;

mod lib;
use lib::*;

#[test]
fn new_empty_chain() {
    let mut chain = get_test_chain();

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut chain);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_NEWCHAIN as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 52);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.as_bytes().to_vec()),
        ])
        .to_raw()
    );
}

#[test]
fn new_empty_chain_with_userdata() {
    let mut chain = get_test_chain();
    chain.set_userdata(CHAIN_USERDATA);

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut buf, &mut chain);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_NEWCHAIN as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 72);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_CHAIN_USERDATA, CHAIN_USERDATA.as_bytes().to_vec())
        ])
        .to_raw()
    );
}

#[test]
fn delete_empty_chain() {
    let mut chain = get_test_chain();

    let mut buf = Vec::new();
    let (nlmsghdr, _nfgenmsg, raw_expr) =
        get_test_nlmsg_with_msg_type(&mut buf, &mut chain, MsgType::Del);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_DELCHAIN as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 52);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.as_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.as_bytes().to_vec()),
        ])
        .to_raw()
    );
}

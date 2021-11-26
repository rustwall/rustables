use std::ffi::CStr;

mod sys;
use rustables::MsgType;
use sys::*;

mod lib;
use lib::*;

#[test]
fn new_empty_table() {
    let mut table = get_test_table();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut table);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_NEWTABLE as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 44);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_TABLE_NAME, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_TABLE_FLAGS, 0u32.to_be_bytes().to_vec()),
        ])
        .to_raw()
    );
}

#[test]
fn new_empty_table_with_userdata() {
    let mut table = get_test_table();
    table.set_userdata(CStr::from_bytes_with_nul(TABLE_USERDATA).unwrap());
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut table);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_NEWTABLE as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 64);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_TABLE_NAME, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_TABLE_FLAGS, 0u32.to_be_bytes().to_vec()),
            NetlinkExpr::Final(NFTA_TABLE_USERDATA, TABLE_USERDATA.to_vec())
        ])
        .to_raw()
    );
}

#[test]
fn delete_empty_table() {
    let mut table = get_test_table();
    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_with_msg_type(&mut table, MsgType::Del);
    assert_eq!(
        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
        NFT_MSG_DELTABLE as u8
    );
    assert_eq!(nlmsghdr.nlmsg_len, 44);

    assert_eq!(
        raw_expr,
        NetlinkExpr::List(vec![
            NetlinkExpr::Final(NFTA_TABLE_NAME, TABLE_NAME.to_vec()),
            NetlinkExpr::Final(NFTA_TABLE_FLAGS, 0u32.to_be_bytes().to_vec()),
        ])
        .to_raw()
    );
}

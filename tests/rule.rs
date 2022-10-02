//use std::ffi::CStr;
//
//mod sys;
//use rustables::{query::get_operation_from_nlmsghdr_type, MsgType};
//use sys::*;
//
//mod lib;
//use lib::*;
//
//#[test]
//fn new_empty_rule() {
//    let mut rule = get_test_rule();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut rule);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWRULE as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 52);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn new_empty_rule_with_userdata() {
//    let mut rule = get_test_rule();
//    rule.set_userdata(CStr::from_bytes_with_nul(RULE_USERDATA).unwrap());
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut rule);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWRULE as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 72);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_USERDATA, RULE_USERDATA.to_vec())
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn new_empty_rule_with_position_and_handle() {
//    let handle = 1337;
//    let position = 42;
//    let mut rule = get_test_rule();
//    rule.set_handle(handle);
//    rule.set_position(position);
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut rule);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWRULE as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 76);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_HANDLE, handle.to_be_bytes().to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_POSITION, position.to_be_bytes().to_vec()),
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn delete_empty_rule() {
//    let mut rule = get_test_rule();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_with_msg_type(&mut rule, MsgType::Del);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_DELRULE as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 52);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn delete_empty_rule_with_handle() {
//    let handle = 42;
//    let mut rule = get_test_rule();
//    rule.set_handle(handle);
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_with_msg_type(&mut rule, MsgType::Del);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_DELRULE as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 64);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_RULE_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_CHAIN, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_RULE_HANDLE, handle.to_be_bytes().to_vec()),
//        ])
//        .to_raw()
//    );
//}

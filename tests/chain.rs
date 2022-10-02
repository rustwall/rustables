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
//fn new_empty_chain() {
//    let mut chain = get_test_chain();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut chain);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWCHAIN as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 52);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.to_vec()),
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn new_empty_chain_with_userdata() {
//    let mut chain = get_test_chain();
//    chain.set_userdata(CStr::from_bytes_with_nul(CHAIN_USERDATA).unwrap());
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut chain);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWCHAIN as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 72);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_CHAIN_USERDATA, CHAIN_USERDATA.to_vec())
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn delete_empty_chain() {
//    let mut chain = get_test_chain();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_with_msg_type(&mut chain, MsgType::Del);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_DELCHAIN as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 52);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_CHAIN_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_CHAIN_NAME, CHAIN_NAME.to_vec()),
//        ])
//        .to_raw()
//    );
//}

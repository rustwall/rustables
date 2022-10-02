//mod sys;
//use std::net::{Ipv4Addr, Ipv6Addr};
//
//use rustables::{query::get_operation_from_nlmsghdr_type, set::SetKey, MsgType};
//use sys::*;
//
//mod lib;
//use lib::*;
//
//#[test]
//fn new_empty_set() {
//    let mut set = get_test_set::<Ipv4Addr>();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg(&mut set);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_NEWSET as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 80);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_SET_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_SET_NAME, SET_NAME.to_vec()),
//            NetlinkExpr::Final(
//                NFTA_SET_FLAGS,
//                ((libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32)
//                    .to_be_bytes()
//                    .to_vec()
//            ),
//            NetlinkExpr::Final(NFTA_SET_KEY_TYPE, Ipv4Addr::TYPE.to_be_bytes().to_vec()),
//            NetlinkExpr::Final(NFTA_SET_KEY_LEN, Ipv4Addr::LEN.to_be_bytes().to_vec()),
//            NetlinkExpr::Final(NFTA_SET_ID, SET_ID.to_be_bytes().to_vec()),
//        ])
//        .to_raw()
//    );
//}
//
//#[test]
//fn delete_empty_set() {
//    let mut set = get_test_set::<Ipv6Addr>();
//    let (nlmsghdr, _nfgenmsg, raw_expr) = get_test_nlmsg_with_msg_type(&mut set, MsgType::Del);
//    assert_eq!(
//        get_operation_from_nlmsghdr_type(nlmsghdr.nlmsg_type),
//        NFT_MSG_DELSET as u8
//    );
//    assert_eq!(nlmsghdr.nlmsg_len, 80);
//
//    assert_eq!(
//        raw_expr,
//        NetlinkExpr::List(vec![
//            NetlinkExpr::Final(NFTA_SET_TABLE, TABLE_NAME.to_vec()),
//            NetlinkExpr::Final(NFTA_SET_NAME, SET_NAME.to_vec()),
//            NetlinkExpr::Final(
//                NFTA_SET_FLAGS,
//                ((libc::NFT_SET_ANONYMOUS | libc::NFT_SET_CONSTANT) as u32)
//                    .to_be_bytes()
//                    .to_vec()
//            ),
//            NetlinkExpr::Final(NFTA_SET_KEY_TYPE, Ipv6Addr::TYPE.to_be_bytes().to_vec()),
//            NetlinkExpr::Final(NFTA_SET_KEY_LEN, Ipv6Addr::LEN.to_be_bytes().to_vec()),
//            NetlinkExpr::Final(NFTA_SET_ID, SET_ID.to_be_bytes().to_vec()),
//        ])
//        .to_raw()
//    );
//}

mod sys;
use libc::NFNL_MSG_BATCH_BEGIN;
use nix::libc::NFNL_MSG_BATCH_END;
use rustables::nlmsg::NfNetlinkDeserializable;
use rustables::nlmsg::NfNetlinkObject;
use rustables::parser::{get_operation_from_nlmsghdr_type, parse_nlmsg, parse_object};
use rustables::{Batch, MsgType, Table};

mod lib;
use lib::*;

#[test]
fn batch_empty() {
    let batch = Batch::new();
    let buf = batch.finalize();

    let (hdr, msg) = parse_nlmsg(&buf).expect("Invalid nlmsg message");
    assert_eq!(hdr.nlmsg_type, NFNL_MSG_BATCH_BEGIN as u16);
    let (_nfgenmsg, attrs, remaining_data) =
        parse_object(hdr, msg, &buf).expect("Could not parse the batch message");

    assert_eq!(attrs.get_raw_data(), []);

    let (hdr, msg) = parse_nlmsg(&remaining_data).expect("Invalid nlmsg message");
    assert_eq!(hdr.nlmsg_type, NFNL_MSG_BATCH_END as u16);
    let (_nfgenmsg, attrs, remaining_data) =
        parse_object(hdr, msg, &remaining_data).expect("Could not parse the batch message");

    assert_eq!(attrs.get_raw_data(), []);

    assert_eq!(remaining_data, [])
}

#[test]
fn batch_with_objects() {
    let mut original_tables = vec![];
    for i in 0..10 {
        let mut table = get_test_table();
        table.set_userdata(vec![i as u8]);
        original_tables.push(table);
    }

    let mut batch = Batch::new();
    for i in 0..10 {
        batch.add(
            &original_tables[i],
            if i % 2 == 0 {
                MsgType::Add
            } else {
                MsgType::Del
            },
        );
    }
    let buf = batch.finalize();

    let (hdr, msg) = parse_nlmsg(&buf).expect("Invalid nlmsg message");
    assert_eq!(hdr.nlmsg_type, NFNL_MSG_BATCH_BEGIN as u16);
    let (_nfgenmsg, attrs, mut remaining_data) =
        parse_object(hdr, msg, &buf).expect("Could not parse the batch message");

    assert_eq!(attrs.get_raw_data(), []);

    for i in 0..10 {
        let (deserialized_table, rest) =
            Table::deserialize(remaining_data).expect("could not deserialize a table");
        remaining_data = rest;

        assert_eq!(deserialized_table, original_tables[i]);
    }

    let (hdr, msg) = parse_nlmsg(&remaining_data).expect("Invalid nlmsg message");
    assert_eq!(hdr.nlmsg_type, NFNL_MSG_BATCH_END as u16);
    let (_nfgenmsg, attrs, remaining_data) =
        parse_object(hdr, msg, &remaining_data).expect("Could not parse the batch message");

    assert_eq!(attrs.get_raw_data(), []);

    assert_eq!(remaining_data, [])
}

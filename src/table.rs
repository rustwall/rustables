use std::convert::TryFrom;
use std::fmt::Debug;

use crate::nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable, NfNetlinkObject, NfNetlinkWriter};
use crate::parser::Parsable;
use crate::parser::{DecodeError, InnerFormat};
use crate::sys::{
    self, NFT_MSG_DELTABLE, NFT_MSG_GETTABLE, NFT_MSG_NEWTABLE, NLM_F_ACK, NLM_F_CREATE,
};
use crate::{impl_attr_getters_and_setters, impl_nfnetlinkattribute, MsgType, ProtocolFamily};

/// Abstraction of a `nftnl_table`, the top level container in netfilter. A table has a protocol
/// family and contains [`Chain`]s that in turn hold the rules.
///
/// [`Chain`]: struct.Chain.html
#[derive(Default, PartialEq, Eq)]
pub struct Table {
    flags: Option<u32>,
    name: Option<String>,
    userdata: Option<Vec<u8>>,
    pub family: ProtocolFamily,
}

impl Table {
    pub fn new(family: ProtocolFamily) -> Table {
        let mut res = Self::default();
        res.family = family;
        res
    }
}

impl Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut res = f.debug_struct("Table");
        res.field("family", &self.family);
        self.inner_format_struct(res)?.finish()
    }
}

impl NfNetlinkObject for Table {
    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32) {
        let raw_msg_type = match msg_type {
            MsgType::Add => NFT_MSG_NEWTABLE,
            MsgType::Del => NFT_MSG_DELTABLE,
        } as u16;
        writer.write_header(
            raw_msg_type,
            self.family,
            (if let MsgType::Add = msg_type {
                NLM_F_CREATE
            } else {
                0
            } | NLM_F_ACK) as u16,
            seq,
            None,
        );
        let buf = writer.add_data_zeroed(self.get_size());
        unsafe {
            self.write_payload(buf.as_mut_ptr());
        }
        writer.finalize_writing_object();
    }
}

impl NfNetlinkDeserializable for Table {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (mut obj, nfgenmsg, remaining_data) =
            Self::parse_object(buf, NFT_MSG_NEWTABLE, NFT_MSG_DELTABLE)?;
        obj.family = ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?;

        Ok((obj, remaining_data))
    }
}

impl_attr_getters_and_setters!(
    Table,
    [
        (get_name, set_name, with_name, sys::NFTA_TABLE_NAME, name, String),
        (get_flags, set_flags, with_flags, sys::NFTA_TABLE_FLAGS, flags, u32),
        (
            get_userdata,
            set_userdata,
            with_userdata,
            sys::NFTA_TABLE_USERDATA,
            userdata,
            Vec<u8>
        )
    ]
);

impl_nfnetlinkattribute!(
    inline : Table,
    [
        (sys::NFTA_TABLE_NAME, name),
        (sys::NFTA_TABLE_FLAGS, flags),
        (sys::NFTA_TABLE_USERDATA, userdata)
    ]
);

pub fn list_tables() -> Result<Vec<Table>, crate::query::Error> {
    let mut result = Vec::new();
    crate::query::list_objects_with_data(
        NFT_MSG_GETTABLE as u16,
        &|table: Table, tables: &mut Vec<Table>| {
            tables.push(table);
            Ok(())
        },
        None,
        &mut result,
    )?;
    Ok(result)
}

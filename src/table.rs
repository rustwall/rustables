use std::convert::TryFrom;
use std::fmt::Debug;

use crate::nlmsg::{
    NfNetlinkAttributes, NfNetlinkDeserializable, NfNetlinkObject, NfNetlinkWriter,
};
use crate::parser::{parse_object, DecodeError, InnerFormat};
use crate::sys::{
    self, NFNL_SUBSYS_NFTABLES, NFTA_OBJ_TABLE, NFTA_TABLE_FLAGS, NFTA_TABLE_NAME,
    NFT_MSG_DELTABLE, NFT_MSG_GETTABLE, NFT_MSG_NEWTABLE, NLM_F_ACK, NLM_F_CREATE,
};
use crate::{impl_attr_getters_and_setters, MsgType, ProtocolFamily};

/// Abstraction of a `nftnl_table`, the top level container in netfilter. A table has a protocol
/// family and contains [`Chain`]s that in turn hold the rules.
///
/// [`Chain`]: struct.Chain.html
#[derive(PartialEq, Eq)]
pub struct Table {
    inner: NfNetlinkAttributes,
    family: ProtocolFamily,
}

impl Table {
    pub fn new(family: ProtocolFamily) -> Table {
        Table {
            inner: NfNetlinkAttributes::new(),
            family,
        }
    }

    pub fn get_family(&self) -> ProtocolFamily {
        self.family
    }

    /*
    /// Returns a textual description of the table.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_table_snprintf(
                descr_buf.as_mut_ptr() as *mut c_char,
                (descr_buf.len() - 1) as u64,
                self.table,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr() as *mut c_char).to_owned()
        }
    }
    */
}
/*
impl PartialEq for Table {
    fn eq(&self, other: &Self) -> bool {
        self.get_name() == other.get_name() && self.family == other.family
    }
}
*/

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
        self.inner.serialize(writer);
        writer.finalize_writing_object();
    }
}

impl NfNetlinkDeserializable for Table {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (inner, nfgenmsg, remaining_data) =
            parse_object::<Self>(buf, NFT_MSG_NEWTABLE, NFT_MSG_DELTABLE)?;

        Ok((
            Self {
                inner,
                family: ProtocolFamily::try_from(nfgenmsg.nfgen_family as i32)?,
            },
            remaining_data,
        ))
    }
}

impl_attr_getters_and_setters!(
    Table,
    [
        (get_flags, set_flags, with_flags, sys::NFTA_TABLE_FLAGS, U32, u32),
        (get_name, set_name, with_name, sys::NFTA_TABLE_NAME, String, String),
        (
            get_userdata,
            set_userdata,
            with_userdata,
            sys::NFTA_TABLE_USERDATA,
            VecU8,
            Vec<u8>
        )
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

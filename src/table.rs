use std::convert::TryFrom;
use std::fmt::Debug;

use crate::nlmsg::{NfNetlinkObject, NfNetlinkWriter};
use crate::parser::{
    get_operation_from_nlmsghdr_type, parse_nlmsg, parse_object, Attribute, DecodeError,
    NfNetlinkAttributeReader, NfNetlinkAttributes, Nfgenmsg, NlMsg, SerializeNfNetlink,
};
use crate::sys::{
    self, NFTA_OBJ_TABLE, NFTA_TABLE_FLAGS, NFTA_TABLE_NAME, NFT_MSG_DELTABLE, NFT_MSG_GETTABLE,
    NFT_MSG_NEWTABLE, NLM_F_ACK,
};
use crate::{impl_attr_getters_and_setters, MsgType, ProtoFamily};

/// Abstraction of `nftnl_table`, the top level container in netfilter. A table has a protocol
/// family and contains [`Chain`]s that in turn hold the rules.
///
/// [`Chain`]: struct.Chain.html
#[derive(Debug, PartialEq, Eq)]
pub struct Table {
    inner: NfNetlinkAttributes,
    family: ProtoFamily,
}

impl Table {
    pub fn new(family: ProtoFamily) -> Table {
        Table {
            inner: NfNetlinkAttributes::new(),
            family,
        }
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

impl NfNetlinkObject for Table {
    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32) {
        let raw_msg_type = match msg_type {
            MsgType::Add => NFT_MSG_NEWTABLE,
            MsgType::Del => NFT_MSG_DELTABLE,
        } as u16;
        writer.write_header(raw_msg_type, self.family, NLM_F_ACK as u16, seq, None);
        self.inner.serialize(writer);
        writer.finalize_writing_object();
    }

    fn decode_attribute(attr_type: u16, buf: &[u8]) -> Result<Attribute, DecodeError> {
        match attr_type {
            NFTA_TABLE_NAME => Ok(Attribute::String(String::from_utf8(buf.to_vec())?)),
            NFTA_TABLE_FLAGS => {
                let val = [buf[0], buf[1], buf[2], buf[3]];

                Ok(Attribute::U32(u32::from_ne_bytes(val)))
            }
            NFTA_TABLE_USERDATA => Ok(Attribute::VecU8(buf.to_vec())),
            _ => Err(DecodeError::UnsupportedAttributeType(attr_type)),
        }
    }

    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (hdr, msg) = parse_nlmsg(buf)?;

        let op = get_operation_from_nlmsghdr_type(hdr.nlmsg_type) as u32;

        if op != NFT_MSG_NEWTABLE && op != NFT_MSG_DELTABLE {
            return Err(DecodeError::UnexpectedType(hdr.nlmsg_type));
        }

        let (nfgenmsg, attrs, remaining_data) = parse_object(hdr, msg, buf)?;

        let inner = attrs.decode::<Table>()?;

        Ok((
            Table {
                inner,
                family: ProtoFamily::try_from(nfgenmsg.family as i32)?,
            },
            remaining_data,
        ))
    }
}

impl_attr_getters_and_setters!(
    Table,
    [
        (get_name, set_name, with_name, sys::NFTA_TABLE_NAME, String, String),
        (
            get_userdata,
            set_userdata,
            with_userdata,
            sys::NFTA_TABLE_USERDATA,
            VecU8,
            Vec<u8>
        ),
        (get_flags, set_flags, with_flags, sys::NFTA_TABLE_FLAGS, U32, u32)
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

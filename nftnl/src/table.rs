use crate::{MsgType, ProtoFamily};
use nftnl_sys::{self as sys, libc};
use std::{
    convert::TryFrom,
    ffi::{c_void, CStr, CString},
    fmt::Debug,
    os::raw::c_char,
};

/// Abstraction of `nftnl_table`. The top level container in netfilter. A table has a protocol
/// family and contain [`Chain`]s that in turn hold the rules.
///
/// [`Chain`]: struct.Chain.html
pub struct Table {
    table: *mut sys::nftnl_table,
    family: ProtoFamily,
}

// Safety: It should be safe to pass this around and *read* from it
// from multiple threads
unsafe impl Send for Table {}
unsafe impl Sync for Table {}

impl Table {
    /// Creates a new table instance with the given name and protocol family.
    pub fn new<T: AsRef<CStr>>(name: &T, family: ProtoFamily) -> Table {
        unsafe {
            let table = try_alloc!(sys::nftnl_table_alloc());

            sys::nftnl_table_set_u32(table, sys::NFTNL_TABLE_FAMILY as u16, family as u32);
            sys::nftnl_table_set_str(table, sys::NFTNL_TABLE_NAME as u16, name.as_ref().as_ptr());
            sys::nftnl_table_set_u32(table, sys::NFTNL_TABLE_FLAGS as u16, 0u32);
            Table { table, family }
        }
    }

    pub unsafe fn from_raw(table: *mut sys::nftnl_table, family: ProtoFamily) -> Self {
        Table { table, family }
    }

    /// Returns the name of this table.
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = sys::nftnl_table_get_str(self.table, sys::NFTNL_TABLE_NAME as u16);
            CStr::from_ptr(ptr)
        }
    }

    /// Returns a textual description of the table.
    pub fn get_str(&self) -> CString {
        let mut descr_buf = vec![0i8; 4096];
        unsafe {
            sys::nftnl_table_snprintf(
                descr_buf.as_mut_ptr(),
                (descr_buf.len() - 1) as u64,
                self.table,
                sys::NFTNL_OUTPUT_DEFAULT,
                0,
            );
            CStr::from_ptr(descr_buf.as_ptr()).to_owned()
        }
    }

    /// Returns the protocol family for this table.
    pub fn get_family(&self) -> ProtoFamily {
        self.family
    }

    /// Returns the raw handle.
    pub fn as_ptr(&self) -> *const sys::nftnl_table {
        self.table as *const sys::nftnl_table
    }

    /// Returns a mutable version of the raw handle.
    pub fn as_mut_ptr(&self) -> *mut sys::nftnl_table {
        self.table
    }
}

impl PartialEq for Table {
    fn eq(&self, other: &Self) -> bool {
        self.get_name() == other.get_name() && self.get_family() == other.get_family()
    }
}

impl Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.get_str())
    }
}

unsafe impl crate::NlMsg for Table {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let raw_msg_type = match msg_type {
            MsgType::Add => libc::NFT_MSG_NEWTABLE,
            MsgType::Del => libc::NFT_MSG_DELTABLE,
        };
        let header = sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            raw_msg_type as u16,
            self.family as u16,
            libc::NLM_F_ACK as u16,
            seq,
        );
        sys::nftnl_table_nlmsg_build_payload(header, self.table);
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        unsafe { sys::nftnl_table_free(self.table) };
    }
}

#[cfg(feature = "query")]
/// A callback to parse the response for messages created with `get_tables_nlmsg`.
pub fn get_tables_cb(
    header: &libc::nlmsghdr,
    (_, tables): &mut (&(), &mut Vec<Table>),
) -> libc::c_int {
    unsafe {
        let table = sys::nftnl_table_alloc();
        if table as usize == 0 {
            return mnl::mnl_sys::MNL_CB_ERROR;
        }
        let err = sys::nftnl_table_nlmsg_parse(header, table);
        if err < 0 {
            error!("Failed to parse nelink table message - {}", err);
            sys::nftnl_table_free(table);
            return err;
        }
        let family = sys::nftnl_table_get_u32(table, sys::NFTNL_TABLE_FAMILY as u16);
        match crate::ProtoFamily::try_from(family as i32) {
            Ok(family) => {
                tables.push(Table::from_raw(table, family));
                mnl::mnl_sys::MNL_CB_OK
            }
            Err(crate::InvalidProtocolFamily) => {
                error!("The netlink table didn't have a valid protocol family !?");
                sys::nftnl_table_free(table);
                mnl::mnl_sys::MNL_CB_ERROR
            }
        }
    }
}

#[cfg(feature = "query")]
pub fn list_tables() -> Result<Vec<Table>, crate::query::Error> {
    crate::query::list_objects_with_data(libc::NFT_MSG_GETTABLE as u16, get_tables_cb, &(), None)
}

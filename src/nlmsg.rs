use std::{collections::HashMap, fmt::Debug, marker::PhantomData, mem::size_of, ops::Deref};

use libc::{
    nlmsgerr, nlmsghdr, NFNETLINK_V0, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END,
    NFNL_SUBSYS_NFTABLES, NLMSG_MIN_TYPE, NLM_F_DUMP_INTR,
};
use thiserror::Error;

use crate::{
    parser::{
        pad_netlink_object, pad_netlink_object_with_variable_size, Attribute, DecodeError,
        NfNetlinkAttributes, Nfgenmsg,
    },
    MsgType, ProtoFamily,
};

pub struct NfNetlinkWriter<'a> {
    buf: &'a mut Vec<u8>,
    headers: HeaderStack<'a>,
}

impl<'a> NfNetlinkWriter<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> NfNetlinkWriter<'a> {
        NfNetlinkWriter {
            buf,
            headers: HeaderStack::new(),
        }
    }

    pub fn add_data_zeroed<'b>(&'b mut self, size: usize) -> &'b mut [u8] {
        let padded_size = pad_netlink_object_with_variable_size(size);
        let start = self.buf.len();
        self.buf.resize(start + padded_size, 0);

        self.headers.add_size(padded_size as u32);

        &mut self.buf[start..start + size]
    }

    pub fn extract_buffer(self) -> &'a mut Vec<u8> {
        self.buf
    }

    // rewrite of `__nftnl_nlmsg_build_hdr`
    pub fn write_header(
        &mut self,
        msg_type: u16,
        family: ProtoFamily,
        flags: u16,
        seq: u32,
        ressource_id: Option<u16>,
    ) {
        let nlmsghdr_len = pad_netlink_object::<nlmsghdr>();
        let nfgenmsg_len = pad_netlink_object::<Nfgenmsg>();
        let nlmsghdr_buf = self.add_data_zeroed(nlmsghdr_len);

        let mut hdr: &mut nlmsghdr =
            unsafe { std::mem::transmute(nlmsghdr_buf.as_mut_ptr() as *mut nlmsghdr) };
        //let mut hdr = &mut unsafe { *(nlmsghdr_buf.as_mut_ptr() as *mut nlmsghdr) };

        hdr.nlmsg_len = (nlmsghdr_len + nfgenmsg_len) as u32;
        hdr.nlmsg_type = msg_type;
        // batch messages are not specific to the nftables subsystem
        if msg_type != NFNL_MSG_BATCH_BEGIN as u16 && msg_type != NFNL_MSG_BATCH_END as u16 {
            hdr.nlmsg_type |= (NFNL_SUBSYS_NFTABLES as u16) << 8;
        }
        hdr.nlmsg_flags = libc::NLM_F_REQUEST as u16 | flags;
        hdr.nlmsg_seq = seq;

        let nfgenmsg_buf = self.add_data_zeroed(nfgenmsg_len);

        let mut nfgenmsg: &mut Nfgenmsg =
            unsafe { std::mem::transmute(nfgenmsg_buf.as_mut_ptr() as *mut Nfgenmsg) };
        nfgenmsg.family = family as u8;
        nfgenmsg.version = NFNETLINK_V0 as u8;
        nfgenmsg.res_id = ressource_id.unwrap_or(0);

        self.headers.add_level(hdr, Some(nfgenmsg));
    }

    pub fn get_current_header(&mut self) -> Option<&mut nlmsghdr> {
        let stack_size = self.headers.stack.len();
        if stack_size > 0 {
            Some(unsafe { std::mem::transmute(self.headers.stack[stack_size - 1].0) })
        } else {
            None
        }
    }

    pub fn finalize_writing_object(&mut self) {
        self.headers.pop_level();
    }
}

struct HeaderStack<'a> {
    stack: Vec<(*mut nlmsghdr, Option<*mut Nfgenmsg>)>,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> HeaderStack<'a> {
    fn new() -> HeaderStack<'a> {
        HeaderStack {
            stack: Vec::new(),
            lifetime: PhantomData,
        }
    }

    /// resize all the stacked netlink containers to hold additional_size new bytes
    fn add_size(&mut self, additional_size: u32) {
        for (hdr, _) in &mut self.stack {
            unsafe {
                (**hdr).nlmsg_len = (**hdr).nlmsg_len + additional_size;
            }
        }
    }

    fn add_level(&mut self, hdr: *mut nlmsghdr, nfgenmsg: Option<*mut Nfgenmsg>) {
        self.stack.push((hdr, nfgenmsg));
    }

    fn pop_level(&mut self) {
        self.stack.pop();
    }
}

pub trait NfNetlinkObject: Sized {
    fn add_or_remove<'a>(&self, writer: &mut NfNetlinkWriter<'a>, msg_type: MsgType, seq: u32);

    fn decode_attribute(attr_type: u16, buf: &[u8]) -> Result<Attribute, DecodeError>;

    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError>;
}

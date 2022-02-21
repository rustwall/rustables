use std::mem::size_of;

use crate::{nft_nlmsg_maxsize, sys, ProtoFamily};
use libc::{
    nlmsgerr, nlmsghdr, NFNETLINK_V0, NFNL_SUBSYS_NFTABLES, NLMSG_DONE, NLMSG_ERROR,
    NLMSG_MIN_TYPE, NLMSG_NOOP, NLM_F_DUMP_INTR,
};
use sys::libc;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Nfgenmsg {
    pub family: u8,  /* AF_xxx */
    pub version: u8, /* nfnetlink version */
    pub res_id: u16, /* resource id */
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("The buffer is too small to hold a valid message")]
    BufTooSmall,

    #[error("The message is too small")]
    NlMsgTooSmall,

    #[error("Invalid subsystem, expected NFTABLES")]
    InvalidSubsystem(u8),

    #[error("Invalid version, expected NFNETLINK_V0")]
    InvalidVersion(u8),

    #[error("Invalid port ID")]
    InvalidPortId(u32),

    #[error("Invalid sequence number")]
    InvalidSeq(u32),

    #[error("The generation number was bumped in the kernel while the operation was running, interrupting it")]
    ConcurrentGenerationUpdate,

    #[error("Unsupported message type")]
    UnsupportedType(u16),

    #[error("A custom error occured")]
    Custom(Box<dyn std::error::Error + 'static>),
}

pub fn get_subsystem_from_nlmsghdr_type(x: u16) -> u8 {
    ((x & 0xff00) >> 8) as u8
}

pub fn get_operation_from_nlmsghdr_type(x: u16) -> u8 {
    (x & 0x00ff) as u8
}

pub unsafe fn get_nlmsghdr(
    buf: &[u8],
    expected_seq: u32,
    expected_port_id: u32,
) -> Result<&nlmsghdr, ParseError> {
    let size_of_hdr = size_of::<nlmsghdr>();

    if buf.len() < size_of_hdr {
        return Err(ParseError::BufTooSmall);
    }

    let nlmsghdr_ptr = buf[0..size_of_hdr].as_ptr() as *const nlmsghdr;
    let nlmsghdr = *nlmsghdr_ptr;

    if nlmsghdr.nlmsg_len as usize > buf.len() || (nlmsghdr.nlmsg_len as usize) < size_of_hdr {
        println!("a: {}, {}", buf.len(), nlmsghdr.nlmsg_len);
        return Err(ParseError::NlMsgTooSmall);
    }

    if nlmsghdr.nlmsg_pid != 0 && expected_port_id != 0 && nlmsghdr.nlmsg_pid != expected_port_id {
        return Err(ParseError::InvalidPortId(nlmsghdr.nlmsg_pid));
    }

    if nlmsghdr.nlmsg_seq != 0 && expected_seq != 0 && nlmsghdr.nlmsg_seq != expected_seq {
        return Err(ParseError::InvalidSeq(nlmsghdr.nlmsg_seq));
    }

    if nlmsghdr.nlmsg_flags & NLM_F_DUMP_INTR as u16 != 0 {
        return Err(ParseError::ConcurrentGenerationUpdate);
    }

    Ok(&*nlmsghdr_ptr as &nlmsghdr)
}

pub enum NlMsg<'a> {
    Done,
    Noop,
    Error(nlmsgerr),
    NfGenMsg(&'a Nfgenmsg, &'a [u8]),
}

pub unsafe fn parse_nlmsg<'a>(
    buf: &'a [u8],
    expected_seq: u32,
    expected_port_id: u32,
) -> Result<(&'a nlmsghdr, NlMsg<'a>), ParseError> {
    // in theory the message is composed of the following parts:
    // - nlmsghdr (contains the message size and type)
    // - struct nlmsgerr OR nfgenmsg (nftables header that describes the message family)
    // - the raw value that we want to validate (if the previous part is nfgenmsg)
    let nlmsghdr = get_nlmsghdr(buf, expected_seq, expected_port_id)?;

    let size_of_hdr = size_of::<nlmsghdr>();

    if nlmsghdr.nlmsg_type < NLMSG_MIN_TYPE as u16 {
        match nlmsghdr.nlmsg_type as libc::c_int {
            NLMSG_NOOP => return Ok((nlmsghdr, NlMsg::Noop)),
            NLMSG_ERROR => {
                if nlmsghdr.nlmsg_len as usize > buf.len()
                    || (nlmsghdr.nlmsg_len as usize) < size_of_hdr + size_of::<nlmsgerr>()
                {
                    println!("b: {}, {}", buf.len(), nlmsghdr.nlmsg_len);
                    return Err(ParseError::NlMsgTooSmall);
                }
                let mut err = *(buf[size_of_hdr..size_of_hdr + size_of::<nlmsgerr>()].as_ptr()
                    as *const nlmsgerr);
                // some APIs return negative values, while other return positive values
                err.error = err.error.abs();
                return Ok((nlmsghdr, NlMsg::Error(err)));
            }
            NLMSG_DONE => return Ok((nlmsghdr, NlMsg::Done)),
            x => return Err(ParseError::UnsupportedType(x as u16)),
        }
    }

    let subsys = get_subsystem_from_nlmsghdr_type(nlmsghdr.nlmsg_type);
    if subsys != NFNL_SUBSYS_NFTABLES as u8 {
        return Err(ParseError::InvalidSubsystem(subsys));
    }

    let size_of_nfgenmsg = size_of::<Nfgenmsg>();
    if nlmsghdr.nlmsg_len as usize > buf.len()
        || (nlmsghdr.nlmsg_len as usize) < size_of_hdr + size_of_nfgenmsg
    {
        println!("c: {}, {}", buf.len(), nlmsghdr.nlmsg_len);
        return Err(ParseError::NlMsgTooSmall);
    }

    let nfgenmsg_ptr = buf[size_of_hdr..size_of_hdr + size_of_nfgenmsg].as_ptr() as *const Nfgenmsg;
    let nfgenmsg = *nfgenmsg_ptr;
    let subsys = get_subsystem_from_nlmsghdr_type(nlmsghdr.nlmsg_type);
    if subsys != NFNL_SUBSYS_NFTABLES as u8 {
        return Err(ParseError::InvalidSubsystem(subsys));
    }
    if nfgenmsg.version != NFNETLINK_V0 as u8 {
        return Err(ParseError::InvalidVersion(nfgenmsg.version));
    }

    let raw_value = &buf[size_of_hdr + size_of_nfgenmsg..nlmsghdr.nlmsg_len as usize];

    Ok((
        nlmsghdr,
        NlMsg::NfGenMsg(&*nfgenmsg_ptr as &Nfgenmsg, raw_value),
    ))
}

/// Returns a buffer containing a netlink message which requests a list of all the netfilter
/// matching objects (e.g. tables, chains, rules, ...).
/// Supply the type of objects to retrieve (e.g. libc::NFT_MSG_GETTABLE), and optionally a callback
/// to execute on the header, to set parameters for example.
/// To pass arbitrary data inside that callback, please use a closure.
pub fn get_list_of_objects<Error>(
    seq: u32,
    target: u16,
    setup_cb: Option<&dyn Fn(&mut libc::nlmsghdr) -> Result<(), Error>>,
) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0; nft_nlmsg_maxsize() as usize];
    let hdr = unsafe {
        &mut *sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut libc::c_char,
            target,
            ProtoFamily::Unspec as u16,
            (libc::NLM_F_ROOT | libc::NLM_F_MATCH) as u16,
            seq,
        )
    };
    if let Some(cb) = setup_cb {
        cb(hdr)?;
    }
    Ok(buffer)
}

#[cfg(feature = "query")]
mod inner {
    use std::os::unix::prelude::RawFd;

    use nix::{
        errno::Errno,
        sys::socket::{
            self, AddressFamily, MsgFlags, NetlinkAddr, SockAddr, SockFlag, SockProtocol, SockType,
        },
    };

    use crate::FinalizedBatch;

    use super::*;

    #[derive(thiserror::Error, Debug)]
    pub enum Error {
        #[error("Unable to open netlink socket to netfilter")]
        NetlinkOpenError(#[source] nix::Error),

        #[error("Unable to send netlink command to netfilter")]
        NetlinkSendError(#[source] nix::Error),

        #[error("Error while reading from netlink socket")]
        NetlinkRecvError(#[source] nix::Error),

        #[error("Error while processing an incoming netlink message")]
        ProcessNetlinkError(#[from] ParseError),

        #[error("Error received from the kernel")]
        NetlinkError(nlmsgerr),

        #[error("Custom error when customizing the query")]
        InitError(#[from] Box<dyn std::error::Error + Send + 'static>),

        #[error("Couldn't allocate a netlink object, out of memory ?")]
        NetlinkAllocationFailed,

        #[error("This socket is not a netlink socket")]
        NotNetlinkSocket,

        #[error("Couldn't retrieve information on a socket")]
        RetrievingSocketInfoFailed,

        #[error("Only a part of the message was sent")]
        TruncatedSend,

        #[error("Couldn't close the socket")]
        CloseFailed(#[source] Errno),
    }

    fn recv_and_process<'a, T>(
        sock: RawFd,
        cb: &dyn Fn(&nlmsghdr, &Nfgenmsg, &[u8], &mut T) -> Result<(), Error>,
        working_data: &'a mut T,
        seq: u32,
        portid: u32,
    ) -> Result<(), Error> {
        let mut msg_buffer = vec![0; nft_nlmsg_maxsize() as usize];

        loop {
            let nb_recv = socket::recv(sock, &mut msg_buffer, MsgFlags::empty())
                .map_err(Error::NetlinkRecvError)?;
            if nb_recv <= 0 {
                return Ok(());
            }
            let mut buf = &msg_buffer.as_slice()[0..nb_recv];
            loop {
                let (nlmsghdr, msg) = unsafe { parse_nlmsg(&buf, seq, portid) }?;
                match msg {
                    NlMsg::Done => {
                        return Ok(());
                    }
                    NlMsg::Error(e) => {
                        if e.error != 0 {
                            return Err(Error::NetlinkError(e));
                        }
                    }
                    NlMsg::Noop => {}
                    NlMsg::NfGenMsg(genmsg, data) => cb(&nlmsghdr, &genmsg, &data, working_data)?,
                }

                // netlink messages are 4bytes aligned
                let aligned_length = ((nlmsghdr.nlmsg_len + 3) & !3u32) as usize;

                // retrieve the next message
                buf = &buf[aligned_length..];

                // exit the loop when we consumed all the buffer
                if buf.len() == 0 {
                    break;
                }
            }
        }
    }

    fn socket_close_wrapper(
        sock: RawFd,
        cb: impl FnOnce(RawFd) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let ret = cb(sock);

        // we don't need to shutdown the socket (in fact, Linux doesn't support that operation;
        // and return EOPNOTSUPP if we try)
        nix::unistd::close(sock).map_err(Error::CloseFailed)?;

        ret
    }

    /// Lists objects of a certain type (e.g. libc::NFT_MSG_GETTABLE) with the help of a helper
    /// function called by mnl::cb_run2.
    /// The callback expects a tuple of additional data (supplied as an argument to this function)
    /// and of the output vector, to which it should append the parsed object it received.
    pub fn list_objects_with_data<'a, T>(
        data_type: u16,
        cb: &dyn Fn(&libc::nlmsghdr, &Nfgenmsg, &[u8], &mut T) -> Result<(), Error>,
        working_data: &'a mut T,
        req_hdr_customize: Option<&dyn Fn(&mut libc::nlmsghdr) -> Result<(), Error>>,
    ) -> Result<(), Error> {
        debug!("listing objects of kind {}", data_type);
        let sock = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(Error::NetlinkOpenError)?;

        let seq = 0;
        let portid = 0;

        let chains_buf = get_list_of_objects(seq, data_type, req_hdr_customize)?;
        socket::send(sock, &chains_buf, MsgFlags::empty()).map_err(Error::NetlinkSendError)?;

        Ok(socket_close_wrapper(sock, move |sock| {
            recv_and_process(sock, cb, working_data, seq, portid)
        })?)
    }

    pub fn send_batch(batch: &mut FinalizedBatch) -> Result<(), Error> {
        let sock = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(Error::NetlinkOpenError)?;

        let seq = 0;
        let portid = 0;

        // while this bind() is not strictly necessary, strace have trouble decoding the messages
        // if we don't
        let addr = SockAddr::Netlink(NetlinkAddr::new(portid, 0));
        socket::bind(sock, &addr).expect("bind");
        //match socket::getsockname(sock).map_err(|_| Error::RetrievingSocketInfoFailed)? {
        //    SockAddr::Netlink(addr) => addr.0.nl_pid,
        //    _ => return Err(Error::NotNetlinkSocket),
        //};

        for data in batch {
            if socket::send(sock, data, MsgFlags::empty()).map_err(Error::NetlinkSendError)?
                < data.len()
            {
                return Err(Error::TruncatedSend);
            }
        }

        Ok(socket_close_wrapper(sock, move |sock| {
            recv_and_process(sock, &|_, _, _, _| Ok(()), &mut (), seq, portid)
        })?)
    }
}

#[cfg(feature = "query")]
pub use inner::*;

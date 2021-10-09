use crate::{nft_nlmsg_maxsize, nftnl_sys as sys, ProtoFamily};
use sys::libc;

/// Returns a buffer containing a netlink message which requests a list of all the netfilter
/// matching objects (e.g. tables, chains, rules, ...).
/// Supply the type of objects to retrieve (e.g. libc::NFT_MSG_GETTABLE), and optionally
/// a callback to execute on the header, to set parameters for example.
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
    use super::*;

    #[derive(thiserror::Error, Debug)]
    pub enum Error {
        #[error("Unable to open netlink socket to netfilter")]
        NetlinkOpenError(#[source] std::io::Error),

        #[error("Unable to send netlink command to netfilter")]
        NetlinkSendError(#[source] std::io::Error),

        #[error("Error while reading from netlink socket")]
        NetlinkRecvError(#[source] std::io::Error),

        #[error("Error while processing an incoming netlink message")]
        ProcessNetlinkError(#[source] std::io::Error),

        #[error("Custom error when customizing the query")]
        InitError(#[from] Box<dyn std::error::Error>),

        #[error("Couldn't allocate a netlink object, out of memory ?")]
        NetlinkAllocationFailed,
    }

    /// List objects of a certain type (e.g. libc::NFT_MSG_GETTABLE) with the help of an helper
    /// function called by mnl::cb_run2.
    /// The callback expect a tuple of additional data (supplied as an argument to
    /// this function) and of the output vector, to which it should append the parsed
    /// object it received.
    pub fn list_objects_with_data<'a, A, T>(
        data_type: u16,
        cb: fn(&libc::nlmsghdr, &mut (&'a A, &mut Vec<T>)) -> libc::c_int,
        additional_data: &'a A,
        req_hdr_customize: Option<&dyn Fn(&mut libc::nlmsghdr) -> Result<(), Error>>,
    ) -> Result<Vec<T>, Error>
    where
        T: 'a,
    {
        let socket = mnl::Socket::new(mnl::Bus::Netfilter).map_err(Error::NetlinkOpenError)?;

        let seq = 0;
        let portid = socket.portid();

        let chains_buf = get_list_of_objects(seq, data_type, req_hdr_customize)?;
        socket.send(&chains_buf).map_err(Error::NetlinkSendError)?;

        let mut res = Vec::new();

        let mut msg_buffer = vec![0; nft_nlmsg_maxsize() as usize];
        while socket
            .recv(&mut msg_buffer)
            .map_err(Error::NetlinkRecvError)?
            > 0
        {
            if let mnl::CbResult::Stop = mnl::cb_run2(
                &msg_buffer,
                seq,
                portid,
                cb,
                &mut (additional_data, &mut res),
            )
            .map_err(Error::ProcessNetlinkError)?
            {
                break;
            }
        }

        Ok(res)
    }
}

#[cfg(feature = "query")]
pub use inner::*;

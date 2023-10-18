use libc;

use thiserror::Error;

use crate::error::QueryError;
use crate::nlmsg::{NfNetlinkObject, NfNetlinkWriter};
use crate::sys::NFNL_SUBSYS_NFTABLES;
use crate::{MsgType, ProtocolFamily};

use nix::sys::socket::{
    self, AddressFamily, MsgFlags, NetlinkAddr, SockAddr, SockFlag, SockProtocol, SockType,
};

/// Error while communicating with netlink.
#[derive(Error, Debug)]
#[error("Error while communicating with netlink")]
pub struct NetlinkError(());

/// A batch of netfilter messages to be performed in one atomic operation.
pub struct Batch {
    buf: Box<Vec<u8>>,
    // the 'static lifetime here is a cheat, as the writer can only be used as long
    // as `self.buf` exists. This is why this member must never be exposed directly to
    // the rest of the crate (let alone publicly).
    writer: NfNetlinkWriter<'static>,
    seq: u32,
}

impl Batch {
    /// Creates a new nftnl batch with the [default page size].
    ///
    /// [default page size]: fn.default_batch_page_size.html
    pub fn new() -> Self {
        // TODO: use a pinned Box ?
        let mut buf = Box::new(Vec::with_capacity(default_batch_page_size() as usize));
        // Safe because we hold onto the buffer for as long as `writer` exists
        let mut writer = NfNetlinkWriter::new(unsafe {
            std::mem::transmute(Box::as_mut(&mut buf) as *mut Vec<u8>)
        });
        let seq = 0;
        writer.write_header(
            libc::NFNL_MSG_BATCH_BEGIN as u16,
            ProtocolFamily::Unspec,
            0,
            seq,
            Some(libc::NFNL_SUBSYS_NFTABLES as u16),
        );
        writer.finalize_writing_object();
        Batch {
            buf,
            writer,
            seq: seq + 1,
        }
    }

    /// Adds the given message to this batch.
    pub fn add<T: NfNetlinkObject>(&mut self, msg: &T, msg_type: MsgType) {
        trace!("Writing NlMsg with seq {} to batch", self.seq);
        msg.add_or_remove(&mut self.writer, msg_type, self.seq);
        self.seq += 1;
    }

    /// Adds all the messages in the given iterator to this batch.
    pub fn add_iter<T: NfNetlinkObject, I: Iterator<Item = T>>(
        &mut self,
        msg_iter: I,
        msg_type: MsgType,
    ) {
        for msg in msg_iter {
            self.add(&msg, msg_type);
        }
    }

    /// Adds the final end message to the batch and returns a [`FinalizedBatch`] that can be used
    /// to send the messages to netfilter.
    ///
    /// Return None if there is no object in the batch (this could block forever).
    ///
    /// [`FinalizedBatch`]: struct.FinalizedBatch.html
    pub fn finalize(mut self) -> Vec<u8> {
        self.writer.write_header(
            libc::NFNL_MSG_BATCH_END as u16,
            ProtocolFamily::Unspec,
            0,
            self.seq,
            Some(NFNL_SUBSYS_NFTABLES as u16),
        );
        self.writer.finalize_writing_object();
        *self.buf
    }

    pub fn send(self) -> Result<(), QueryError> {
        use crate::query::{recv_and_process, socket_close_wrapper};

        let sock = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(QueryError::NetlinkOpenError)?;

        let max_seq = self.seq - 1;

        let addr = SockAddr::Netlink(NetlinkAddr::new(0, 0));
        // while this bind() is not strictly necessary, strace have trouble decoding the messages
        // if we don't
        socket::bind(sock, &addr).expect("bind");

        let to_send = self.finalize();
        let mut sent = 0;
        while sent != to_send.len() {
            sent += socket::send(sock, &to_send[sent..], MsgFlags::empty())
                .map_err(QueryError::NetlinkSendError)?;
        }

        Ok(socket_close_wrapper(sock, move |sock| {
            recv_and_process(sock, Some(max_seq), None, &mut ())
        })?)
    }
}

/// Selected batch page is 256 Kbytes long to load ruleset of half a million rules without hitting
/// -EMSGSIZE due to large iovec.
pub fn default_batch_page_size() -> u32 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 * 32 }
}

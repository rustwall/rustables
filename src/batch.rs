use libc;

use thiserror::Error;

use crate::nlmsg::{NfNetlinkObject, NfNetlinkWriter};
use crate::{MsgType, ProtoFamily};

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
        let mut writer = NfNetlinkWriter::new(unsafe {
            std::mem::transmute(Box::as_mut(&mut buf) as *mut Vec<u8>)
        });
        writer.write_header(
            libc::NFNL_MSG_BATCH_BEGIN as u16,
            ProtoFamily::Unspec,
            0,
            0,
            Some(libc::NFNL_SUBSYS_NFTABLES as u16),
        );
        writer.finalize_writing_object();
        Batch {
            buf,
            writer,
            seq: 1,
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
            ProtoFamily::Unspec,
            0,
            self.seq,
            Some(libc::NFNL_SUBSYS_NFTABLES as u16),
        );
        self.writer.finalize_writing_object();
        *self.buf
    }
}

/// Selected batch page is 256 Kbytes long to load ruleset of half a million rules without hitting
/// -EMSGSIZE due to large iovec.
pub fn default_batch_page_size() -> u32 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 * 32 }
}

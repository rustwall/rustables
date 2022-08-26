use crate::nlmsg::{NfNetlinkObject, NfNetlinkWriter};
use crate::sys::{self};
use crate::{MsgType, ProtoFamily};
use libc;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::ptr;
use thiserror::Error;

/// Error while communicating with netlink.
#[derive(Error, Debug)]
#[error("Error while communicating with netlink")]
pub struct NetlinkError(());

/// A batch of netfilter messages to be performed in one atomic operation. Corresponds to
/// `nftnl_batch` in libnftnl.
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
    pub fn finalize(mut self) -> FinalizedBatch {
        self.writer.write_header(
            libc::NFNL_MSG_BATCH_END as u16,
            ProtoFamily::Unspec,
            0,
            self.seq,
            Some(libc::NFNL_SUBSYS_NFTABLES as u16),
        );
        FinalizedBatch { batch: self }
    }

    /*
        fn current(&self) -> *mut c_void {
            unsafe { sys::nftnl_batch_buffer(self.batch) }
        }

        fn next(&mut self) {
            if unsafe { sys::nftnl_batch_update(self.batch) } < 0 {
                // See try_alloc definition.
                std::process::abort();
            }
            self.seq += 1;
        }

        fn write_begin_msg(&mut self) {
            unsafe { sys::nftnl_batch_begin(self.current() as *mut c_char, self.seq) };
            self.next();
        }

        fn write_end_msg(&mut self) {
            unsafe { sys::nftnl_batch_end(self.current() as *mut c_char, self.seq) };
            self.next();
        }

        #[cfg(feature = "unsafe-raw-handles")]
        /// Returns the raw handle.
        pub fn as_ptr(&self) -> *const sys::nftnl_batch {
            self.batch as *const sys::nftnl_batch
        }

        #[cfg(feature = "unsafe-raw-handles")]
        /// Returns a mutable version of the raw handle.
        pub fn as_mut_ptr(&mut self) -> *mut sys::nftnl_batch {
            self.batch
        }
    */
}

/// A wrapper over [`Batch`], guaranteed to start with a proper batch begin and end with a proper
/// batch end message. Created from [`Batch::finalize`].
///
/// Can be turned into an iterator of the byte buffers to send to netlink to execute this batch.
///
/// [`Batch`]: struct.Batch.html
/// [`Batch::finalize`]: struct.Batch.html#method.finalize
pub struct FinalizedBatch {
    batch: Batch,
}

/*
impl FinalizedBatch {
    /// Returns the iterator over byte buffers to send to netlink.
    pub fn iter(&mut self) -> Iter<'_> {
        let num_pages = unsafe { sys::nftnl_batch_iovec_len(self.batch.batch) as usize };
        let mut iovecs = vec![
            libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            };
            num_pages
        ];
        let iovecs_ptr = iovecs.as_mut_ptr();
        unsafe {
            sys::nftnl_batch_iovec(self.batch.batch, iovecs_ptr, num_pages as u32);
        }
        Iter {
            iovecs: iovecs.into_iter(),
            _marker: ::std::marker::PhantomData,
        }
    }
}

impl<'a> IntoIterator for &'a mut FinalizedBatch {
    type Item = &'a [u8];
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

pub struct Iter<'a> {
    iovecs: ::std::vec::IntoIter<libc::iovec>,
    _marker: ::std::marker::PhantomData<&'a ()>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.iovecs.next().map(|iovec| unsafe {
            ::std::slice::from_raw_parts(iovec.iov_base as *const u8, iovec.iov_len)
        })
    }
}
*/

/// Selected batch page is 256 Kbytes long to load ruleset of half a million rules without hitting
/// -EMSGSIZE due to large iovec.
pub fn default_batch_page_size() -> u32 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 * 32 }
}

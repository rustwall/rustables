use std::fmt::Debug;

use rustables_sys::libc;

/// A netfilter data register. The expressions store and read data to and from these
/// when evaluating rule statements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum Register {
    Verdict = libc::NFT_REG_VERDICT,
    Reg1 = libc::NFT_REG_1,
    Reg2 = libc::NFT_REG_2,
    Reg3 = libc::NFT_REG_3,
    Reg4 = libc::NFT_REG_4,
}

impl Register {
    pub fn to_raw(self) -> u32 {
        self as u32
    }

    pub fn from_raw(val: u32) -> Option<Self> {
        match val as i32 {
            libc::NFT_REG_VERDICT => Some(Self::Verdict),
            libc::NFT_REG_1 => Some(Self::Reg1),
            libc::NFT_REG_2 => Some(Self::Reg2),
            libc::NFT_REG_3 => Some(Self::Reg3),
            libc::NFT_REG_4 => Some(Self::Reg4),
            _ => None,
        }
    }
}

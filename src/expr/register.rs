use std::fmt::Debug;

use crate::{
    nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable},
    parser::DecodeError,
    sys::{NFT_REG_1, NFT_REG_2, NFT_REG_3, NFT_REG_4, NFT_REG_VERDICT},
};

/// A netfilter data register. The expressions store and read data to and from these when
/// evaluating rule statements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum Register {
    Verdict = NFT_REG_VERDICT,
    Reg1 = NFT_REG_1,
    Reg2 = NFT_REG_2,
    Reg3 = NFT_REG_3,
    Reg4 = NFT_REG_4,
}

impl NfNetlinkAttribute for Register {
    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as u32).write_payload(addr);
    }
}

impl NfNetlinkDeserializable for Register {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), crate::parser::DecodeError> {
        let (val, remaining) = u32::deserialize(buf)?;
        Ok((
            match val {
                NFT_REG_VERDICT => Self::Verdict,
                NFT_REG_1 => Self::Reg1,
                NFT_REG_2 => Self::Reg2,
                NFT_REG_3 => Self::Reg3,
                NFT_REG_4 => Self::Reg4,
                _ => return Err(DecodeError::UnknownRegisterValue),
            },
            remaining,
        ))
    }
}

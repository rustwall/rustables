use std::fmt::Debug;

use libc::{NF_ACCEPT, NF_DROP, NF_QUEUE};

use super::{ExpressionData, Immediate, Register};
use crate::{
    create_wrapper_type,
    nlmsg::{NfNetlinkAttribute, NfNetlinkDeserializable},
    parser::DecodeError,
    sys::{self, NFT_BREAK, NFT_CONTINUE, NFT_GOTO, NFT_JUMP, NFT_RETURN},
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(i32)]
pub enum VerdictType {
    Drop = NF_DROP,
    Accept = NF_ACCEPT,
    Queue = NF_QUEUE,
    Continue = NFT_CONTINUE,
    Break = NFT_BREAK,
    Jump = NFT_JUMP,
    Goto = NFT_GOTO,
    Return = NFT_RETURN,
}

impl NfNetlinkAttribute for VerdictType {
    fn get_size(&self) -> usize {
        (*self as i32).get_size()
    }

    unsafe fn write_payload(&self, addr: *mut u8) {
        (*self as i32).write_payload(addr);
    }
}

impl NfNetlinkDeserializable for VerdictType {
    fn deserialize(buf: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (v, remaining_data) = i32::deserialize(buf)?;
        Ok((
            match v {
                NF_DROP => VerdictType::Drop,
                NF_ACCEPT => VerdictType::Accept,
                NF_QUEUE => VerdictType::Queue,
                NFT_CONTINUE => VerdictType::Continue,
                NFT_BREAK => VerdictType::Break,
                NFT_JUMP => VerdictType::Jump,
                NFT_GOTO => VerdictType::Goto,
                NFT_RETURN => VerdictType::Goto,
                _ => return Err(DecodeError::UnknownExpressionVerdictType),
            },
            remaining_data,
        ))
    }
}

create_wrapper_type!(
    nested: VerdictAttribute,
    [
        (
            get_code,
            set_code,
            with_code,
            sys::NFTA_VERDICT_CODE,
            code,
            VerdictType
        ),
        (
            get_chain,
            set_chain,
            with_chain,
            sys::NFTA_VERDICT_CHAIN,
            chain,
            String
        ),
        (
            get_chain_id,
            set_chain_id,
            with_chain_id,
            sys::NFTA_VERDICT_CHAIN_ID,
            chain_id,
            u32
        )
    ]
);

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum VerdictKind {
    /// Silently drop the packet.
    Drop,
    /// Accept the packet and let it pass.
    Accept,
    Queue,
    Continue,
    Break,
    Jump {
        chain: String,
    },
    Goto {
        chain: String,
    },
    Return,
}

impl Immediate {
    pub fn new_verdict(kind: VerdictKind) -> Self {
        let code = match kind {
            VerdictKind::Drop => VerdictType::Drop,
            VerdictKind::Accept => VerdictType::Accept,
            VerdictKind::Queue => VerdictType::Queue,
            VerdictKind::Continue => VerdictType::Continue,
            VerdictKind::Break => VerdictType::Break,
            VerdictKind::Jump { .. } => VerdictType::Jump,
            VerdictKind::Goto { .. } => VerdictType::Goto,
            VerdictKind::Return => VerdictType::Return,
        };
        let mut data = VerdictAttribute::default().with_code(code);
        if let VerdictKind::Jump { chain } | VerdictKind::Goto { chain } = kind {
            data.set_chain(chain);
        }
        Immediate::default()
            .with_dreg(Register::Verdict)
            .with_data(ExpressionData::default().with_verdict(data))
    }
}

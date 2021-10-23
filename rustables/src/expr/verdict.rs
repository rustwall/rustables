use super::{Expression, Rule};
use rustables_sys::{
    self as sys,
    libc::{self, c_char},
};
use std::ffi::{CStr, CString};

/// A verdict expression. In the background, this is usually an "Immediate" expression in nftnl
/// terms, but here it is simplified to only represent a verdict.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Verdict {
    /// Silently drop the packet.
    Drop,
    /// Accept the packet and let it pass.
    Accept,
    Queue,
    Continue,
    Break,
    Jump {
        chain: CString,
    },
    Goto {
        chain: CString,
    },
    Return,
}

impl Verdict {
    fn chain(&self) -> Option<&CStr> {
        match *self {
            Verdict::Jump { ref chain } => Some(chain.as_c_str()),
            Verdict::Goto { ref chain } => Some(chain.as_c_str()),
            _ => None,
        }
    }
}

impl Expression for Verdict {
    fn get_raw_name() -> *const libc::c_char {
        b"immediate\0" as *const _ as *const c_char
    }

    fn from_expr(expr: *const sys::nftnl_expr) -> Option<Self> {
        unsafe {
            let mut chain = None;
            if sys::nftnl_expr_is_set(expr, sys::NFTNL_EXPR_IMM_CHAIN as u16) {
                let raw_chain = sys::nftnl_expr_get_str(expr, sys::NFTNL_EXPR_IMM_CHAIN as u16);

                if raw_chain.is_null() {
                    trace!("Unexpected empty chain name when deserializing 'verdict' expression");
                    return None;
                }
                chain = Some(CStr::from_ptr(raw_chain).to_owned());
            }

            let verdict = sys::nftnl_expr_get_u32(expr, sys::NFTNL_EXPR_IMM_VERDICT as u16);

            match verdict as i32 {
                libc::NF_DROP => Some(Verdict::Drop),
                libc::NF_ACCEPT => Some(Verdict::Accept),
                libc::NF_QUEUE => Some(Verdict::Queue),
                libc::NFT_CONTINUE => Some(Verdict::Continue),
                libc::NFT_BREAK => Some(Verdict::Break),
                libc::NFT_JUMP => chain.map(|chain| Verdict::Jump { chain }),
                libc::NFT_GOTO => chain.map(|chain| Verdict::Goto { chain }),
                libc::NFT_RETURN => Some(Verdict::Return),
                _ => None,
            }
        }
    }

    fn to_expr(&self, _rule: &Rule) -> *mut sys::nftnl_expr {
        let immediate_const = match *self {
            Verdict::Drop => libc::NF_DROP,
            Verdict::Accept => libc::NF_ACCEPT,
            Verdict::Queue => libc::NF_QUEUE,
            Verdict::Continue => libc::NFT_CONTINUE,
            Verdict::Break => libc::NFT_BREAK,
            Verdict::Jump { .. } => libc::NFT_JUMP,
            Verdict::Goto { .. } => libc::NFT_GOTO,
            Verdict::Return => libc::NFT_RETURN,
        };
        unsafe {
            let expr = try_alloc!(sys::nftnl_expr_alloc(
                b"immediate\0" as *const _ as *const c_char
            ));

            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_DREG as u16,
                libc::NFT_REG_VERDICT as u32,
            );

            if let Some(chain) = self.chain() {
                sys::nftnl_expr_set_str(expr, sys::NFTNL_EXPR_IMM_CHAIN as u16, chain.as_ptr());
            }
            sys::nftnl_expr_set_u32(
                expr,
                sys::NFTNL_EXPR_IMM_VERDICT as u16,
                immediate_const as u32,
            );

            expr
        }
    }
}

#[macro_export]
macro_rules! nft_expr_verdict {
    (drop) => {
        $crate::expr::Verdict::Drop
    };
    (accept) => {
        $crate::expr::Verdict::Accept
    };
    (reject icmp $code:expr) => {
        $crate::expr::Verdict::Reject(RejectionType::Icmp($code))
    };
    (reject tcp-rst) => {
        $crate::expr::Verdict::Reject(RejectionType::TcpRst)
    };
    (queue) => {
        $crate::expr::Verdict::Queue
    };
    (continue) => {
        $crate::expr::Verdict::Continue
    };
    (break) => {
        $crate::expr::Verdict::Break
    };
    (jump $chain:expr) => {
        $crate::expr::Verdict::Jump { chain: $chain }
    };
    (goto $chain:expr) => {
        $crate::expr::Verdict::Goto { chain: $chain }
    };
    (return) => {
        $crate::expr::Verdict::Return
    };
}

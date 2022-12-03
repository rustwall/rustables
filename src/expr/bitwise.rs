use rustables_macros::nfnetlink_struct;

use super::{Expression, ExpressionData, Register};
use crate::parser::DecodeError;
use crate::sys::{
    NFTA_BITWISE_DREG, NFTA_BITWISE_LEN, NFTA_BITWISE_MASK, NFTA_BITWISE_SREG, NFTA_BITWISE_XOR,
};

#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[nfnetlink_struct]
pub struct Bitwise {
    #[field(NFTA_BITWISE_SREG)]
    sreg: Register,
    #[field(NFTA_BITWISE_DREG)]
    dreg: Register,
    #[field(NFTA_BITWISE_LEN)]
    len: u32,
    #[field(NFTA_BITWISE_MASK)]
    mask: ExpressionData,
    #[field(NFTA_BITWISE_XOR)]
    xor: ExpressionData,
}

impl Expression for Bitwise {
    fn get_name() -> &'static str {
        "bitwise"
    }
}

impl Bitwise {
    /// Returns a new `Bitwise` instance that first masks the value it's applied to with `mask` and
    /// then performs xor with the value in `xor`
    pub fn new(mask: impl Into<Vec<u8>>, xor: impl Into<Vec<u8>>) -> Result<Self, DecodeError> {
        let mask = mask.into();
        let xor = xor.into();
        if mask.len() != xor.len() {
            return Err(DecodeError::IncompatibleLength);
        }
        Ok(Bitwise::default()
            .with_sreg(Register::Reg1)
            .with_dreg(Register::Reg1)
            .with_len(mask.len() as u32)
            .with_xor(ExpressionData::default().with_value(xor))
            .with_mask(ExpressionData::default().with_value(mask)))
    }
}
